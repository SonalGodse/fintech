import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { CreateAccountDto, CreateUserAndAccountRequest, CreateUserAndAccountResponse, LoginResponse, TokenResponse, UserAccountResponse, UserResponse } from "./Interface";
import { APIError } from "encore.dev/api";
import axios from "axios";
import { env } from "../../config/env.config";
import { prisma } from "../../lib/prisma";

if (!env.JWT_SECRET_KEY) {
    throw new Error('JWT_SECRET_KEY is not defined in environment variables');
}

const SECRET_KEY = env.JWT_SECRET_KEY;

// Helper function to generate tokens
const generateTokens = (accountId: number, username: string) => {
    const accessToken = jwt.sign(
        { id: accountId, username },
        SECRET_KEY,
        { expiresIn: "15m" }
    );
    const refreshToken = jwt.sign(
        { id: accountId },
        SECRET_KEY,
        { expiresIn: "7d" }
    );
    return { accessToken, refreshToken };
};

export const AuthService = {
    create: async (data: CreateUserAndAccountRequest): Promise<UserResponse> => {
        try {
            // Validate required fields
            if (!data.firstName?.trim()) {
                throw APIError.invalidArgument("First name is required");
            }
            if (!data.lastName?.trim()) {
                throw APIError.invalidArgument("Last name is required");
            }
            if (!data.email?.trim()) {
                throw APIError.invalidArgument("Email is required");
            }
            if (!data.account?.username?.trim()) {
                throw APIError.invalidArgument("Username is required");
            }
            if (!data.account?.password?.trim()) {
                throw APIError.invalidArgument("Password is required");
            }

            // Check if username already exists
            const existingAccount = await prisma.account.findUnique({
                where: {
                    username: data.account.username
                }
            });
            const existingUser = await prisma.users.findUnique({
                where: {
                    email: data?.email
                }
            });
            
            if(existingUser){
                throw APIError.alreadyExists("Email already exists");
            }
            if (existingAccount) {
                throw APIError.alreadyExists("Username already exists");
            }
           
            // Hash the password
            const hashedPassword = await bcrypt.hash(data?.account?.password || "", 10);
            
            // Create the account
            return await prisma.$transaction(async (tx) => {
                // Create the account with all required fields
                const account = await tx.account.create({
                    data: {
                        username: data.account?.username || "",
                        password: hashedPassword,
                        active: true,
                        status: 1,
                        locked: false,
                        is_deleted: false,
                        created_ts: Math.floor(Date.now() / 1000)
                    },
                });
        
                // Create the user associated with the account
                const user = await tx.users.create({
                    data: {
                        first_name: data.firstName,
                        last_name: data.lastName,
                        phone: data.phone,
                        email: data.email,
                        type: data.type,
                        created_ts: Math.floor(Date.now() / 1000),
                        account_id: account.id,
                    },
                });

                // Format response according to UserAccountResponse interface
                const response: UserAccountResponse = {
                    id: user.id,
                    firstName: user.first_name || "",
                    lastName: user.last_name || "",
                    phone: user.phone || undefined,
                    email: user.email || "",
                    account: {
                        id: account.id,
                        username: account.username || ""
                    }
                };
        
                return { 
                    success: true,
                    message: "User and account created successfully",
                    result: response
                };
            });
        } catch (error) {
            console.error("Error creating user with account:", error);
            if (error instanceof APIError) throw error;
            throw APIError.internal("Failed to create user and account");
        }
    },

    login: async (
        username: string,
        password: string,
        recaptchaToken: string,
        authType: "CREDENTIALS" | "MPIN",
        mpin: number,
        deviceId: string,
        deviceType: string,
        userId?: number
    ): Promise<LoginResponse> => {
        try {
            if (authType === "CREDENTIALS") {
                // Verify captcha
                if (!recaptchaToken) {
                    throw APIError.invalidArgument("Captcha token is required");
                }

                const isCaptchaValid = await verifyRecaptcha(recaptchaToken);
             
                // Get account
                const account = await prisma.account.findUnique({
                    where: { username },
                    select: {
                        id: true,
                        username: true,
                        password: true,
                        wrong_attempt: true,
                        locked: true
                    },
                });

                if (!account?.password) {
                    throw APIError.permissionDenied("Invalid credentials");
                }

                // Check if account is locked
                if (account.locked) {
                    throw APIError.permissionDenied("Your account is locked due to multiple failed login attempts");
                }

                // Verify password
                const isPasswordValid = await bcrypt.compare(password, account.password);
                if (!isPasswordValid) {
                    const updatedAttempts = (account.wrong_attempt || 0) + 1;
                    const isLocked = updatedAttempts >= 3;

                    await prisma.account.update({
                        where: { username },
                        data: {
                            wrong_attempt: updatedAttempts,
                            locked: isLocked
                        },
                    });

                    throw APIError.permissionDenied(
                        isLocked 
                            ? "Your account is locked due to multiple failed login attempts"
                            : "Invalid credentials"
                    );
                }

                // Reset failed attempts and update last login
                await prisma.account.update({
                    where: { username },
                    data: {
                        wrong_attempt: 0,
                        last_login: Math.floor(Date.now() / 1000)
                    },
                });

                // Generate tokens
                const { accessToken, refreshToken } = generateTokens(account.id, account?.username || "");

                return {
                    success: true,
                    message: "Login successful",
                    result: { accessToken, refreshToken }
                };
            }

            if (authType === "MPIN") {
                // Validate MPIN request
                if (!userId || !mpin || !deviceId || !deviceType) {
                    throw APIError.invalidArgument("All MPIN authentication fields are required");
                }

                // Get account
                const account = await prisma.account.findUnique({
                    where: { id: userId },
                    select: {
                        id: true,
                        username: true,
                        mpin: true,
                        device_id: true,
                        wrong_attempt: true,
                        locked: true
                    },
                });

                if (!account?.mpin) {
                    throw APIError.permissionDenied("Invalid MPIN credentials");
                }

                // Check if account is locked
                if (account.locked) {
                    throw APIError.permissionDenied("Your account is locked due to multiple failed login attempts");
                }

                // Verify MPIN and device
                const isMpinValid = mpin === account.mpin;
                const isDeviceValid = deviceId === account.device_id;

                if (!isMpinValid || !isDeviceValid) {
                    const updatedAttempts = (account.wrong_attempt || 0) + 1;
                    const isLocked = updatedAttempts >= 3;

                    await prisma.account.update({
                        where: { id: userId },
                        data: {
                            wrong_attempt: updatedAttempts,
                            locked: isLocked
                        },
                    });

                    throw APIError.permissionDenied(
                        isLocked
                            ? "Your account is locked due to multiple failed login attempts"
                            : !isMpinValid ? "Invalid MPIN" : "Device ID mismatch"
                    );
                }

                // Generate tokens
                const { accessToken, refreshToken } = generateTokens(account.id, account?.username || "");

                return {
                    success: true,
                    message: "Login successful",
                    result: { accessToken, refreshToken }
                };
            }

            throw APIError.invalidArgument("Invalid authentication type");
        } catch (error) {
            console.error("Error in login:", error);
            if (error instanceof APIError) throw error;
            throw APIError.internal("Login failed");
        }
    },

    saveMpin: async (
        mpin: number,
        deviceId: string,
        deviceType: string,
        userId?: number
    ): Promise<{ success: boolean; message: string }> => {
        try {
            // Validate required fields
            if (!mpin || !deviceId || !deviceType || !userId) {
                throw APIError.invalidArgument("MPIN, Device ID, Device Type, and User ID are required");
            }

            // Get user and check if account exists
            const user = await prisma.users.findUnique({
                where: { id: userId },
                select: { account_id: true },
            });

            if (!user?.account_id) {
                throw APIError.notFound("User not found or account not linked");
            }

            // Update account with MPIN and device info
            await prisma.account.update({
                where: { id: user.account_id },
                data: {
                    mpin,
                    device_id: deviceId,
                    device_type: deviceType,
                    updated_ts: Math.floor(Date.now() / 1000)
                },
            });

            return {
                success: true,
                message: "MPIN saved successfully"
            };
        } catch (error) {
            console.error("Error saving MPIN:", error);
            if (error instanceof APIError) throw error;
            throw APIError.internal("Failed to save MPIN");
        }
    },

    refreshToken: async (refreshToken: string): Promise<TokenResponse> => {
        try {
            // Verify refresh token
            const payload = jwt.verify(refreshToken, SECRET_KEY) as { id: number };

            // Get account
            const account = await prisma.account.findUnique({
                where: { id: payload.id },
                select: { id: true, username: true }
            });

            if (!account?.id) {
                throw APIError.permissionDenied("Invalid refresh token");
            }

            // Generate new tokens
            const { accessToken, refreshToken: newRefreshToken } = generateTokens(account.id, account?.username || "");

            return {
                success: true,
                message: "Token refreshed successfully",
                result: { accessToken, refreshToken: newRefreshToken }
            };
        } catch (error) {
            console.error("Error refreshing token:", error);
            if (error instanceof APIError) throw error;
            throw APIError.permissionDenied("Invalid refresh token");
        }
    }
};

async function verifyRecaptcha(recaptchaToken: string): Promise<boolean> {
    const secretKey = env.RECAPTCHA_SECRET_KEY;
    const verifyUrl = env.RECAPTCHA_VERIFY_URL || "https://www.google.com/recaptcha/api/siteverify";

    try {
        const response = await axios.post(verifyUrl, null, {
            params: {
                secret: secretKey,
                response: recaptchaToken,
            },
        });

        return response.data.success;
    } catch (error) {
        console.error("Error verifying reCAPTCHA:", error);
        return false;
    }
}
