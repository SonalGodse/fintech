import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { CreateAccountDto, CreateUserAndAccountRequest, CreateUserAndAccountResponse, UserResponse } from "./Interface";
import { APIError } from "encore.dev/api";
import axios from "axios";

const SECRET_KEY = "nK4h9P#mY2x$vL8q5W3jR7tZ9nB2cF5v";
const prisma = new PrismaClient();

export const UserService = {
    create:async (data: CreateUserAndAccountRequest): Promise<UserResponse> => {
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
        
                // Format response according to CreateUserAndAccountResponse interface
                const response: CreateUserAndAccountResponse = {
                    id: user.id,
                    firstName: user?.first_name || "",
                    lastName: user.last_name || "",
                    phone: user.phone ?? undefined,
                    email: user.email || "",
                    username: account.username || "",
                };
        
                return { 
                    success: true,
                    message: "User and account created successfully",
                    result: response
                };
            });
        } catch (error) {
            console.error("Error creating user with account:", error);
            // if (error === "P2002") {
            //     throw APIError.alreadyExists("Username already exists");
            // }
            throw error;
        }
    },

    async login(
        username: string,
        password: string,
        recaptchaToken: string,
        authType: string,
        mpin: number,
        deviceId: string,
        deviceType: string,
        userId?: number
    ) {
        if (authType === "CREDENTIALS") {
            if (!recaptchaToken) {
                throw APIError.permissionDenied("Captcha token is required");
            }
   
            try {
                await verifyRecaptcha(recaptchaToken);
            } catch (error) {
                throw APIError.permissionDenied("Invalid captcha");
            }
   
            const account = await prisma.account.findUnique({
                where: { username },
                select: { id: true, username: true, password: true, wrong_attempt: true, locked: true },
            });
   
            if (!account || !account.password) {
                return { success: false, accessToken: "", refreshToken: "" };
            }
   
            if (account.locked) {
                throw APIError.permissionDenied("Your account is locked due to multiple failed login attempts.");
            }
   
            const isPasswordValid = await bcrypt.compare(password, account.password);
   
            if (!isPasswordValid) {
                const updatedAttempts = (account.wrong_attempt || 0) + 1;
                const isLocked = updatedAttempts >= 3;
   
                await prisma.account.update({
                    where: { username },
                    data: {
                        wrong_attempt: updatedAttempts,
                        locked: isLocked,
                    },
                });
   
                throw APIError.permissionDenied(
                    isLocked ? "Your account is locked due to multiple failed login attempts."
                             : "Invalid credentials"
                );
            }
   
            await prisma.account.update({
                where: { username },
                data: {
                    wrong_attempt: 0,
                    last_login: Math.floor(Date.now() / 1000),
                },
            });
   
            const accessToken = jwt.sign({ id: account.id, username: account.username }, SECRET_KEY, {
                expiresIn: "15m",
            });
            const refreshToken = jwt.sign({ id: account.id }, SECRET_KEY, { expiresIn: "7d" });
   
            return { success: true, accessToken, refreshToken };
        }
   
        if (authType === "MPIN") {
            if (!mpin || !userId || !deviceId || !deviceType) {
                throw APIError.permissionDenied("MPIN and userId are required for MPIN authentication.");
            }
   
            // Fetch account details along with device ID
            const account = await prisma.account.findUnique({
                where: { id: userId },
                select: { id: true, username: true, mpin: true, device_id: true, wrong_attempt: true, locked: true },
            });
   
            if (!account || !account.mpin) {
                return { success: false, accessToken: "", refreshToken: "" };
            }
   
            if (account.locked) {
                throw APIError.permissionDenied("Your account is locked due to multiple failed login attempts.");
            }
   
            // Check if MPIN is valid
            const isMpinValid = mpin === account.mpin;
   
            // Check if deviceId matches
            const isDeviceValid = deviceId === account.device_id;
   
            if (!isMpinValid || !isDeviceValid) {
                const updatedAttempts = (account.wrong_attempt || 0) + 1;
                const isLocked = updatedAttempts >= 3;
   
                await prisma.account.update({
                    where: { id: userId },
                    data: {
                        wrong_attempt: updatedAttempts,
                        locked: isLocked,
                    },
                });
   
                throw APIError.permissionDenied(
                    isLocked ? "Your account is locked due to multiple failed login attempts."
                             : !isMpinValid ? "Invalid MPIN"
                             : "Device ID mismatch"
                );
            }
   
            // Reset wrong attempt count and update last login timestamp
            await prisma.account.update({
                where: { id: userId },
                data: {
                    wrong_attempt: 0,
                    last_login: Math.floor(Date.now() / 1000),
                },
            });
   
            const accessToken = jwt.sign({ id: account.id, username: account.username }, SECRET_KEY, {
                expiresIn: "15m",
            });
            const refreshToken = jwt.sign({ id: account.id }, SECRET_KEY, { expiresIn: "7d" });
   
            return { success: true, accessToken, refreshToken };
        }
   
        return { success: false, accessToken: "", refreshToken: "" };
    },
   
    async saveMpin(mpin: number, deviceId: string, deviceType: string, userId?: number) {
        if (!mpin || !deviceId || !deviceType || !userId) {
            throw APIError.permissionDenied("MPIN, Device ID, Device Type, and User ID are required.");
        }
   
        const user = await prisma.users.findUnique({
            where: { id: userId },
            select: { account_id: true },
        });

        if (!user || !user.account_id) {
            throw APIError.notFound("User not found or account not linked.");
        }
   
        await prisma.account.update({
            where: { id: user.account_id },
            data: {
                mpin,
                device_id: deviceId,
                device_type: deviceType,
                updated_ts: Math.floor(Date.now() / 1000),
            },
        });
   
        return { success: true, message: "MPIN saved successfully." };
    },

    async refreshToken(refreshToken: string) {
        try {
            const payload = jwt.verify(refreshToken, SECRET_KEY) as { id: number };

            const newAccessToken = jwt.sign({ id: payload.id }, SECRET_KEY, { expiresIn: "15m" });
            const newRefreshToken = jwt.sign({ id: payload.id }, SECRET_KEY, { expiresIn: "7d" });

            return { accessToken: newAccessToken, newRefreshToken };
        } catch (error) {
            throw APIError.permissionDenied("Invalid refresh token");
        }
    },
};

async function verifyRecaptcha(recaptchaToken: string) {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    const verifyUrl = process.env.RECAPTCHA_VERIFY_URL || "https://www.google.com/recaptcha/api/siteverify";

    try {
        const response = await axios.post(verifyUrl, null, {
            params: {
                secret: secretKey,
                response: recaptchaToken,
            },
        });

        console.log("reCAPTCHA Response:", response.data);

        const { success, score, hostname } = response.data;

        if (!success) {
            throw new Error("Invalid captcha");
        }

        return true;
    } catch (error) {
        console.error("Error verifying reCAPTCHA:", error);
        return false;
    }
}
