import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { CreateAccountDto } from "./Interface";
import { APIError } from "encore.dev/api";
import axios from "axios";

const SECRET_KEY = "nK4h9P#mY2x$vL8q5W3jR7tZ9nB2cF5v";
const prisma = new PrismaClient();

export const UserService = {
    async createAccount(data: CreateAccountDto) {
        const hashedPassword = await bcrypt.hash(data.password, 10);
        console.log(hashedPassword);

        const account = await prisma.account.create({
            data: {
                username: data.username,
                password: hashedPassword,
                active: data.active,
                wrong_attempt: data.wrongAttempt,
                wrong_otp_attempt: data.wrongOtpAttempt,
                last_login: data.lastLogin,
                status: data.status,
                locked: data.locked,
                is_deleted: data.isDeleted,
            },
        });

        return {
            ...account,
            id: Number(account.id),
        };
    },

    async login(username: string, password: string, recaptchaToken: string, authType: string) {
        if (!recaptchaToken) {
            throw APIError.permissionDenied("Captcha token is required");
        }
    
        try {
            await verifyRecaptcha(recaptchaToken);
        } catch (error) {
            throw APIError.permissionDenied("Invalid captcha");
        }
    
        if (authType === "CREDENTIALS") {
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
    
        return { success: false, accessToken: "", refreshToken: "" };
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
