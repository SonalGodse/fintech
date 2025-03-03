import { api, APIError } from "encore.dev/api";
import { CreateUserAndAccountRequest, LoginResponse, UserResponse, UserAccountResponse } from "./Interface";
import { AuthService } from "./auth.service";

export const refreshToken = api(
    { expose: true, method: "POST", path: "/auth/refresh" },
    async ({ data }: { data: { refreshToken: string } }): Promise<{ accessToken: string; refreshToken: string }> => {
        try {
            const response = await AuthService.refreshToken(data.refreshToken);
            return {
                accessToken: response.result.accessToken,
                refreshToken: response.result.refreshToken
            };
        } catch (error) {
            if (error instanceof APIError) throw error;
            throw APIError.internal("Failed to refresh token");
        }
    }
);

export const login = api(
    { expose: true, method: "POST", path: "/auth/login" },
    async ({ data }: { data: { 
        username: string;
        password?: string;
        recaptchaToken?: string;
        authType?: "CREDENTIALS" | "MPIN";
        mpin?: number;
        deviceId?: string;
        deviceType?: string;
        userId?: number;
    } }): Promise<{ accessToken: string; refreshToken: string }> => {
        try {
            if (data.authType === "CREDENTIALS" && !data.recaptchaToken) {
                throw APIError.permissionDenied("Captcha token is required");
            }

            const response = await AuthService.login(
                data.username,
                data.password || "", 
                data.recaptchaToken || "", 
                data.authType || "CREDENTIALS",
                data.mpin || 0,
                data.deviceId || "",
                data.deviceType || "",
                data.userId
            );

            return {
                accessToken: response.result.accessToken,
                refreshToken: response.result.refreshToken
            };
        } catch (error) {
            if (error instanceof APIError) throw error;
            throw APIError.internal("Login failed");
        }
    }
);

export const saveMpin = api(
    { expose: true, method: "POST", path: "/auth/save-mpin" },
    async (data: { mpin: number; deviceId: string; deviceType: string; userId?: number }) => {
        try {
            const response = await AuthService.saveMpin(data.mpin, data.deviceId, data.deviceType, data.userId);
            return response;
        } catch (error) {
            throw APIError.aborted(error?.toString() || "Failed to save MPIN");
        }
    }
);

export const createUserAndAccount = api(
    { expose: true, method: "POST", path: "/userAccount" },
    async ({ data }: { data: CreateUserAndAccountRequest }): Promise<UserAccountResponse> => {
        try {
            const response = await AuthService.create(data);
            return response.result as UserAccountResponse;
        } catch (error) {
            if (error instanceof APIError) throw error;
            throw APIError.internal("Failed to create user");
        }
    }
);

export const forgotPassword = api(
    { expose: true, method: "POST", path: "/auth/forgot-password" },
    async (data: { username: string }) => {
        try {
            await AuthService.forgotPassword(data.username);
            return { success: true, message: "Reset password link sent to email." };
        } catch (error) {
            throw APIError.aborted(error?.toString() || "Failed to process forgot password request");
        }
    }
);

export const resetPassword = api(
    { expose: true, method: "POST", path: "/auth/reset-password" },
    async (data: { token: string; newPassword: string }) => {
        try {
            await AuthService.resetPassword(data.token, data.newPassword);
            return { success: true, message: "Password reset successfully." };
        } catch (error) {
            throw APIError.aborted(error?.toString() || "Failed to reset password");
        }
    }
);