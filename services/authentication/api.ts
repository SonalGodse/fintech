import { api, APIError } from "encore.dev/api";
import { UserService } from "./auth.service";
import { CreateAccountDto, CreateUserAndAccountRequest, UserResponse } from "./Interface";

export const create = api(
    { expose: true, method: "POST", path: "/account" },
    async (data: CreateAccountDto): Promise<UserResponse> => {
        try {
            const result = await UserService.createAccount(data);

            return {
                success: true,
                message: "User created successfully",
            };
        } catch (error) {
            throw APIError.aborted(error?.toString() || "Error creating user");
        }
    }
);

export const refreshToken = api(
    { expose: true, method: "POST", path: "/auth/refresh" },
    async (data: { refreshToken: string }) => {
        try {
            const { accessToken, newRefreshToken } = await UserService.refreshToken(data.refreshToken);

            return { accessToken, refreshToken: newRefreshToken };
        } catch (error) {
            throw APIError.permissionDenied("Invalid refresh token");
        }
    }
);

export const login = api(
    { expose: true, method: "POST", path: "/auth/login" },
    async (data: { 
        username: string; 
        password?: string; 
        recaptchaToken?: string; 
        authType?: string; 
        mpin?: number; 
        deviceId?: string; 
        deviceType: string; 
        userId?: number 
    }) => {
        try {
            if (data.authType === "CREDENTIALS" && !data.recaptchaToken) {
                throw APIError.permissionDenied("Captcha token is required");
            }

            const { success, accessToken, refreshToken } = await UserService.login(
                data.username,
                data.password || "", 
                data.recaptchaToken || "", 
                data.authType || "CREDENTIALS",
                data.mpin || 0,             
                data.deviceId || "",          
                data.deviceType,       
                data.userId                   
            );

            if (!success) {
                throw APIError.permissionDenied("Invalid credentials");
            }

            return { accessToken, refreshToken };
        } catch (error) {
            throw APIError.aborted(error?.toString() || "Login failed");
        }
    }
);

export const saveMpin = api(
    { expose: true, method: "POST", path: "/auth/save-mpin" },
    async (data: { mpin: number; deviceId: string; deviceType: string; userId?: number }) => {
        try {
            const response = await UserService.saveMpin(data.mpin, data.deviceId, data.deviceType, data.userId);
            return response;
        } catch (error) {
            throw APIError.aborted(error?.toString() || "Failed to save MPIN");
        }
    }
);

export const createUserAndAccount = api(
    { expose: true, method: "POST", path: "/userAccount" },
    async (data: CreateUserAndAccountRequest): Promise<UserResponse> => {
        try {
            await UserService.create(data);
            return { success: true, message: "User created successfully" };
        } catch (error) {
            throw APIError.aborted(error?.toString() || "Error creating user");
        }
    }
);
 