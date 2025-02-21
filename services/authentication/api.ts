import { api, APIError } from "encore.dev/api";
import { UserService } from "./auth.service";
import { CreateAccountDto, UserResponse } from "./Interface";

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

export const login = api(
    { expose: true, method: "POST", path: "/auth/login" },
    async (data: { username: string; password: string; recaptchaToken?: string; authType?: string;}) => {
        try {
            if (data.authType ==="MPIN" && !data.recaptchaToken) {
                throw APIError.permissionDenied("Captcha token is required");
            }

            const { success, accessToken, refreshToken } = await UserService.login(
                data.username,
                data.password,
                data.recaptchaToken || '',
                data.authType || 'CREDENTIALS'
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
