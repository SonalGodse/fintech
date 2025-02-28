import dotenv from 'dotenv';
import { z } from 'zod';

// Load environment variables from .env file
dotenv.config();

// Define environment variables schema
const envSchema = z.object({
    JWT_SECRET_KEY: z.string().min(1, 'JWT_SECRET_KEY is required'),
    RECAPTCHA_SECRET_KEY: z.string().optional(),
    RECAPTCHA_VERIFY_URL: z.string().optional(),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
});

// Validate and export environment variables
const validateEnv = () => {
    try {
        return envSchema.parse(process.env);
    } catch (error) {
        if (error instanceof z.ZodError) {
            const missingVars = error.errors.map(err => err.path.join('.')).join(', ');
            throw new Error(`Missing or invalid environment variables: ${missingVars}`);
        }
        throw error;
    }
};

export const env = validateEnv();
