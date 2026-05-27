import { z } from "zod";

const envSchema = z.object({
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  GEMINI_API_KEY: z.string().min(1).optional(),
  GEMINI_MODEL: z.string().min(1).default("gemini-2.0-flash"),
  CORAL_BRIDGE_URL: z.string().url().optional(),
  CORAL_BRIDGE_TOKEN: z.string().min(1).optional(),
});

const parsedEnv = envSchema.safeParse({
  DATABASE_URL: process.env.DATABASE_URL,
  GEMINI_API_KEY: process.env.GEMINI_API_KEY,
  GEMINI_MODEL: process.env.GEMINI_MODEL,
  CORAL_BRIDGE_URL: process.env.CORAL_BRIDGE_URL,
  CORAL_BRIDGE_TOKEN: process.env.CORAL_BRIDGE_TOKEN,
});

if (!parsedEnv.success) {
  throw new Error(parsedEnv.error.message);
}

export const env = parsedEnv.data;
