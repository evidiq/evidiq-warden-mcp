import { z } from "zod";

const WardenAppConfigSchema = z.object({
  port: z.coerce.number().int().positive().default(3000),
  hostname: z.string().default("0.0.0.0"),
  publicBaseUrl: z.string().url().default("https://mcp.evidiq.dev/warden"),
  maxInputBytes: z.coerce.number().int().positive().default(524288),
  maxFiles: z.coerce.number().int().positive().default(40),
  artifactTtlMs: z.coerce.number().int().positive().default(600000),
  ruleBudgetMs: z.coerce.number().int().positive().default(8000),
});

export type WardenAppConfig = z.infer<typeof WardenAppConfigSchema>;

export function getWardenAppConfig(): WardenAppConfig {
  return WardenAppConfigSchema.parse({
    port: process.env.PORT,
    hostname: process.env.HOSTNAME,
    publicBaseUrl: process.env.PUBLIC_BASE_URL,
    maxInputBytes: process.env.WARDEN_MAX_INPUT_BYTES,
    maxFiles: process.env.WARDEN_MAX_FILES,
    artifactTtlMs: process.env.WARDEN_ARTIFACT_TTL_MS,
    ruleBudgetMs: process.env.WARDEN_RULE_BUDGET_MS,
  });
}
