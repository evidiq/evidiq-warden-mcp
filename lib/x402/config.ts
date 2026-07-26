import { z } from "zod";

export const XLAYER_NETWORK = "eip155:196" as const;
export const XLAYER_USDT0 = "0x779ded0c9e1022225f8e0630b35a9b54be713736" as const;
export const XLAYER_RPC_URL = "https://rpc.xlayer.tech";
export const DEFAULT_FACILITATOR_URL = "https://web3.okx.com";
export const DEFAULT_PUBLIC_BASE_URL = "https://mcp.evidiq.dev/warden";

const CHAIN_SLUGS: Record<string, string> = {
  "x-layer": "eip155:196",
  xlayer: "eip155:196",
  "x-layer-mainnet": "eip155:196",
  "x-layer-testnet": "eip155:1952",
  "xlayer-testnet": "eip155:1952",
};

function resolveNetwork(): string | undefined {
  const raw = (process.env.X402_NETWORK ?? process.env.X402_CHAIN)?.trim();
  if (!raw) return undefined;
  if (/^eip155:\d+$/.test(raw)) return raw;
  return CHAIN_SLUGS[raw.toLowerCase()];
}

/** Prices are fixed atomic USD₮0 units and cannot be overridden by env. */
export const TOOL_PRICES = Object.freeze({
  review_diff: 5_000n,
  review_files: 10_000n,
  analyze_complexity: 15_000n,
  check_policy: 20_000n,
  attest_review: 30_000n,
} as const);

export type PaidToolName = keyof typeof TOOL_PRICES;

export const PAID_TOOL_NAMES = Object.freeze([
  "review_diff",
  "review_files",
  "analyze_complexity",
  "check_policy",
  "attest_review",
] as const satisfies readonly PaidToolName[]);

export const FREE_TOOL_NAMES = Object.freeze([
  "warden_capabilities",
  "validate_source",
  "estimate_cost",
  "verify_review_report",
  "get_artifact",
] as const);

export type FreeToolName = (typeof FREE_TOOL_NAMES)[number];

export const PAID_TOOLS: ReadonlySet<string> = new Set(PAID_TOOL_NAMES);
export const FREE_TOOLS: ReadonlySet<string> = new Set(FREE_TOOL_NAMES);

const WardenConfigSchema = z.object({
  network: z.string().regex(/^eip155:\d+$/, "network must resolve to CAIP-2, e.g. eip155:196"),
  asset: z.string().regex(/^0x[0-9a-fA-F]{40}$/, "X402_ASSET must be a 0x... token address"),
  payTo: z.string().regex(/^0x[0-9a-fA-F]{40}$/, "X402_PAY_TO must be a 0x... address"),
  domainName: z.string().min(1),
  domainVersion: z.string().min(1),
  facilitatorUrl: z.string().url(),
  rpcUrl: z.string().url(),
  publicBaseUrl: z.string().url(),
  settleKey: z.string().regex(/^0x[0-9a-fA-F]{64}$/, "X402_SETTLE_KEY must be a 0x... 32-byte private key").optional(),
  useFacilitator: z.boolean(),
});

export type WardenConfig = {
  network: string;
  chainId: number;
  asset: `0x${string}`;
  payTo: `0x${string}`;
  domainName: string;
  domainVersion: string;
  facilitatorUrl: string;
  rpcUrl: string;
  publicBaseUrl: string;
  settleKey?: `0x${string}`;
  useFacilitator: boolean;
};

export type RedactConfig = WardenConfig;

export type OkxCredentials = {
  apiKey: string;
  secretKey: string;
  passphrase: string;
  baseUrl: string;
  syncSettle: boolean;
};

export function getOkxCredentials(): OkxCredentials | null {
  const apiKey = process.env.OKX_API_KEY?.trim();
  const secretKey = process.env.OKX_SECRET_KEY?.trim();
  const passphrase = process.env.OKX_PASSPHRASE?.trim();

  if (!apiKey && !secretKey && !passphrase) return null;
  if (!apiKey || !secretKey || !passphrase) {
    throw new Error(
      "Incomplete OKX Payment SDK config: OKX_API_KEY, OKX_SECRET_KEY, and OKX_PASSPHRASE must be set together"
    );
  }

  return {
    apiKey,
    secretKey,
    passphrase,
    baseUrl: process.env.OKX_BASE_URL?.trim() || DEFAULT_FACILITATOR_URL,
    syncSettle: process.env.OKX_SYNC_SETTLE?.trim() !== "0",
  };
}

export function priceForTool(toolName: string): bigint | undefined {
  if (!PAID_TOOLS.has(toolName)) return undefined;
  return TOOL_PRICES[toolName as PaidToolName];
}

export function getWardenConfig(): WardenConfig | null {
  const payTo = process.env.X402_PAY_TO?.trim();
  if (!payTo) return null;

  const parsed = WardenConfigSchema.safeParse({
    network: resolveNetwork() ?? XLAYER_NETWORK,
    asset: process.env.X402_ASSET?.trim() || XLAYER_USDT0,
    payTo,
    domainName: process.env.X402_DOMAIN_NAME?.trim() || "USD₮0",
    domainVersion: process.env.X402_DOMAIN_VERSION?.trim() || "1",
    facilitatorUrl: process.env.X402_FACILITATOR_URL?.trim() || DEFAULT_FACILITATOR_URL,
    rpcUrl: process.env.X402_RPC?.trim() || process.env.X402_RPC_URL?.trim() || XLAYER_RPC_URL,
    publicBaseUrl: process.env.PUBLIC_BASE_URL?.trim() || DEFAULT_PUBLIC_BASE_URL,
    settleKey: process.env.X402_SETTLE_KEY?.trim() || undefined,
    useFacilitator: process.env.X402_USE_FACILITATOR?.trim() === "1",
  });

  if (!parsed.success) {
    throw new Error(`Invalid Warden x402 config: ${parsed.error.message}`);
  }

  return {
    ...parsed.data,
    asset: parsed.data.asset as `0x${string}`,
    payTo: parsed.data.payTo as `0x${string}`,
    settleKey: parsed.data.settleKey as `0x${string}` | undefined,
    chainId: Number(parsed.data.network.split(":")[1]),
  };
}

export function getRedactConfig() {
  return getWardenConfig();
}
