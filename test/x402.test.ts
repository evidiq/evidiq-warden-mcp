import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { withX402Gate } from "../lib/x402/gate.js";
import type { PaymentVerifier } from "../lib/x402/facilitator.js";
import type { PaymentPayload, SettleResult, VerifyResult } from "../lib/x402/types.js";

const decodePaymentResponseHeader = (h: string) => JSON.parse(Buffer.from(h, "base64").toString("utf8"));

const encodePaymentRequestHeader = (p: PaymentPayload) => Buffer.from(JSON.stringify(p)).toString("base64");

const DEFAULT_ENV = { ...process.env };

function resetEnv() {
  process.env = { ...DEFAULT_ENV };
  delete process.env.X402_NETWORK;
  delete process.env.X402_CHAIN;
  delete process.env.X402_ASSET;
  delete process.env.X402_PAY_TO;
  delete process.env.X402_FACILITATOR_URL;
  delete process.env.X402_RPC;
  delete process.env.X402_RPC_URL;
  delete process.env.PUBLIC_BASE_URL;
}

function setValidEnv() {
  process.env.X402_NETWORK = "eip155:196";
  process.env.X402_ASSET = "0x779ded0c9e1022225f8e0630b35a9b54be713736";
  process.env.X402_PAY_TO = "0x2a8efe3093278bb4bd3b2d9c7b5ba992ca4fc9b0";
  process.env.PUBLIC_BASE_URL = "https://mcp.evidiq.dev/warden";
}

function buildDummyPayment(amount: string = "5000", nonce: string = "0x" + "1".repeat(64)): PaymentPayload {
  return {
    x402Version: 2,
    scheme: "exact",
    network: "eip155:196",
    accepted: {
      scheme: "exact",
      network: "eip155:196",
      asset: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
      amount,
      payTo: "0x2a8efe3093278bb4bd3b2d9c7b5ba992ca4fc9b0",
      maxTimeoutSeconds: 300,
      extra: { name: "USD₮0", version: "1" },
    },
    payload: {
      signature: ("0x" + "a".repeat(130)) as any,
      authorization: {
        from: "0x1111111111111111111111111111111111111111",
        to: "0x2a8efe3093278bb4bd3b2d9c7b5ba992ca4fc9b0",
        value: amount,
        nonce: nonce as any,
        validAfter: "0",
        validBefore: "9999999999",
      },
    },
  };
}

describe("Warden x402 Payment Gate", () => {
  beforeEach(resetEnv);
  afterEach(resetEnv);

  it("allows free tools (warden_capabilities) without x402 headers", async () => {
    setValidEnv();
    const handler = withX402Gate(async () => new Response(JSON.stringify({ result: { status: "ok" } })));
    const req = new Request("https://mcp.evidiq.dev/warden/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "warden_capabilities" },
      }),
    });

    const res = await handler(req);
    expect(res.status).toBe(200);
  });

  it("returns 402 for unauthenticated paid tools (review_diff)", async () => {
    setValidEnv();
    const handler = withX402Gate(async () => new Response(JSON.stringify({ result: { status: "ok" } })));
    const req = new Request("https://mcp.evidiq.dev/warden/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "review_diff", arguments: { diff: "--- a\n+++ b" } },
      }),
    });

    const res = await handler(req);
    expect(res.status).toBe(402);
    expect(res.headers.get("payment-required")).toBeDefined();
  });

  it("processes paid tool call successfully when valid payment header is provided", async () => {
    setValidEnv();
    const payment = buildDummyPayment("5000", "0x" + "1".repeat(64));

    const mockVerifier: PaymentVerifier = {
      verify: async (): Promise<VerifyResult> => ({ valid: true, payer: payment.payload.authorization.from }),
      settle: async (): Promise<SettleResult> => ({
        status: "settled",
        success: true,
        transaction: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        payer: payment.payload.authorization.from,
      }),
    };

    const handler = withX402Gate(
      async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { verdict: "PASS" } })),
      { verifierFactory: () => mockVerifier }
    );

    const paymentHeader = encodePaymentRequestHeader(payment);
    const req = new Request("https://mcp.evidiq.dev/warden/mcp", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "payment-signature": paymentHeader,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "review_diff", arguments: { diff: "--- a\n+++ b" } },
      }),
    });

    const res = await handler(req);
    expect(res.status).toBe(200);
    expect(res.headers.get("payment-response")).toBeDefined();

    const decodedResp = decodePaymentResponseHeader(res.headers.get("payment-response")!);
    expect(decodedResp?.status).toBe("settled");
    expect(decodedResp?.transaction).toBe("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
  });
});
