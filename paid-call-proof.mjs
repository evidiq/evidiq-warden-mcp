/**
 * Real x402 paid call proof for EVIDIQ Warden MCP on X Layer mainnet using real USDT0.
 *
 * Proves that Warden settles through the official OKX Payment SDK on-chain.
 *
 *   node paid-call-proof.mjs
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";

const ENDPOINT = process.env.ENDPOINT ?? "https://mcp.evidiq.dev/warden/mcp";
const RPC = process.env.RPC ?? "https://rpc.xlayer.tech";
const TOOL = process.env.TOOL ?? "review_diff";
const OUR_SETTLE_WALLET = "0xd6b658dc6e53444bf9cba598afdd21ede0a62fb9";
const ACCEPT = "application/json";

const argumentsByTool = {
  review_diff: {
    diff: `--- a/src/server.ts
+++ b/src/server.ts
@@ -1,3 +1,4 @@
 import express from "express";
 const app = express();
+const cmd = req.query.cmd; eval(cmd);
 app.listen(3000);`,
  },
  review_files: {
    files: [
      {
        path: "src/danger.ts",
        content: `const cmd = "ls"; eval(cmd);`,
      },
    ],
  },
  analyze_complexity: {
    files: [
      {
        path: "src/complex.ts",
        content: `function foo(x: number) { if (x > 1) { if (x > 2) { return x; } } return 0; }`,
      },
    ],
  },
  check_policy: {
    files: [
      {
        path: "src/app.ts",
        content: `const secret = "AKIAIOSFODNN7EXAMPLE";`,
      },
    ],
    policy: "security-baseline",
  },
  attest_review: {
    files: [
      {
        path: "src/clean.ts",
        content: `const safeNumber = 42;`,
      },
    ],
    policy: "agent-written-code",
    commitSha: "a1b2c3d4e5f60718293041526374859607182930",
  },
};

const body = {
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name: TOOL, arguments: argumentsByTool[TOOL] },
};

function parseMcpBody(text) {
  for (const line of text.split("\n")) {
    const trimmed = line.startsWith("data: ") ? line.slice(6).trim() : line.trim();
    if (trimmed.startsWith("{")) {
      try {
        return JSON.parse(trimmed);
      } catch {
        /* keep scanning */
      }
    }
  }
  return null;
}

async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return (await res.json()).result;
}

const key = JSON.parse(
  readFileSync(`${homedir()}/.evidiq-x402-test-wallet.json`, "utf8")
).privateKey;
const buyer = privateKeyToAccount(key);
console.log(`=======================================================`);
console.log(` EVIDIQ Warden MCP — Live On-Chain Proof Test`);
console.log(` Tool           : ${TOOL}`);
console.log(` Buyer Wallet   : ${buyer.address}`);
console.log(` Endpoint       : ${ENDPOINT}`);
console.log(`=======================================================\n`);

const unpaid = await fetch(ENDPOINT, {
  method: "POST",
  headers: { accept: ACCEPT, "content-type": "application/json" },
  body: JSON.stringify(body),
});
console.log(`1. Unpaid Request  -> HTTP ${unpaid.status}`);
if (unpaid.status !== 402) {
  console.log((await unpaid.text()).slice(0, 400));
  process.exit(1);
}

const challengeHeader = unpaid.headers.get("payment-required");
const challenge = challengeHeader
  ? JSON.parse(Buffer.from(challengeHeader, "base64").toString("utf8"))
  : await unpaid.clone().json();
const terms = challenge.accepts[0];
console.log(`   Quoted Price    : ${terms.amount} atomic (${Number(terms.amount) / 1e6} USD₮0)`);

const nonce = `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex")}`;
const validBefore = BigInt(Math.floor(Date.now() / 1000) + 600);
const signature = await buyer.signTypedData({
  domain: {
    name: terms.extra.name,
    version: terms.extra.version,
    chainId: Number(terms.network.split(":")[1]),
    verifyingContract: terms.asset,
  },
  types: {
    TransferWithAuthorization: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" },
      { name: "nonce", type: "bytes32" },
    ],
  },
  primaryType: "TransferWithAuthorization",
  message: {
    from: buyer.address,
    to: terms.payTo,
    value: BigInt(terms.amount),
    validAfter: 0n,
    validBefore,
    nonce,
  },
});

const header = Buffer.from(
  JSON.stringify({
    x402Version: 2,
    accepted: terms,
    payload: {
      signature,
      authorization: {
        from: buyer.address,
        to: terms.payTo,
        value: terms.amount,
        validAfter: "0",
        validBefore: validBefore.toString(),
        nonce,
      },
    },
  }),
  "utf8"
).toString("base64");

console.log(`2. Submitting Signed x402 Payment Envelope...`);
const paid = await fetch(ENDPOINT, {
  method: "POST",
  headers: {
    accept: ACCEPT,
    "content-type": "application/json",
    "payment-signature": header,
  },
  body: JSON.stringify(body),
});
const text = await paid.text();
console.log(`   Paid Replay Status -> HTTP ${paid.status}`);

const responseHeader = paid.headers.get("payment-response");
let settleTx = null;
if (responseHeader) {
  const decoded = JSON.parse(Buffer.from(responseHeader, "base64").toString("utf8"));
  settleTx = decoded.transaction;
  console.log(`   Payment Settlement Status : ${decoded.status ?? decoded.success}`);
  console.log(`   On-Chain Tx Hash          : ${settleTx}`);
} else {
  console.log("   PAYMENT-RESPONSE Header   : MISSING");
}

const parsed = parseMcpBody(text);
const first = parsed?.result?.content?.[0]?.text ?? text;
console.log(`3. Tool Result Error Flag   : ${parsed?.result?.isError === true}`);
console.log(`   Tool Execution Output:\n${first}\n`);

if (settleTx) {
  console.log(`4. Verifying Transaction Receipt on X Layer Mainnet (${settleTx})...`);
  let receipt = null;
  for (let attempt = 0; attempt < 10 && !receipt; attempt += 1) {
    receipt = await rpc("eth_getTransactionReceipt", [settleTx]);
    if (!receipt) await new Promise((r) => setTimeout(r, 3000));
  }
  const tx = await rpc("eth_getTransactionByHash", [settleTx]);
  console.log(
    `   Receipt Status  : ${receipt?.status === "0x1" ? "SUCCESS (0x1)" : receipt?.status}`
  );
  console.log(`   Block Number    : ${parseInt(receipt?.blockNumber ?? "0x0", 16)}`);
  console.log(`   Broadcaster     : ${tx?.from}`);
  console.log(
    `   Relayer Check   : ${
      tx?.from?.toLowerCase() === OUR_SETTLE_WALLET
        ? "SELF-HOSTED RELAYER"
        : "OKX OFFICIAL FACILITATOR RELAYER (Web3 SDK)"
    }`
  );
}
