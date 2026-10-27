import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ssh2 from "ssh2";
import { fingerprint, keyType, privateKeyPem, publicKeyBlob, publicKeyLine } from "./ssh-key.js";

// ssh2 is the library Skiff connects with, so it's the judge of whether our
// output is a valid SSH key. It's an independent implementation, not ours.
const { parseKey } = ssh2.utils;

async function newEd25519Pair() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return { pair, jwk: await crypto.subtle.exportKey("jwk", pair.privateKey) };
}

async function newEd25519Jwk() {
  return (await newEd25519Pair()).jwk;
}

function parse(key: string) {
  const parsed = parseKey(key);
  assert.ok(!(parsed instanceof Error), `ssh2 rejected the key: ${parsed}`);
  return Array.isArray(parsed) ? parsed[0]! : parsed;
}
const parsePublic = parse;

// OpenSSH's own ssh-keygen is the strictest reader of these files. It's on
// CI's Ubuntu runners; where it isn't installed, those tests are skipped.
const hasSshKeygen = spawnSync("ssh-keygen", ["-?"]).error === undefined;

/** Runs ssh-keygen on a private key file and returns what it prints. */
function sshKeygen(args: string[], pem: string): string {
  const dir = mkdtempSync(join(tmpdir(), "skiff-key-"));
  try {
    const file = join(dir, "id");
    // ssh-keygen refuses to read a private key other users could read.
    writeFileSync(file, pem, { mode: 0o600 });
    const run = spawnSync("ssh-keygen", [...args, "-f", file], { encoding: "utf-8" });
    assert.equal(run.status, 0, `ssh-keygen failed: ${run.stderr}`);
    return run.stdout.trim();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("Ed25519 public key", () => {
  test("is accepted by ssh2 as an Ed25519 public key", async () => {
    const key = parsePublic(publicKeyLine(await newEd25519Jwk()));
    assert.equal(key.type, "ssh-ed25519");
    assert.equal(key.isPrivateKey(), false);
  });

  test("matches what ssh2 reads back from the line", async () => {
    const jwk = await newEd25519Jwk();
    const key = parsePublic(publicKeyLine(jwk));
    assert.deepEqual(new Uint8Array(key.getPublicSSH()), publicKeyBlob(jwk));
  });

  // Checks we put the right 32 bytes in, using Node's own crypto as a second opinion.
  test("holds the same key Node's crypto sees in the JWK", async () => {
    const jwk = await newEd25519Jwk();
    const der = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" }).export({ type: "spki", format: "der" });
    assert.deepEqual(publicKeyBlob(jwk).subarray(-32), new Uint8Array(der.subarray(-32)));
  });

  test("starts with the key type", async () => {
    const jwk = await newEd25519Jwk();
    assert.equal(keyType(jwk), "ssh-ed25519");
    assert.match(publicKeyLine(jwk), /^ssh-ed25519 AAAA/);
  });
});

describe("Key comment", () => {
  test("goes at the end of the line, where ssh2 finds it", async () => {
    const key = parsePublic(publicKeyLine(await newEd25519Jwk(), "skiff-web-1 2026-10-27"));
    assert.equal(key.comment, "skiff-web-1 2026-10-27");
  });

  test("is left off cleanly when empty, with no trailing space", async () => {
    const line = publicKeyLine(await newEd25519Jwk(), "  ");
    assert.equal(line.split(" ").length, 2);
    assert.ok(!line.endsWith(" "));
  });

  // A line break would split the authorized_keys entry into two broken lines.
  test("is rejected if it contains a line break", async () => {
    const jwk = await newEd25519Jwk();
    assert.throws(() => publicKeyLine(jwk, "a\nb"), /line breaks/);
    assert.throws(() => publicKeyLine(jwk, "a\rb"), /line breaks/);
  });
});

describe("Fingerprint", () => {
  // Same recipe as `ssh-keygen -l`: SHA-256 of the key, base64 without the = padding.
  test("matches the ssh-keygen format, worked out with Node's own hashing", async () => {
    const blob = publicKeyBlob(await newEd25519Jwk());
    const expected = "SHA256:" + createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
    assert.equal(await fingerprint(blob), expected);
  });

  test("is different for different keys", async () => {
    const a = await fingerprint(publicKeyBlob(await newEd25519Jwk()));
    const b = await fingerprint(publicKeyBlob(await newEd25519Jwk()));
    assert.notEqual(a, b);
  });
});

describe("Ed25519 private key", () => {
  test("is accepted by ssh2 as an Ed25519 private key", async () => {
    const key = parse(privateKeyPem(await newEd25519Jwk()));
    assert.equal(key.type, "ssh-ed25519");
    assert.equal(key.isPrivateKey(), true);
  });

  test("carries the same public key as the public key line", async () => {
    const jwk = await newEd25519Jwk();
    assert.deepEqual(new Uint8Array(parse(privateKeyPem(jwk)).getPublicSSH()), publicKeyBlob(jwk));
  });

  // The real proof it's the right private key: what it signs, the original
  // WebCrypto public key accepts.
  test("signs data that the original public key verifies", async () => {
    const { pair, jwk } = await newEd25519Pair();
    const data = new TextEncoder().encode("hello from skiff");
    const signature = parse(privateKeyPem(jwk)).sign(data);
    assert.ok(!(signature instanceof Error), `ssh2 couldn't sign: ${signature}`);
    assert.equal(await crypto.subtle.verify({ name: "Ed25519" }, pair.publicKey, signature, data), true);
  });

  test("stores the comment", async () => {
    assert.equal(parse(privateKeyPem(await newEd25519Jwk(), "skiff-web-1")).comment, "skiff-web-1");
  });

  test("is laid out like an ssh-keygen file", async () => {
    const lines = privateKeyPem(await newEd25519Jwk()).split("\n");
    assert.equal(lines[0], "-----BEGIN OPENSSH PRIVATE KEY-----");
    assert.equal(lines.at(-2), "-----END OPENSSH PRIVATE KEY-----");
    assert.equal(lines.at(-1), "", "ends with a newline");
    for (const line of lines.slice(1, -2)) assert.ok(line.length <= 70, `line too long: ${line.length}`);
  });

  test("a key without its private part is refused", () => {
    assert.throws(() => privateKeyPem({ kty: "OKP", crv: "Ed25519", x: "AA" }), /missing its private part/);
  });
});

describe("Ed25519 private key, checked by OpenSSH's ssh-keygen", { skip: !hasSshKeygen && "ssh-keygen isn't installed" }, () => {
  test("gives back exactly our public key line", async () => {
    const jwk = await newEd25519Jwk();
    assert.equal(sshKeygen(["-y"], privateKeyPem(jwk, "skiff-web-1")), publicKeyLine(jwk, "skiff-web-1"));
  });

  test("shows the same fingerprint as ours", async () => {
    const jwk = await newEd25519Jwk();
    const printed = sshKeygen(["-l"], privateKeyPem(jwk));
    assert.ok(printed.includes(await fingerprint(publicKeyBlob(jwk))), printed);
  });

  // The comment's length decides how much padding goes on the end, so try
  // every padding length (0-7) twice over. ssh-keygen rejects bad padding.
  test("accepts every comment length, so every amount of padding", async () => {
    const jwk = await newEd25519Jwk();
    for (let n = 0; n < 16; n++) {
      const comment = "c".repeat(n);
      assert.equal(sshKeygen(["-y"], privateKeyPem(jwk, comment)), publicKeyLine(jwk, comment));
    }
  });
});

describe("Unsupported keys", () => {
  test("are refused with a clear message", () => {
    assert.throws(() => publicKeyBlob({ kty: "EC", crv: "P-384", x: "AA" }), /Unsupported key type: EC P-384/);
  });

  test("a key without its public part is refused", () => {
    assert.throws(() => publicKeyBlob({ kty: "OKP", crv: "Ed25519" }), /missing its public part/);
  });
});
