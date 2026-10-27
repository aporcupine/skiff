import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey } from "node:crypto";
import ssh2 from "ssh2";
import { fingerprint, keyType, publicKeyBlob, publicKeyLine } from "./ssh-key.js";

// ssh2 is the library Skiff connects with, so it's the judge of whether our
// output is a valid SSH key. It's an independent implementation, not ours.
const { parseKey } = ssh2.utils;

async function newEd25519Jwk() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return crypto.subtle.exportKey("jwk", pair.privateKey);
}

function parsePublic(line: string) {
  const parsed = parseKey(line);
  assert.ok(!(parsed instanceof Error), `ssh2 rejected the key: ${parsed}`);
  return Array.isArray(parsed) ? parsed[0]! : parsed;
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

describe("Unsupported keys", () => {
  test("are refused with a clear message", () => {
    assert.throws(() => publicKeyBlob({ kty: "EC", crv: "P-384", x: "AA" }), /Unsupported key type: EC P-384/);
  });

  test("a key without its public part is refused", () => {
    assert.throws(() => publicKeyBlob({ kty: "OKP", crv: "Ed25519" }), /missing its public part/);
  });
});
