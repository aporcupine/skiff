import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, verify, KeyObject } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ssh2 from "ssh2";
import { authorizedKeysCommand, defaultKeyComment, fingerprint, keyType, privateKeyPem, publicKeyBlob, publicKeyLine } from "./ssh-key.js";

// ssh2 is the library Skiff connects with, so it's the judge of whether our
// output is a valid SSH key. It's an independent implementation, not ours.
const { parseKey } = ssh2.utils;

// Every key type runs through the same tests below.
const keyTypes = [
  {
    name: "Ed25519",
    sshType: "ssh-ed25519",
    algorithm: { name: "Ed25519" },
    hash: null, // Ed25519 hashes internally
  },
  {
    name: "ECDSA P-256",
    sshType: "ecdsa-sha2-nistp256",
    algorithm: { name: "ECDSA", namedCurve: "P-256" },
    hash: "sha256",
  },
] as const;

type KeyTypeCase = (typeof keyTypes)[number];

async function newPair(type: KeyTypeCase) {
  const pair = (await crypto.subtle.generateKey(type.algorithm, true, ["sign", "verify"])) as CryptoKeyPair;
  return { pair, jwk: await crypto.subtle.exportKey("jwk", pair.privateKey) };
}

async function newJwk(type: KeyTypeCase) {
  return (await newPair(type)).jwk;
}

function parse(key: string) {
  const parsed = parseKey(key);
  assert.ok(!(parsed instanceof Error), `ssh2 rejected the key: ${parsed}`);
  return Array.isArray(parsed) ? parsed[0]! : parsed;
}

// Tests that run a POSIX shell, or rely on Unix file permissions, can't run
// on Windows; they're skipped there.
const isWindows = process.platform === "win32";

// OpenSSH's own ssh-keygen is the strictest reader of these files. It's on
// CI's Ubuntu runners; where it isn't installed, those tests are skipped.
// Windows is skipped too: ssh-keygen there checks file ACLs, not the mode we set.
const hasSshKeygen = !isWindows && spawnSync("ssh-keygen", ["-?"]).error === undefined;

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

for (const type of keyTypes) {
  describe(`${type.name} public key`, () => {
    test("is accepted by ssh2 as a public key of the right type", async () => {
      const key = parse(publicKeyLine(await newJwk(type)));
      assert.equal(key.type, type.sshType);
      assert.equal(key.isPrivateKey(), false);
    });

    test("matches what ssh2 reads back from the line", async () => {
      const jwk = await newJwk(type);
      assert.deepEqual(new Uint8Array(parse(publicKeyLine(jwk)).getPublicSSH()), publicKeyBlob(jwk));
    });

    // Checks we put the right key bytes in, using Node's own crypto as a second
    // opinion. Its DER export ends with the same raw key SSH stores last.
    test("holds the same key Node's crypto sees in the JWK", async () => {
      const { pair, jwk } = await newPair(type);
      const der = KeyObject.from(pair.publicKey).export({ type: "spki", format: "der" });
      const blob = publicKeyBlob(jwk);
      const size = type.name === "Ed25519" ? 32 : 65;
      assert.deepEqual(blob.subarray(-size), new Uint8Array(der.subarray(-size)));
    });

    test("starts with the key type", async () => {
      const jwk = await newJwk(type);
      assert.equal(keyType(jwk), type.sshType);
      assert.ok(publicKeyLine(jwk).startsWith(`${type.sshType} AAAA`));
    });
  });

  describe(`${type.name} private key`, () => {
    test("is accepted by ssh2 as a private key of the right type", async () => {
      const key = parse(privateKeyPem(await newJwk(type)));
      assert.equal(key.type, type.sshType);
      assert.equal(key.isPrivateKey(), true);
    });

    test("carries the same public key as the public key line", async () => {
      const jwk = await newJwk(type);
      assert.deepEqual(new Uint8Array(parse(privateKeyPem(jwk)).getPublicSSH()), publicKeyBlob(jwk));
    });

    // The real proof it's the right private key: what it signs, the original
    // WebCrypto public key accepts.
    test("signs data that the original public key verifies", async () => {
      const { pair, jwk } = await newPair(type);
      const data = new TextEncoder().encode("hello from skiff");
      const signature = parse(privateKeyPem(jwk)).sign(data);
      assert.ok(!(signature instanceof Error), `ssh2 couldn't sign: ${signature}`);
      // ssh2 gives ECDSA signatures in DER form, which Node's verify reads directly.
      const publicKey = { key: KeyObject.from(pair.publicKey), dsaEncoding: "der" as const };
      assert.equal(verify(type.hash, data, publicKey, signature), true);
    });

    test("stores the comment", async () => {
      assert.equal(parse(privateKeyPem(await newJwk(type), "skiff-web-1")).comment, "skiff-web-1");
    });

    test("is laid out like an ssh-keygen file", async () => {
      const lines = privateKeyPem(await newJwk(type)).split("\n");
      assert.equal(lines[0], "-----BEGIN OPENSSH PRIVATE KEY-----");
      assert.equal(lines.at(-2), "-----END OPENSSH PRIVATE KEY-----");
      assert.equal(lines.at(-1), "", "ends with a newline");
      for (const line of lines.slice(1, -2)) assert.ok(line.length <= 70, `line too long: ${line.length}`);
    });

    test("a key without its private part is refused", async () => {
      const { d: _d, ...publicOnly } = await newJwk(type);
      assert.throws(() => privateKeyPem(publicOnly), /missing its private part/);
    });
  });

  describe(`${type.name} private key, checked by OpenSSH's ssh-keygen`, { skip: !hasSshKeygen && "ssh-keygen isn't installed" }, () => {
    test("gives back exactly our public key line", async () => {
      const jwk = await newJwk(type);
      assert.equal(sshKeygen(["-y"], privateKeyPem(jwk, "skiff-web-1")), publicKeyLine(jwk, "skiff-web-1"));
    });

    test("shows the same fingerprint as ours", async () => {
      const jwk = await newJwk(type);
      const printed = sshKeygen(["-l"], privateKeyPem(jwk));
      assert.ok(printed.includes(await fingerprint(publicKeyBlob(jwk))), printed);
    });

    // The comment's length decides how much padding goes on the end, so try
    // every padding length (0-7) twice over. ssh-keygen rejects bad padding.
    test("accepts every comment length, so every amount of padding", async () => {
      const jwk = await newJwk(type);
      for (let n = 0; n < 16; n++) {
        const comment = "c".repeat(n);
        assert.equal(sshKeygen(["-y"], privateKeyPem(jwk, comment)), publicKeyLine(jwk, comment));
      }
    });
  });
}

// The private number of a P-256 key is written as an SSH big number, so its
// first byte decides whether a 00 goes in front. Random keys hit both cases
// about half the time each; these make sure both are always tested.
describe("ECDSA P-256 private number", { skip: !hasSshKeygen && "ssh-keygen isn't installed" }, () => {
  async function keyWhoseFirstByte(wanted: (b: number) => boolean) {
    for (;;) {
      const jwk = await newJwk(keyTypes[1]);
      if (wanted(Buffer.from(jwk.d!, "base64url")[0]!)) return jwk;
    }
  }

  test("works when its first bit is set (needs a 00 in front)", async () => {
    const jwk = await keyWhoseFirstByte((b) => b >= 0x80);
    assert.equal(sshKeygen(["-y"], privateKeyPem(jwk)), publicKeyLine(jwk));
  });

  test("works when its first bit is clear (no 00 needed)", async () => {
    const jwk = await keyWhoseFirstByte((b) => b < 0x80);
    assert.equal(sshKeygen(["-y"], privateKeyPem(jwk)), publicKeyLine(jwk));
  });
});

describe("Key comment", () => {
  test("goes at the end of the line, where ssh2 finds it", async () => {
    const key = parse(publicKeyLine(await newJwk(keyTypes[0]), "skiff-web-1 2026-10-27"));
    assert.equal(key.comment, "skiff-web-1 2026-10-27");
  });

  test("is left off cleanly when empty, with no trailing space", async () => {
    const line = publicKeyLine(await newJwk(keyTypes[0]), "  ");
    assert.equal(line.split(" ").length, 2);
    assert.ok(!line.endsWith(" "));
  });

  // A line break would split the authorized_keys entry into two broken lines.
  test("is rejected if it contains a line break", async () => {
    const jwk = await newJwk(keyTypes[0]);
    assert.throws(() => publicKeyLine(jwk, "a\nb"), /line breaks/);
    assert.throws(() => publicKeyLine(jwk, "a\rb"), /line breaks/);
    assert.throws(() => privateKeyPem(jwk, "a\nb"), /line breaks/);
  });
});

describe("Fingerprint", () => {
  // Same recipe as `ssh-keygen -l`: SHA-256 of the key, base64 without the = padding.
  test("matches the ssh-keygen format, worked out with Node's own hashing", async () => {
    const blob = publicKeyBlob(await newJwk(keyTypes[0]));
    const expected = "SHA256:" + createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
    assert.equal(await fingerprint(blob), expected);
  });

  test("is different for different keys", async () => {
    const a = await fingerprint(publicKeyBlob(await newJwk(keyTypes[0])));
    const b = await fingerprint(publicKeyBlob(await newJwk(keyTypes[0])));
    assert.notEqual(a, b);
  });
});

describe("Unsupported keys", () => {
  test("are refused with a clear message", () => {
    assert.throws(() => publicKeyBlob({ kty: "EC", crv: "P-384", x: "AA", y: "AA" }), /Unsupported key type: EC P-384/);
  });

  test("a key without its public part is refused", () => {
    assert.throws(() => publicKeyBlob({ kty: "OKP", crv: "Ed25519" }), /missing its public part/);
    assert.throws(() => publicKeyBlob({ kty: "EC", crv: "P-256", x: "AA" }), /missing its public part/);
  });
});

describe("Install command", { skip: isWindows && "needs a POSIX shell" }, () => {
  // Runs the command for real in a shell, with a throwaway home directory.
  function runInFreshHome(command: string) {
    const home = mkdtempSync(join(tmpdir(), "skiff-home-"));
    try {
      const run = spawnSync("sh", ["-c", command], { env: { ...process.env, HOME: home }, encoding: "utf-8" });
      assert.equal(run.status, 0, `the command failed: ${run.stderr}`);
      return {
        authorizedKeys: readFileSync(join(home, ".ssh", "authorized_keys"), "utf-8"),
        sshDirMode: statSync(join(home, ".ssh")).mode & 0o777,
        fileMode: statSync(join(home, ".ssh", "authorized_keys")).mode & 0o777,
      };
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }

  test("adds the key to authorized_keys, with the permissions sshd needs", async () => {
    const line = publicKeyLine(await newJwk(keyTypes[0]), "skiff-web-1");
    const result = runInFreshHome(authorizedKeysCommand(line));
    assert.equal(result.authorizedKeys, line + "\n");
    assert.equal(result.sshDirMode, 0o700);
    assert.equal(result.fileMode, 0o600);
  });

  test("keeps keys that are already there", async () => {
    const first = publicKeyLine(await newJwk(keyTypes[0]), "first");
    const second = publicKeyLine(await newJwk(keyTypes[0]), "second");
    const result = runInFreshHome(authorizedKeysCommand(first) + " && " + authorizedKeysCommand(second));
    assert.equal(result.authorizedKeys, first + "\n" + second + "\n");
  });

  // A comment could hold anything the user typed; none of it may run as a command.
  test("copes with quotes and shell characters in the comment", async () => {
    const line = publicKeyLine(await newJwk(keyTypes[0]), `it's $(touch pwned) \`id\` "x"; rm -rf /tmp/nope`);
    assert.equal(runInFreshHome(authorizedKeysCommand(line)).authorizedKeys, line + "\n");
  });
  // Some shells' echo turns \c, \n and friends into control codes; \c would
  // cut the line short and drop its newline, gluing the next key onto it.
  test("writes backslashes in the comment exactly as typed", async () => {
    const line = publicKeyLine(await newJwk(keyTypes[0]), "tom\\cafter \\n \\t \\\\ end");
    assert.equal(runInFreshHome(authorizedKeysCommand(line)).authorizedKeys, line + "\n");
  });
});

describe("Default key comment", () => {
  const date = new Date("2026-10-27T12:00:00Z");

  test("names the app, the host and the date", () => {
    assert.equal(defaultKeyComment("prod-web-1", date), "skiff-prod-web-1-2026-10-27");
  });

  test("turns spaces and odd characters into dashes", () => {
    assert.equal(defaultKeyComment("  Production Web #1 ", date), "skiff-production-web-1-2026-10-27");
  });

  test("keeps the dots in a hostname", () => {
    assert.equal(defaultKeyComment("web.example.com", date), "skiff-web.example.com-2026-10-27");
  });

  test("still works with no host name yet", () => {
    assert.equal(defaultKeyComment("", date), "skiff-2026-10-27");
  });
});
