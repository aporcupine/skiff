import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { SshWriter } from "./ssh-wire.js";

// Expected bytes are written as hex so they can be read against the spec.
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const fromHex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

describe("SshWriter", () => {
  // Every length and count in an SSH key is stored this way.
  test("writes numbers as 4 bytes, most significant first", () => {
    assert.equal(hex(new SshWriter().uint32(0x01020304).bytes()), "01020304");
  });

  // e.g. the key type name "ssh-ed25519" is stored as 00 00 00 0b + its 11 bytes.
  test("writes text with its length in front", () => {
    assert.equal(hex(new SshWriter().string("ssh-ed25519").bytes()), "0000000b" + hex(new TextEncoder().encode("ssh-ed25519")));
  });

  test("writes raw bytes with their length in front", () => {
    assert.equal(hex(new SshWriter().string(fromHex("cafe")).bytes()), "00000002cafe");
  });

  test("writes an empty string as just a zero length", () => {
    assert.equal(hex(new SshWriter().string("").bytes()), "00000000");
  });

  test("writes several values back to back, in the order given", () => {
    const out = new SshWriter().string("a").uint32(1).string(fromHex("ff")).bytes();
    assert.equal(hex(out), "00000001" + "61" + "00000001" + "00000001ff");
  });
});

// Big numbers (the private parts of RSA and ECDSA keys). SSH reads a number
// whose first bit is set as negative, so those get a 00 byte in front.
describe("SshWriter big numbers", () => {
  // The expected bytes are copied from the SSH spec (RFC 4251 section 5).
  test("matches the examples in the SSH spec", () => {
    assert.equal(hex(new SshWriter().mpint(fromHex("00")).bytes()), "00000000");
    assert.equal(hex(new SshWriter().mpint(fromHex("09a378f9b2e332a7")).bytes()), "0000000809a378f9b2e332a7");
    assert.equal(hex(new SshWriter().mpint(fromHex("80")).bytes()), "000000020080");
  });

  // Browsers can hand us numbers padded with zero bytes, which SSH doesn't allow.
  test("strips leading zero bytes", () => {
    assert.equal(hex(new SshWriter().mpint(fromHex("000001")).bytes()), "0000000101");
  });

  test("strips leading zeros, then adds one 00 back if the first bit is set", () => {
    assert.equal(hex(new SshWriter().mpint(fromHex("0000ff")).bytes()), "0000000200ff");
  });
});
