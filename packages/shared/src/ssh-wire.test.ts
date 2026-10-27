import { test } from "node:test";
import assert from "node:assert/strict";
import { SshWriter } from "./ssh-wire.js";

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const fromHex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

test("uint32 is big-endian", () => {
  assert.equal(hex(new SshWriter().uint32(0x01020304).bytes()), "01020304");
});

test("string is length-prefixed, for text and bytes", () => {
  assert.equal(hex(new SshWriter().string("ssh-ed25519").bytes()), "0000000b" + hex(new TextEncoder().encode("ssh-ed25519")));
  assert.equal(hex(new SshWriter().string(fromHex("cafe")).bytes()), "00000002cafe");
  assert.equal(hex(new SshWriter().string("").bytes()), "00000000");
});

// The non-negative examples from RFC 4251 §5.
test("mpint matches the RFC 4251 examples", () => {
  assert.equal(hex(new SshWriter().mpint(fromHex("00")).bytes()), "00000000");
  assert.equal(hex(new SshWriter().mpint(fromHex("09a378f9b2e332a7")).bytes()), "0000000809a378f9b2e332a7");
  assert.equal(hex(new SshWriter().mpint(fromHex("80")).bytes()), "000000020080");
});

test("mpint drops leading zeros before deciding on the 0x00 pad", () => {
  assert.equal(hex(new SshWriter().mpint(fromHex("000001")).bytes()), "0000000101");
  assert.equal(hex(new SshWriter().mpint(fromHex("0000ff")).bytes()), "0000000200ff");
});

test("writes chain in order", () => {
  const out = new SshWriter().string("a").uint32(1).string(fromHex("ff")).bytes();
  assert.equal(hex(out), "00000001" + "61" + "00000001" + "00000001ff");
});
