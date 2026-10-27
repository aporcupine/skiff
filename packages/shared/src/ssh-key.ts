/**
 * Turns a key pair generated with WebCrypto into the formats OpenSSH uses, so
 * keys can be generated in the browser without sending anything to the
 * server. Works from a JWK export: it hands over every part of the key as
 * base64url, with no ASN.1 to unpick.
 */
import { SshWriter, concatBytes } from "./ssh-wire.js";

/** The parts of a WebCrypto JWK export that SSH keys are built from. */
export interface KeyJwk {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
}

/** The SSH name for the key's type, e.g. "ssh-ed25519". */
export function keyType(jwk: KeyJwk): string {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "ssh-ed25519";
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ecdsa-sha2-nistp256";
  throw new Error(`Unsupported key type: ${jwk.kty ?? "?"} ${jwk.crv ?? ""}`.trim());
}

/** The public key as SSH stores it: the key type, then the key itself. */
export function publicKeyBlob(jwk: KeyJwk): Uint8Array {
  const w = new SshWriter().string(keyType(jwk));
  writePublic(w, jwk);
  return w.bytes();
}

/** The one-line form that goes in ~/.ssh/authorized_keys. */
export function publicKeyLine(jwk: KeyJwk, comment = ""): string {
  return [keyType(jwk), toBase64(publicKeyBlob(jwk)), cleanComment(comment)].filter(Boolean).join(" ");
}

/**
 * The private key file, unencrypted, in the "openssh-key-v1" format
 * ssh-keygen writes (see PROTOCOL.key in the OpenSSH source). Skiff encrypts
 * it in the vault, so a passphrase here would only add a second secret.
 */
export function privateKeyPem(jwk: KeyJwk, comment = ""): string {
  const type = keyType(jwk);
  // Two copies of the same random number: OpenSSH compares them to tell a
  // wrong passphrase from a corrupt file. Unencrypted, they just have to match.
  const [checkint = 0] = crypto.getRandomValues(new Uint32Array(1));
  const section = new SshWriter().uint32(checkint).uint32(checkint).string(type);
  writePublic(section, jwk);
  writePrivate(section, jwk);
  section.string(cleanComment(comment));
  const unpadded = section.bytes();
  // Padded to the 8-byte block size with 1, 2, 3, …, which OpenSSH checks.
  const padding = Uint8Array.from({ length: (8 - (unpadded.length % 8)) % 8 }, (_, i) => i + 1);

  const file = new SshWriter()
    .raw(new TextEncoder().encode("openssh-key-v1\0"))
    .string("none") // cipher
    .string("none") // key derivation function
    .string("") // its options
    .uint32(1) // number of keys
    .string(publicKeyBlob(jwk))
    .string(concatBytes(unpadded, padding))
    .bytes();
  const lines = toBase64(file).match(/.{1,70}/g) ?? [];
  return ["-----BEGIN OPENSSH PRIVATE KEY-----", ...lines, "-----END OPENSSH PRIVATE KEY-----", ""].join("\n");
}

/** The fingerprint `ssh-keygen -l` prints, e.g. "SHA256:uNiVztksCs…". */
export async function fingerprint(blob: Uint8Array): Promise<string> {
  // The copy gives digest() the plain ArrayBuffer its types insist on.
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(blob)));
  return "SHA256:" + toBase64(digest).replace(/=+$/, "");
}

function writePublic(w: SshWriter, jwk: KeyJwk): void {
  if (!jwk.x) throw new Error("The key is missing its public part.");
  if (jwk.kty === "EC") {
    if (!jwk.y) throw new Error("The key is missing its public part.");
    // The curve name, then the public point uncompressed: 0x04, x, y.
    w.string("nistp256").string(concatBytes(new Uint8Array([4]), fromBase64Url(jwk.x), fromBase64Url(jwk.y)));
  } else {
    w.string(fromBase64Url(jwk.x));
  }
}

function writePrivate(w: SshWriter, jwk: KeyJwk): void {
  if (!jwk.d || !jwk.x) throw new Error("The key is missing its private part.");
  if (jwk.kty === "EC") {
    w.mpint(fromBase64Url(jwk.d));
  } else {
    // OpenSSH stores the 32-byte seed followed by the public key.
    w.string(concatBytes(fromBase64Url(jwk.d), fromBase64Url(jwk.x)));
  }
}

function cleanComment(comment: string): string {
  // A line break would split the authorized_keys entry in two.
  if (/[\r\n]/.test(comment)) throw new Error("A key comment can't contain line breaks.");
  return comment.trim();
}

function fromBase64Url(s: string): Uint8Array {
  const binary = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
