/**
 * Turns a key pair generated with WebCrypto into the formats OpenSSH uses, so
 * keys can be generated in the browser without sending anything to the
 * server. Works from a JWK export: it hands over every part of the key as
 * base64url, with no ASN.1 to unpick.
 */
import { SshWriter } from "./ssh-wire.js";

/** The parts of a WebCrypto JWK export that SSH keys are built from. */
export interface KeyJwk {
  kty?: string;
  crv?: string;
  x?: string;
}

/** The SSH name for the key's type, e.g. "ssh-ed25519". */
export function keyType(jwk: KeyJwk): string {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "ssh-ed25519";
  throw new Error(`Unsupported key type: ${jwk.kty ?? "?"} ${jwk.crv ?? ""}`.trim());
}

/** The public key as SSH stores it: the key type, then the key itself. */
export function publicKeyBlob(jwk: KeyJwk): Uint8Array {
  const type = keyType(jwk);
  if (!jwk.x) throw new Error("The key is missing its public part.");
  return new SshWriter().string(type).string(fromBase64Url(jwk.x)).bytes();
}

/** The one-line form that goes in ~/.ssh/authorized_keys. */
export function publicKeyLine(jwk: KeyJwk, comment = ""): string {
  // A line break would split the authorized_keys entry in two.
  if (/[\r\n]/.test(comment)) throw new Error("A key comment can't contain line breaks.");
  return [keyType(jwk), toBase64(publicKeyBlob(jwk)), comment.trim()].filter(Boolean).join(" ");
}

/** The fingerprint `ssh-keygen -l` prints, e.g. "SHA256:uNiVztksCs…". */
export async function fingerprint(blob: Uint8Array): Promise<string> {
  // The copy gives digest() the plain ArrayBuffer its types insist on.
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(blob)));
  return "SHA256:" + toBase64(digest).replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array {
  const binary = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
