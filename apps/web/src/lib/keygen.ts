import { fingerprint, publicKeyBlob } from "@skiff/shared";

/**
 * SSH key generation in the browser, with WebCrypto. The private key only
 * leaves the browser the same way a pasted key does: in the host's credential,
 * encrypted into the vault on save.
 */
export type KeyKind = "ed25519" | "ecdsa-p256";

export const KEY_KINDS: Record<KeyKind, { label: string; algorithm: EcKeyGenParams | Algorithm }> = {
  "ed25519": { label: "Ed25519", algorithm: { name: "Ed25519" } },
  "ecdsa-p256": { label: "ECDSA P-256", algorithm: { name: "ECDSA", namedCurve: "P-256" } },
};

export interface GeneratedKey {
  kind: KeyKind;
  /** Includes the private part. Kept in memory only until the host is saved. */
  jwk: JsonWebKey;
  fingerprint: string;
}

/**
 * The key kinds this browser can generate, best first. WebCrypto only exists
 * on HTTPS (or localhost), so this is empty over plain HTTP. Ed25519 is newer
 * than ECDSA, so older browsers may only offer P-256.
 */
export async function supportedKeyKinds(): Promise<KeyKind[]> {
  if (!window.isSecureContext || !crypto.subtle) return [];
  const supported: KeyKind[] = [];
  for (const kind of Object.keys(KEY_KINDS) as KeyKind[]) {
    try {
      await crypto.subtle.generateKey(KEY_KINDS[kind].algorithm, true, ["sign", "verify"]);
      supported.push(kind);
    } catch {
      // Not supported here; leave it out.
    }
  }
  return supported;
}

export async function generateKey(kind: KeyKind): Promise<GeneratedKey> {
  const pair = (await crypto.subtle.generateKey(KEY_KINDS[kind].algorithm, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return { kind, jwk, fingerprint: await fingerprint(publicKeyBlob(jwk)) };
}
