import { useEffect, useId, useState } from "react";
import { authorizedKeysCommand, publicKeyLine } from "@skiff/shared";
import { KEY_KINDS, generateKey, supportedKeyKinds, type GeneratedKey, type KeyKind } from "@/lib/keygen";
import { useCopyState, writeClipboard } from "@/components/MemoryEntryParts";
import * as I from "@/components/icons";

/** "or Generate a new key", shown under the private key box. */
export function GenerateKeyRow({
  onGenerated,
  onBusyChange,
}: {
  onGenerated: (key: GeneratedKey) => void;
  /** So the dialog can hold off saving until the key exists. */
  onBusyChange: (busy: boolean) => void;
}) {
  const [kinds, setKinds] = useState<KeyKind[] | null>(null);
  const [kind, setKind] = useState<KeyKind>("ed25519");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    supportedKeyKinds().then((found) => {
      if (!live) return;
      setKinds(found);
      if (found[0]) setKind(found[0]);
    });
    return () => { live = false; };
  }, []);

  if (kinds === null) return null;
  if (kinds.length === 0) {
    return (
      <div className="keygen__hint">
        {window.isSecureContext
          ? "This browser can't generate SSH keys. Paste an existing private key instead."
          : "Generating a key needs Skiff to be opened over HTTPS. You can still paste an existing private key."}
      </div>
    );
  }

  const generate = async () => {
    setBusy(true);
    onBusyChange(true);
    setError("");
    try {
      onGenerated(await generateKey(kind));
    } catch (err: any) {
      setError(err?.message || "Couldn't generate a key.");
    } finally {
      setBusy(false);
      onBusyChange(false);
    }
  };

  return (
    <div className="keygen__row">
      <span className="keygen__or">or</span>
      <button type="button" className="btn btn--secondary keygen__btn" disabled={busy} onClick={generate}>
        <I.Key size={13} /> {busy ? "Generating…" : "Generate a new key"}
      </button>
      {kinds.length > 1 && (
        <select className="keygen__kind" aria-label="Key type" value={kind} onChange={(e) => setKind(e.target.value as KeyKind)}>
          {kinds.map((k) => <option key={k} value={k}>{KEY_KINDS[k].label}</option>)}
        </select>
      )}
      {error && <div className="field-error">{error}</div>}
    </div>
  );
}

/**
 * A key generated in this dialog: its public half to copy to the server, and
 * a way to throw it away. The private half is never shown.
 */
export function GeneratedKeyPanel({
  generatedKey,
  comment,
  onCommentChange,
  onDiscard,
  replacingKey,
}: {
  generatedKey: GeneratedKey;
  comment: string;
  onCommentChange: (comment: string) => void;
  onDiscard: () => void;
  /** Editing a host that already has a credential, which this key will replace. */
  replacingKey: boolean;
}) {
  const line = publicKeyLine(generatedKey.jwk, comment);
  const commentId = useId();
  return (
    <div className="keygen">
      <div className="keygen__head">
        <span><I.Key size={13} /> New {KEY_KINDS[generatedKey.kind].label} key</span>
        <button type="button" className="btn btn--ghost keygen__discard" onClick={onDiscard}>Discard</button>
      </div>

      <div className="field">
        <label htmlFor={commentId}>Comment (helps you spot this key in authorized_keys)</label>
        <input id={commentId} value={comment} onChange={(e) => onCommentChange(e.target.value)} className="mono" spellCheck={false} />
      </div>

      <div className="field">
        <label>Public key</label>
        <CodeWithCopy text={line} />
        <div className="keygen__fp">Fingerprint <span className="mono">{generatedKey.fingerprint}</span></div>
      </div>

      <div className="field">
        <label>Add it to the server: run this there, as the user Skiff signs in as</label>
        <CodeWithCopy text={authorizedKeysCommand(line)} />
      </div>

      {replacingKey ? (
        <div className="keygen__warn">
          <span className="ic"><I.Warn size={14} /></span>
          <span>
            <strong>Add the public key to the server before you save.</strong> Saving switches this host to the new key,
            so Skiff can't sign in until the server has it.
          </span>
        </div>
      ) : (
        <div className="keygen__hint">
          Copy the public key now: Skiff won't show it again. The private key is saved, encrypted, with this host and never shown.
        </div>
      )}
    </div>
  );
}

function CodeWithCopy({ text }: { text: string }) {
  const [copied, setCopied] = useCopyState();
  return (
    <div className="keygen__code">
      <pre className="mono">{text}</pre>
      <button type="button" className="keygen__copy" title="Copy" onClick={async () => setCopied(await writeClipboard(text))}>
        {copied === "ok" ? <I.Check size={13} /> : <I.Copy size={13} />}
        <span>{copied === "ok" ? "Copied" : copied === "fail" ? "Couldn't copy" : "Copy"}</span>
      </button>
    </div>
  );
}
