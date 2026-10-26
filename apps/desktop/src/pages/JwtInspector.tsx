import { useState } from "react";
import { KeyRound } from "lucide-react";
import { coreClient, JwtDecoded, VerifyResult } from "../lib/coreClient";

export default function JwtInspector() {
  const [token, setToken] = useState("");
  const [decoded, setDecoded] = useState<JwtDecoded | null>(null);
  const [decodeError, setDecodeError] = useState<string | null>(null);

  const [secret, setSecret] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  async function handleDecode(value: string) {
    setToken(value);
    setVerifyResult(null);
    if (!value.trim()) {
      setDecoded(null);
      setDecodeError(null);
      return;
    }
    try {
      const d = await coreClient.jwtDecode(value.trim());
      setDecoded(d);
      setDecodeError(null);
    } catch (err) {
      setDecoded(null);
      setDecodeError((err as Error).message);
    }
  }

  async function handleVerify() {
    if (!decoded) return;
    setVerifying(true);
    try {
      const isHmac = decoded.algorithm.startsWith("HS");
      const res = await coreClient.jwtVerify(
        token.trim(),
        decoded.algorithm,
        isHmac ? { secret } : { publicKeyPem }
      );
      setVerifyResult(res);
    } catch (err) {
      setVerifyResult({ valid: false, error: (err as Error).message });
    } finally {
      setVerifying(false);
    }
  }

  const isHmac = decoded?.algorithm?.startsWith("HS");
  const isAsymmetric = decoded?.algorithm?.startsWith("RS") || decoded?.algorithm?.startsWith("ES");

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center gap-2 mb-1">
        <KeyRound size={18} className="text-indigo-400" />
        <h1 className="text-lg font-semibold">JWT Inspector</h1>
      </div>
      <p className="text-sm text-slate-500 mb-6">
        Decode, inspect, and optionally verify a JWT's signature for authorized testing.
      </p>

      <textarea
        className="w-full bg-slate-900 border border-slate-800 rounded-md px-3 py-2 text-xs font-mono outline-none focus:border-indigo-500 h-24"
        placeholder="Paste a JWT: eyJhbGciOi..."
        value={token}
        onChange={(e) => handleDecode(e.target.value)}
      />

      {decodeError && <div className="text-xs text-rose-400 mt-2">{decodeError}</div>}

      {decoded && (
        <div className="mt-6 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Panel title="Header">
              <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                {JSON.stringify(decoded.header, null, 2)}
              </pre>
            </Panel>
            <Panel title="Payload">
              <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                {JSON.stringify(decoded.payload, null, 2)}
              </pre>
            </Panel>
            <Panel title="Signature">
              <div className="text-xs font-mono break-all text-slate-400">{decoded.signature || "(none)"}</div>
              <div className="mt-3 space-y-1 text-xs">
                <StatusRow label="Algorithm" value={decoded.algorithm || "(missing)"} />
                <StatusRow
                  label="Expiry"
                  value={decoded.expiresAt ? new Date(decoded.expiresAt).toLocaleString() : "none"}
                  tone={decoded.isExpired ? "bad" : "ok"}
                />
                {decoded.notBefore && (
                  <StatusRow
                    label="Not before"
                    value={new Date(decoded.notBefore).toLocaleString()}
                    tone={decoded.isNotYetValid ? "bad" : "ok"}
                  />
                )}
              </div>
            </Panel>
          </div>

          {decoded.warnings.length > 0 && (
            <div className="border border-amber-500/30 bg-amber-500/10 rounded-lg p-3 text-xs text-amber-300 space-y-1">
              {decoded.warnings.map((w, i) => (
                <div key={i}>⚠ {w}</div>
              ))}
            </div>
          )}

          {(isHmac || isAsymmetric) && (
            <div className="border border-slate-800 rounded-lg p-4 bg-slate-900/40">
              <div className="text-sm font-medium mb-3">Verify signature</div>
              {isHmac ? (
                <input
                  className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm outline-none focus:border-indigo-500 mb-3"
                  placeholder="HMAC secret"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                />
              ) : (
                <textarea
                  className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-xs font-mono outline-none focus:border-indigo-500 h-24 mb-3"
                  placeholder="-----BEGIN PUBLIC KEY-----"
                  value={publicKeyPem}
                  onChange={(e) => setPublicKeyPem(e.target.value)}
                />
              )}
              <button
                onClick={handleVerify}
                disabled={verifying}
                className="bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 text-white text-sm font-medium px-3 py-1.5 rounded-md"
              >
                {verifying ? "Verifying..." : "Verify signature"}
              </button>

              {verifyResult && (
                <div
                  className={`mt-3 text-sm font-medium ${
                    verifyResult.valid ? "text-emerald-400" : "text-rose-400"
                  }`}
                >
                  {verifyResult.valid ? "✓ Signature valid" : `✗ Invalid — ${verifyResult.error ?? "signature does not match"}`}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-slate-800 rounded-lg p-3 bg-slate-900/40">
      <div className="text-xs font-medium text-slate-400 mb-2">{title}</div>
      {children}
    </div>
  );
}

function StatusRow({ label, value, tone }: { label: string; value: string; tone?: "ok" | "bad" }) {
  return (
    <div className="flex justify-between">
      <span className="text-slate-500">{label}</span>
      <span className={tone === "bad" ? "text-rose-400" : tone === "ok" ? "text-emerald-400" : "text-slate-300"}>
        {value}
      </span>
    </div>
  );
}
