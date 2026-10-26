import { useState } from "react";
import { Binary } from "lucide-react";
import { coreClient, DecompressionStep } from "../lib/coreClient";

const METHODS = [
  { value: "base64", label: "Base64 decode" },
  { value: "base64url", label: "Base64URL decode" },
  { value: "gzip", label: "gzip decompress" },
  { value: "deflate", label: "deflate decompress" },
  { value: "zlib", label: "zlib decompress" },
  { value: "brotli", label: "brotli decompress" },
  { value: "zstd", label: "zstd decompress" },
  { value: "urldecode", label: "URL decode" },
  { value: "hexdecode", label: "Hex decode" },
  { value: "json-pretty", label: "JSON pretty-print" },
  { value: "json-minify", label: "JSON minify" },
];

export default function DecompressionInspector() {
  const [input, setInput] = useState("");
  const [chain, setChain] = useState<string[]>([]);
  const [results, setResults] = useState<DecompressionStep[]>([]);
  const [detected, setDetected] = useState<string[]>([]);
  const [running, setRunning] = useState(false);

  async function handleDetect() {
    if (!input.trim()) return;
    const res = await coreClient.decompressionDetect(input);
    setDetected(res.detected);
  }

  function addStep(method: string) {
    setChain((c) => [...c, method]);
  }

  function removeStep(i: number) {
    setChain((c) => c.filter((_, idx) => idx !== i));
  }

  async function handleRun() {
    if (!input.trim() || chain.length === 0) return;
    setRunning(true);
    try {
      const res = await coreClient.decompressionChain(chain, input);
      setResults(res);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center gap-2 mb-1">
        <Binary size={18} className="text-indigo-400" />
        <h1 className="text-lg font-semibold">Decompression Inspector</h1>
      </div>
      <p className="text-sm text-slate-500 mb-6">
        Decode and decompress encoded values. Chain steps, e.g. Base64 → gzip → JSON. Nothing here is ever executed.
      </p>

      <textarea
        className="w-full bg-slate-900 border border-slate-800 rounded-md px-3 py-2 text-xs font-mono outline-none focus:border-indigo-500 h-28"
        placeholder="Paste a value: H4sIAAAAAAAA... / eyJmb28i... / %7B%22a%22...7D"
        value={input}
        onChange={(e) => setInput(e.target.value)}
      />

      <div className="flex items-center gap-2 mt-3">
        <button
          onClick={handleDetect}
          className="text-xs border border-slate-700 hover:border-slate-500 rounded-md px-3 py-1.5 text-slate-300"
        >
          Auto-detect
        </button>
        {detected.length > 0 && (
          <span className="text-xs text-slate-500">
            Likely: {detected.join(", ")}
          </span>
        )}
      </div>

      <div className="mt-5">
        <div className="text-xs text-slate-400 mb-2">Add a step:</div>
        <div className="flex flex-wrap gap-2">
          {METHODS.map((m) => (
            <button
              key={m.value}
              onClick={() => addStep(m.value)}
              className="text-xs border border-slate-700 hover:border-indigo-500 hover:text-indigo-300 rounded-md px-2.5 py-1 text-slate-400"
            >
              + {m.label}
            </button>
          ))}
        </div>
      </div>

      {chain.length > 0 && (
        <div className="mt-4 flex items-center gap-2 flex-wrap">
          {chain.map((step, i) => (
            <div key={i} className="flex items-center gap-1">
              {i > 0 && <span className="text-slate-600">→</span>}
              <span className="text-xs bg-slate-800 rounded-md px-2 py-1 flex items-center gap-2">
                {step}
                <button onClick={() => removeStep(i)} className="text-slate-500 hover:text-rose-400">
                  ×
                </button>
              </span>
            </div>
          ))}
        </div>
      )}

      <button
        onClick={handleRun}
        disabled={running || chain.length === 0 || !input.trim()}
        className="mt-4 bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 text-white text-sm font-medium px-3 py-1.5 rounded-md"
      >
        {running ? "Running..." : "Run chain"}
      </button>

      {results.length > 0 && (
        <div className="mt-6 space-y-3">
          {results.map((r, i) => (
            <div key={i} className="border border-slate-800 rounded-lg p-3 bg-slate-900/40">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-indigo-300">
                  Step {i + 1}: {r.method}
                </span>
                <span className="text-[11px] text-slate-500">
                  {r.inputSize}B → {r.outputSize}B
                </span>
              </div>
              {r.error ? (
                <div className="text-xs text-rose-400">{r.error}</div>
              ) : (
                <pre className="text-xs font-mono whitespace-pre-wrap break-all text-slate-300">
                  {r.outputPreview}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
