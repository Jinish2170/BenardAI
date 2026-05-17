import { useEffect, useState } from 'react';
import './App.css';

type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
type Classification = 'benign' | 'suspicious' | 'malicious' | 'inconclusive';
type Tab = 'verdict' | 'evidence' | 'mitre' | 'history';

interface Evidence {
  analyzer: string;
  field: string;
  value: unknown;
  severity: Severity;
  description: string;
  details?: Record<string, unknown> | null;
  source_url?: string | null;
  collected_at: string;
}

interface MitreTechnique {
  technique_id: string;
  name: string;
  rationale: string;
  cites: string[];
}

interface Verdict {
  classification: Classification;
  severity: Severity;
  confidence: 'low' | 'medium' | 'high';
  summary: string;
  key_indicators: string[];
  mitre_techniques: MitreTechnique[];
  recommended_actions: string[];
  abstention_reason?: string | null;
}

interface AnalysisRecord {
  id: string;
  input: { kind: string; value: string; filename?: string | null };
  evidence: Evidence[];
  verdict: Verdict;
  stats: Record<string, unknown>;
  created_at: string;
}

interface HistoryItem {
  id: string; kind: string; value: string;
  classification: string; severity: Severity;
  created_at: string; evidence_count: number;
}

function App() {
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<{phase: string; message: string}[]>([]);
  const [result, setResult] = useState<AnalysisRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('verdict');
  const [history, setHistory] = useState<HistoryItem[]>([]);

  const fetchHistory = async () => {
    try {
      const r = await fetch('/api/analyses?limit=50');
      if (!r.ok) return;
      const j = await r.json();
      setHistory(j.analyses || []);
    } catch { /* silent */ }
  };

  useEffect(() => {
    if (tab === 'history') fetchHistory();
  }, [tab]);

  const runAnalysis = async () => {
    if (!file && !text.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setProgress([]);
    setTab('verdict');

    const fd = new FormData();
    if (file) fd.append('file', file);
    if (text.trim()) fd.append('value', text.trim());

    try {
      const res = await fetch('/api/analyze/stream', { method: 'POST', body: fd });
      if (!res.body) throw new Error('No stream from server');
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const evt = JSON.parse(line);
            if (evt.event === 'progress') {
              setProgress((p) => [...p, evt.data]);
            } else if (evt.event === 'result') {
              setResult(evt.data);
            } else if (evt.event === 'error') {
              setError(evt.data?.message || 'Analysis failed');
            }
          } catch { /* skip malformed */ }
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadHistorical = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`/api/analysis/${encodeURIComponent(id)}`);
      if (!r.ok) throw new Error('Not found');
      setResult(await r.json());
      setTab('verdict');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const exportJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bernard-${result.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const renderCitations = (text: string) => {
    const parts = text.split(/(\[[a-z][a-z0-9_]*\.[a-z0-9_]+\])/g);
    return parts.map((part, i) => {
      const m = part.match(/^\[([a-z][a-z0-9_]*)\.([a-z0-9_]+)\]$/);
      if (!m) return <span key={i}>{part}</span>;
      return <span key={i} className="cite" title={`${m[1]}.${m[2]}`}>{m[1]}.{m[2]}</span>;
    });
  };

  return (
    <div className="app">
      <header className="header">
        <div className="logo">
          <span className="logo-icon">B</span>
          <h1>Bernard</h1>
        </div>
        <p className="tagline">Self-hosted AI threat triage — analyze files, URLs, IPs, domains, and hashes with cited verdicts</p>
      </header>

      <div className="controls">
        <div>
          <label>File upload</label>
          <input
            type="file"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
          <div className="divider" style={{ margin: '1.2rem 0 0.8rem' }}></div>
          <label>URL / IP / domain / hash</label>
          <input
            type="text"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !loading && runAnalysis()}
            placeholder="https://malicious.test/payload.exe  ·  8.8.8.8  ·  d41d8cd98f00b204e9800998ecf8427e"
            className="mono"
          />
        </div>
        <div className="right">
          <button onClick={runAnalysis} disabled={loading || (!file && !text.trim())} className="scan-btn">
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
          <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.3rem', lineHeight: 1.4 }}>
            Pipeline: static analysis → threat-intel enrichment → LLM verdict with MITRE mapping
          </p>
        </div>
      </div>

      {error && <div className="error">{error}</div>}

      {loading && progress.length > 0 && (
        <div className="progress">
          {progress.map((p, i) => (
            <div key={i} className="progress-line">
              <span className="phase">{p.phase}</span>
              {p.message}
            </div>
          ))}
        </div>
      )}

      <div className="tabs">
        <button className={tab === 'verdict' ? 'active' : ''} onClick={() => setTab('verdict')}>Verdict</button>
        <button className={tab === 'evidence' ? 'active' : ''} onClick={() => setTab('evidence')}>
          Evidence{result ? ` (${result.evidence.length})` : ''}
        </button>
        <button className={tab === 'mitre' ? 'active' : ''} onClick={() => setTab('mitre')}>
          MITRE{result ? ` (${result.verdict.mitre_techniques.length})` : ''}
        </button>
        <button className={tab === 'history' ? 'active' : ''} onClick={() => setTab('history')}>History</button>
        {result && <button onClick={exportJSON} className="export-btn">⬇ Export JSON</button>}
      </div>

      {tab === 'verdict' && (
        <div className="tab-content">
          {!result && !loading && (
            <p style={{ color: 'var(--text-secondary)' }}>
              Drop a file or paste a URL/IP/domain/hash above. Bernard runs deterministic
              static analysis + threat-intel enrichment first, then asks the LLM for a verdict
              grounded in that evidence.
            </p>
          )}
          {result && (
            <>
              <div className={`verdict-card ${result.verdict.classification}`}>
                <div className="verdict-class">{result.verdict.classification}</div>
                <div className="verdict-summary">{result.verdict.summary}</div>
                <div className="verdict-meta">
                  <span className={`verdict-pill sev-${result.verdict.severity}`}>
                    {result.verdict.severity}
                  </span>
                  <span className="verdict-pill">conf {result.verdict.confidence}</span>
                  <span className="verdict-pill mono" style={{ fontSize: '0.65rem' }}>
                    {(((result.stats?.duration_ms as number) ?? 0) / 1000).toFixed(1)}s
                  </span>
                </div>
              </div>

              {result.verdict.key_indicators.length > 0 && (
                <div className="section">
                  <h3>Key indicators</h3>
                  <ul className="bullets">
                    {result.verdict.key_indicators.map((ind, i) => (
                      <li key={i}>{renderCitations(ind)}</li>
                    ))}
                  </ul>
                </div>
              )}

              {result.verdict.recommended_actions.length > 0 && (
                <div className="section">
                  <h3>Recommended actions</h3>
                  <ul className="bullets">
                    {result.verdict.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
                  </ul>
                </div>
              )}

              {result.verdict.abstention_reason && (
                <div className="section">
                  <h3>Why Bernard abstained</h3>
                  <p style={{ color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                    {result.verdict.abstention_reason}
                  </p>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {tab === 'evidence' && (
        <div className="tab-content">
          {!result && <p style={{ color: 'var(--text-secondary)' }}>Run an analysis to see evidence.</p>}
          {result && (
            <div>
              {result.evidence.map((e, i) => (
                <div key={i} className="evidence-row">
                  <div className="analyzer">{e.analyzer}</div>
                  <div className="field">{e.field}</div>
                  <div>
                    <div className="value">{formatValue(e.value)}</div>
                    <div className="description">{e.description}</div>
                  </div>
                  <div className={`verdict-pill sev-${e.severity}`}>{e.severity}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {tab === 'mitre' && (
        <div className="tab-content">
          {!result && <p style={{ color: 'var(--text-secondary)' }}>Run an analysis to see MITRE mapping.</p>}
          {result && result.verdict.mitre_techniques.length === 0 && (
            <p style={{ color: 'var(--text-secondary)' }}>
              No MITRE ATT&amp;CK techniques mapped. Either the evidence didn't support any technique,
              or the MITRE catalog isn't loaded (run <code>python scripts/bootstrap_mitre.py</code>).
            </p>
          )}
          {result?.verdict.mitre_techniques.map((t, i) => (
            <div key={i} style={{ padding: '1rem 0', borderBottom: '1px solid var(--border)' }}>
              <div>
                <span className="mitre-chip"><strong>{t.technique_id}</strong> {t.name}</span>
              </div>
              <p style={{ marginTop: '0.5rem', color: 'var(--text-primary)' }}>{t.rationale}</p>
              <div style={{ marginTop: '0.4rem' }}>
                {t.cites.map((c, j) => <span key={j} className="cite">{c}</span>)}
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === 'history' && (
        <div className="tab-content">
          {history.length === 0 && (
            <p style={{ color: 'var(--text-secondary)' }}>No past analyses yet. Run one to start building history.</p>
          )}
          {history.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>Target</th><th>Kind</th><th>Verdict</th><th>Severity</th><th>Evidence</th><th>When</th><th></th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id}>
                    <td className="mono" style={{ wordBreak: 'break-all' }}>{h.value}</td>
                    <td>{h.kind}</td>
                    <td>
                      <span className={`verdict-pill ${h.classification === 'malicious' ? 'sev-critical'
                        : h.classification === 'suspicious' ? 'sev-medium'
                        : h.classification === 'benign' ? 'sev-info'
                        : 'sev-low'}`}>
                        {h.classification}
                      </span>
                    </td>
                    <td><span className={`verdict-pill sev-${h.severity}`}>{h.severity}</span></td>
                    <td>{h.evidence_count}</td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
                      {new Date(h.created_at).toLocaleString()}
                    </td>
                    <td><button className="link-btn" onClick={() => loadHistorical(h.id)}>Open</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'string') return v.length > 200 ? v.slice(0, 200) + '…' : v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  try {
    const s = JSON.stringify(v);
    return s.length > 200 ? s.slice(0, 200) + '…' : s;
  } catch {
    return String(v);
  }
}

export default App;
