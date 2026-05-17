import { useEffect, useMemo, useState } from 'react';
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
interface HealthInfo {
  model: string;
  llm_configured: boolean;
  vt_configured: boolean;
  abuseipdb_configured: boolean;
  abusech_configured: boolean;
  mitre_loaded: boolean;
  version: string;
}
interface TechniqueMeta {
  technique_id: string; name: string;
  description: string; tactics: string[];
  url?: string;
}

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// SVG icons (inline so we keep zero icon-lib weight)
const I = {
  upload: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  ),
  shield: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  check: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  ),
  warn: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  skull: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="10" r="8" />
      <line x1="9" y1="10" x2="9.01" y2="10" />
      <line x1="15" y1="10" x2="15.01" y2="10" />
      <path d="M8 17h8M10 21v-2M14 21v-2" />
    </svg>
  ),
  help: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  chevron: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  ),
  download: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="14" height="14">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  ),
  inbox: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 16 12 14 15 10 15 8 12 2 12" />
      <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
    </svg>
  ),
};

function badgeFor(c: Classification) {
  if (c === 'benign') return I.check;
  if (c === 'suspicious') return I.warn;
  if (c === 'malicious') return I.skull;
  return I.help;
}

function App() {
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<{ phase: string; message: string }[]>([]);
  const [result, setResult] = useState<AnalysisRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>('verdict');
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [expandedMitre, setExpandedMitre] = useState<string | null>(null);
  const [techCache, setTechCache] = useState<Record<string, TechniqueMeta>>({});

  useEffect(() => {
    fetch('/api/health')
      .then((r) => { if (r.ok) return r.json(); })
      .then((j) => { if (j) setHealth(j); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (tab === 'history') {
      fetch('/api/analyses?limit=50')
        .then(r => r.json())
        .then(j => setHistory(j.analyses || []))
        .catch(() => {});
    }
  }, [tab, result]);

  const fetchTechnique = async (id: string) => {
    if (techCache[id]) return;
    try {
      const r = await fetch(`/api/technique/${encodeURIComponent(id)}`);
      if (r.ok) {
        const meta = await r.json();
        setTechCache((c) => ({ ...c, [id]: meta }));
      }
    } catch { /* swallow */ }
  };

  const run = async () => {
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
            if (evt.event === 'progress') setProgress((p) => [...p, evt.data]);
            else if (evt.event === 'result') setResult(evt.data);
            else if (evt.event === 'error') setError(evt.data?.message || 'Analysis failed');
          } catch { /* skip */ }
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
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const renderCit = (s: string) => {
    const parts = s.split(/(\[[a-z][a-z0-9_]*\.[a-z0-9_]+\])/g);
    return parts.map((p, i) => {
      const m = p.match(/^\[([a-z][a-z0-9_]*)\.([a-z0-9_]+)\]$/);
      return m ? <span key={i} className="cite" title={`Cite: ${m[1]}.${m[2]}`}>{m[1]}.{m[2]}</span>
               : <span key={i}>{p}</span>;
    });
  };

  const evidenceGroups = useMemo(() => {
    if (!result) return [];
    const map = new Map<string, Evidence[]>();
    for (const e of result.evidence) {
      const arr = map.get(e.analyzer) || [];
      arr.push(e);
      map.set(e.analyzer, arr);
    }
    return Array.from(map.entries()).map(([analyzer, items]) => ({
      analyzer,
      items,
      maxSev: items.reduce((m, e) => SEV_RANK[e.severity] > SEV_RANK[m] ? e.severity : m, 'info' as Severity),
    })).sort((a, b) => SEV_RANK[b.maxSev] - SEV_RANK[a.maxSev]);
  }, [result]);

  const toggleGroup = (name: string) => {
    setCollapsedGroups((s) => {
      const n = new Set(s);
      n.has(name) ? n.delete(name) : n.add(name);
      return n;
    });
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) setFile(f);
  };

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand">
          <span className="brand-icon">B</span>
          <div className="brand-text">
            <div className="brand-name">Bernard</div>
            <div className="brand-sub">AI threat triage workstation</div>
          </div>
        </div>
        <div className="topbar-status">
          {health && (
            <>
              <span className="status-chip" title="LLM model">
                <span className={`status-dot ${health.llm_configured ? 'on' : 'off'}`}></span>
                {health.model.split('/').pop()}
              </span>
              <span className="status-chip" title="VirusTotal key">
                <span className={`status-dot ${health.vt_configured ? 'on' : 'off'}`}></span>
                VT
              </span>
              <span className="status-chip" title="AbuseIPDB key">
                <span className={`status-dot ${health.abuseipdb_configured ? 'on' : 'off'}`}></span>
                AbuseIPDB
              </span>
              <span className="status-chip" title="abuse.ch key (URLhaus/ThreatFox/MalwareBazaar)">
                <span className={`status-dot ${health.abusech_configured ? 'on' : 'off'}`}></span>
                abuse.ch
              </span>
              <span className="status-chip" title="MITRE ATT&CK catalog loaded">
                <span className={`status-dot ${health.mitre_loaded ? 'on' : 'off'}`}></span>
                MITRE
              </span>
            </>
          )}
        </div>
      </div>

      <div className="hero">
        <h1>Triage anything in one click.</h1>
        <p className="tagline">
          Drop a file or paste a URL / IP / domain / hash. Bernard runs deterministic
          static analysis + threat-intel enrichment, then asks the LLM for a verdict —
          with every claim cited to evidence.
        </p>
      </div>

      <div className="input-card">
        <label
          className={`drop-zone ${dragging ? 'dragging' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
        >
          <div className="drop-zone-icon">{I.upload}</div>
          <div className="drop-zone-label">
            {file ? 'Drop another file or click to replace' : 'Drop a file here, or click to choose'}
          </div>
          <div className="drop-zone-hint">PE · PDF · Office · scripts · any artifact</div>
          {file && <div className="drop-zone-file">📎 {file.name} · {(file.size / 1024).toFixed(1)} KB</div>}
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </label>

        <div className="row">
          <input
            type="text"
            className="text-input"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !loading && run()}
            placeholder='https://malicious.test/payload  ·  8.8.8.8  ·  evil.example.com  ·  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
          />
          <button className="scan-btn" onClick={run} disabled={loading || (!file && !text.trim())}>
            {loading ? <><span className="spinner"></span> Analyzing</> : <>{I.shield} Analyze</>}
          </button>
        </div>
      </div>

      {error && <div className="error">⚠ {error}</div>}

      {loading && progress.length > 0 && (
        <div className="progress slide-up">
          {progress.map((p, i) => (
            <div key={i} className={`progress-line ${i === progress.length - 1 ? 'active' : ''}`}>
              <span className="phase">{p.phase}</span>
              <span>{p.message}</span>
            </div>
          ))}
        </div>
      )}

      <div className="tabs">
        <button className={tab === 'verdict' ? 'active' : ''} onClick={() => setTab('verdict')}>
          Verdict
        </button>
        <button className={tab === 'evidence' ? 'active' : ''} onClick={() => setTab('evidence')}>
          Evidence {result && <span className="count">{result.evidence.length}</span>}
        </button>
        <button className={tab === 'mitre' ? 'active' : ''} onClick={() => setTab('mitre')}>
          MITRE {result && <span className="count">{result.verdict.mitre_techniques.length}</span>}
        </button>
        <button className={tab === 'history' ? 'active' : ''} onClick={() => setTab('history')}>
          History
        </button>
        <div className="spacer" />
        {result && <button onClick={exportJSON} className="export-btn">{I.download} Export JSON</button>}
      </div>

      {tab === 'verdict' && (
        <div className="tab-content">
          {!result && !loading && (
            <div className="empty-state">
              <div className="icon">{I.shield}</div>
              <h4>No analysis yet</h4>
              <p>Drop a file or paste an indicator above to get a cited verdict.</p>
            </div>
          )}
          {result && (
            <>
              <div className={`verdict-hero ${result.verdict.classification} fade-in`}>
                <div className="verdict-badge">
                  <span className="icon">{badgeFor(result.verdict.classification)}</span>
                  <span className="label">{result.verdict.classification}</span>
                </div>
                <div className="verdict-body">
                  <div className="verdict-classification">{result.verdict.classification}</div>
                  <p className="verdict-summary">{result.verdict.summary}</p>
                  <div className="verdict-meta">
                    <span className={`meta-pill sev-${result.verdict.severity}`}>
                      <span className="k">Sev</span> {result.verdict.severity}
                    </span>
                    <span className="meta-pill"><span className="k">Conf</span> {result.verdict.confidence}</span>
                    <span className="meta-pill">
                      <span className="k">Time</span>
                      {(((result.stats?.duration_ms as number) ?? 0) / 1000).toFixed(1)}s
                    </span>
                    <span className="meta-pill">
                      <span className="k">Model</span>
                      {(result.stats?.llm_model as string)?.split('/').pop() || 'n/a'}
                    </span>
                    <span className="meta-pill">
                      <span className="k">Evidence</span> {result.evidence.length}
                    </span>
                  </div>
                </div>
              </div>

              {result.verdict.key_indicators.length > 0 && (
                <div className="section">
                  <div className="section-head">
                    <h3>Key indicators</h3>
                    <span className="badge">{result.verdict.key_indicators.length}</span>
                  </div>
                  <ul className="bullets">
                    {result.verdict.key_indicators.map((ind, i) => (
                      <li key={i}>{renderCit(ind)}</li>
                    ))}
                  </ul>
                </div>
              )}

              {result.verdict.recommended_actions.length > 0 && (
                <div className="section">
                  <div className="section-head">
                    <h3>Recommended actions</h3>
                    <span className="badge">{result.verdict.recommended_actions.length}</span>
                  </div>
                  <ul className="bullets">
                    {result.verdict.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
                  </ul>
                </div>
              )}

              {result.verdict.abstention_reason && (
                <div className="section">
                  <div className="section-head"><h3>Why Bernard abstained</h3></div>
                  <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0, fontSize: '0.9rem' }}>
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
          {!result && <EmptyState icon={I.inbox} title="No analysis yet" body="Run a scan to see the full evidence audit." />}
          {result && evidenceGroups.map((g) => {
            const collapsed = collapsedGroups.has(g.analyzer);
            return (
              <div key={g.analyzer} className={`evidence-group ${collapsed ? 'collapsed' : ''}`}>
                <div className="evidence-group-head" onClick={() => toggleGroup(g.analyzer)}>
                  <span className="chevron">{I.chevron}</span>
                  <span className="name">{g.analyzer}</span>
                  <span className="count">{g.items.length}</span>
                  <span className={`max-sev sev-${g.maxSev}`}>{g.maxSev}</span>
                </div>
                <div className="evidence-body">
                  {g.items.map((e, i) => (
                    <div key={i} className="evidence-row">
                      <div className="field">{e.field}</div>
                      <div>
                        <div className="value">{formatValue(e.value)}</div>
                        {e.description && <div className="desc">{e.description}</div>}
                        {e.source_url && (
                          <a className="intel-link" href={e.source_url} target="_blank" rel="noreferrer">
                            ↗ view source
                          </a>
                        )}
                      </div>
                      <div className={`sev sev-${e.severity}`}>{e.severity}</div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {tab === 'mitre' && (
        <div className="tab-content">
          {!result && <EmptyState icon={I.shield} title="No analysis yet" body="MITRE ATT&CK techniques will show up here after a scan." />}
          {result && result.verdict.mitre_techniques.length === 0 && (
            <EmptyState
              icon={I.help}
              title="No techniques mapped"
              body={
                health?.mitre_loaded
                  ? 'The evidence collected did not justify any MITRE ATT&CK technique. This is expected for benign or inconclusive verdicts.'
                  : 'MITRE catalog not loaded. Run `python scripts/bootstrap_mitre.py` to enable technique mapping.'
              }
            />
          )}
          {result?.verdict.mitre_techniques.length ? (
            <>
              <div className="mitre-list">
                {result.verdict.mitre_techniques.map((t) => (
                  <button
                    key={t.technique_id}
                    className="mitre-chip"
                    onClick={() => { setExpandedMitre(expandedMitre === t.technique_id ? null : t.technique_id); fetchTechnique(t.technique_id); }}
                    title={t.name}
                  >
                    <strong>{t.technique_id}</strong> · {t.name}
                  </button>
                ))}
              </div>
              {result.verdict.mitre_techniques
                .filter((t) => expandedMitre === t.technique_id)
                .map((t) => {
                  const meta = techCache[t.technique_id];
                  return (
                    <div key={t.technique_id} className="mitre-card">
                      <div className="mitre-card-head">
                        <span className="mitre-id">{t.technique_id}</span>
                        <span className="mitre-name">{t.name}</span>
                        {meta?.tactics?.length ? (
                          <span className="mitre-tactic">{meta.tactics.join(' · ')}</span>
                        ) : null}
                      </div>
                      <div className="mitre-rationale">{t.rationale}</div>
                      {meta?.description && (
                        <div className="mitre-description">{meta.description}</div>
                      )}
                      <div className="mitre-cites">
                        {t.cites.map((c, j) => <span key={j} className="cite">{c}</span>)}
                      </div>
                      {meta?.url && (
                        <a className="intel-link" href={meta.url} target="_blank" rel="noreferrer">
                          ↗ View on attack.mitre.org
                        </a>
                      )}
                    </div>
                  );
                })}
            </>
          ) : null}
        </div>
      )}

      {tab === 'history' && (
        <div className="tab-content">
          {history.length === 0 ? (
            <EmptyState icon={I.inbox} title="No past analyses yet" body="Run a scan to start building history." />
          ) : (
            <table className="history-table">
              <thead>
                <tr>
                  <th>Target</th><th>Kind</th><th>Verdict</th><th>Severity</th><th>Evidence</th><th>When</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} onClick={() => loadHistorical(h.id)}>
                    <td className="mono" style={{ wordBreak: 'break-all', maxWidth: '280px' }}>{h.value}</td>
                    <td><span className="kind-chip">{h.kind}</span></td>
                    <td>
                      <span className={`sev ${h.classification === 'malicious' ? 'sev-critical'
                          : h.classification === 'suspicious' ? 'sev-medium'
                          : h.classification === 'benign' ? 'sev-info'
                          : 'sev-low'}`}>{h.classification}</span>
                    </td>
                    <td><span className={`sev sev-${h.severity}`}>{h.severity}</span></td>
                    <td className="dim">{h.evidence_count}</td>
                    <td className="dim" style={{ fontSize: '0.78rem' }}>
                      {new Date(h.created_at).toLocaleString()}
                    </td>
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

function EmptyState({ icon, title, body }: { icon: React.ReactNode; title: string; body: string }) {
  return (
    <div className="empty-state">
      <div className="icon">{icon}</div>
      <h4>{title}</h4>
      <p>{body}</p>
    </div>
  );
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'string') return v.length > 240 ? v.slice(0, 240) + '…' : v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  try {
    const s = JSON.stringify(v, null, 0);
    return s.length > 240 ? s.slice(0, 240) + '…' : s;
  } catch {
    return String(v);
  }
}

export default App;
