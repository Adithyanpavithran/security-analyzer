import { useState } from "react";
import "./App.css";

type Finding = {
  check?: string;
  header?: string;
  cookie?: string;
  status: string;
  severity: string;
  message: string;
  recommendation?: string;
};

type ScanResult = {
  target: string;
  hostname?: string;
  final_url?: string;
  status_code?: number;
  https?: boolean;
  reachable: boolean;
  security_headers?: Record<string, {
    present: boolean;
    value: string | null;
    description: string;
  }>;
  cookies?: Array<{
    name: string;
    secure: boolean;
    httponly: boolean;
    samesite: boolean;
  }>;
  tls?: {
    tls_version: string;
    cipher: string;
    expires: string | null;
    days_remaining: number | null;
    valid: boolean;
  } | null;
  dns?: {
    records: Record<string, string[]>;
    spf: { present: boolean };
    dmarc: { present: boolean };
  };
  cors?: {
    allow_origin: string | null;
    allow_credentials: string | null;
    allow_methods: string | null;
    allow_headers: string | null;
  };
  findings?: Finding[];
  error?: string;
};

function App() {
  const [url, setUrl] = useState("https://example.com");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function scanWebsite() {
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch("/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Scan failed");
      }

      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to scan website");
    } finally {
      setLoading(false);
    }
  }

  const findings = result?.findings || [];

  const highCount = findings.filter(
    (item) => item.severity === "high"
  ).length;

  const mediumCount = findings.filter(
    (item) => item.severity === "medium"
  ).length;

  const lowCount = findings.filter(
    (item) => item.severity === "low"
  ).length;

  const passCount = findings.filter(
    (item) => item.status === "PASS"
  ).length;

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <div className="brand">11N11</div>
          <div className="brand-subtitle">SECURITY ANALYZER</div>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          Scanner Online
        </div>
      </header>

      <main className="container">
        <section className="hero">
          <p className="eyebrow">WEBSITE SECURITY ANALYSIS</p>

          <h1>
            Analyze your website's
            <br />
            security posture.
          </h1>

          <p className="hero-text">
            Check HTTPS, security headers, cookies, TLS, DNS and CORS
            configuration from one dashboard.
          </p>

          <div className="scan-box">
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  scanWebsite();
                }
              }}
            />

            <button onClick={scanWebsite} disabled={loading || !url}>
              {loading ? "SCANNING..." : "SCAN WEBSITE"}
            </button>
          </div>

          {error && <div className="error-box">{error}</div>}
        </section>

        {result && result.reachable && (
          <>
            <section className="target-card">
              <div>
                <span className="label">TARGET</span>
                <strong>{result.hostname}</strong>
              </div>

              <div>
                <span className="label">STATUS</span>
                <strong className="success">
                  {result.status_code}
                </strong>
              </div>

              <div>
                <span className="label">HTTPS</span>
                <strong className={result.https ? "success" : "danger"}>
                  {result.https ? "SECURE" : "NOT HTTPS"}
                </strong>
              </div>
            </section>

            <section className="stats">
              <div className="stat-card">
                <span>PASS</span>
                <strong>{passCount}</strong>
              </div>

              <div className="stat-card">
                <span>HIGH</span>
                <strong>{highCount}</strong>
              </div>

              <div className="stat-card">
                <span>MEDIUM</span>
                <strong>{mediumCount}</strong>
              </div>

              <div className="stat-card">
                <span>LOW</span>
                <strong>{lowCount}</strong>
              </div>
            </section>

            <section className="grid">
              <div className="panel">
                <div className="panel-header">
                  <h2>Security Headers</h2>
                </div>

                <div className="check-list">
                  {result.security_headers &&
                    Object.entries(result.security_headers).map(
                      ([name, data]) => (
                        <div className="check-row" key={name}>
                          <div>
                            <strong>{name}</strong>
                            <small>{data.description}</small>
                          </div>

                          <span
                            className={
                              data.present
                                ? "badge pass"
                                : "badge warning"
                            }
                          >
                            {data.present ? "PASS" : "MISSING"}
                          </span>
                        </div>
                      )
                    )}
                </div>
              </div>

              <div className="panel">
                <div className="panel-header">
                  <h2>TLS Security</h2>
                </div>

                {result.tls ? (
                  <div className="tls-info">
                    <div>
                      <span>TLS Version</span>
                      <strong>{result.tls.tls_version}</strong>
                    </div>

                    <div>
                      <span>Cipher</span>
                      <strong>{result.tls.cipher}</strong>
                    </div>

                    <div>
                      <span>Days Remaining</span>
                      <strong>{result.tls.days_remaining}</strong>
                    </div>

                    <div>
                      <span>Certificate</span>
                      <strong className={result.tls.valid ? "success" : "danger"}>
                        {result.tls.valid ? "VALID" : "EXPIRED"}
                      </strong>
                    </div>
                  </div>
                ) : (
                  <div className="empty">
                    TLS information is not available.
                  </div>
                )}
              </div>

              <div className="panel">
                <div className="panel-header">
                  <h2>DNS Security</h2>
                </div>

                <div className="dns-grid">
                  <div>
                    <span>SPF</span>
                    <strong>
                      {result.dns?.spf.present ? "DETECTED" : "NOT DETECTED"}
                    </strong>
                  </div>

                  <div>
                    <span>DMARC</span>
                    <strong>
                      {result.dns?.dmarc.present
                        ? "DETECTED"
                        : "NOT DETECTED"}
                    </strong>
                  </div>

                  <div>
                    <span>A Records</span>
                    <strong>
                      {result.dns?.records.A?.length || 0}
                    </strong>
                  </div>

                  <div>
                    <span>MX Records</span>
                    <strong>
                      {result.dns?.records.MX?.length || 0}
                    </strong>
                  </div>
                </div>
              </div>

              <div className="panel">
                <div className="panel-header">
                  <h2>CORS</h2>
                </div>

                <div className="cors-info">
                  <span>Allowed Origin</span>
                  <strong>
                    {result.cors?.allow_origin || "Not configured"}
                  </strong>

                  <span>Credentials</span>
                  <strong>
                    {result.cors?.allow_credentials || "Not configured"}
                  </strong>
                </div>
              </div>
            </section>

            <section className="panel findings-panel">
              <div className="panel-header">
                <h2>Security Findings</h2>
                <span>{findings.length} checks</span>
              </div>

              {findings.length === 0 ? (
                <div className="empty">No findings returned.</div>
              ) : (
                <div className="findings">
                  {findings.map((finding, index) => (
                    <div className="finding" key={index}>
                      <div className="finding-main">
                        <div className="finding-title">
                          {finding.check ||
                            finding.header ||
                            finding.cookie ||
                            "Security Check"}
                        </div>

                        <p>{finding.message}</p>

                        {finding.recommendation && (
                          <small>
                            Recommendation: {finding.recommendation}
                          </small>
                        )}
                      </div>

                      <div className="finding-status">
                        <span
                          className={`badge ${finding.severity}`}
                        >
                          {finding.severity.toUpperCase()}
                        </span>

                        <span className="finding-result">
                          {finding.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </>
        )}

        {result && !result.reachable && (
          <div className="error-box">
            Website could not be reached.
            {result.error && <div>{result.error}</div>}
          </div>
        )}
      </main>

      <footer>
        11N11 Security Analyzer · Passive website security analysis
      </footer>
    </div>
  );
}

export default App;
