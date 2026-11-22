import { API_URL } from "@/lib/api";

export function UseIt() {
  return (
    <section className="section" id="use" aria-labelledby="use-h">
      <div className="section-head">
        <h2 id="use-h" className="reveal">Use it from your own tools</h2>
        <p className="reveal">The page you are reading calls the same public API. Run it yourself offline, with no key, in one command.</p>
      </div>
      <div className="use-grid">
        <div className="use-card glass reveal">
          <h3>Call the API</h3>
          <p>Plain HTTPS. On the public demo it runs simulated models only and cannot change shared state.</p>
          <pre><code>{`curl -X POST ${API_URL}/analyze \\\n  -H 'content-type: application/json' \\\n  -d @alert.json`}</code></pre>
          <ul><li><a href={`${API_URL}/docs`} target="_blank" rel="noopener">Interactive API docs</a></li><li><a href={`${API_URL}/v2/benchmark`} target="_blank" rel="noopener">/v2/benchmark</a></li></ul>
        </div>
        <div className="use-card glass reveal">
          <h3>Run the image</h3>
          <p>The published container serves the full app on your machine, with the simulated model by default.</p>
          <pre><code>{`docker run --rm -p 127.0.0.1:8501:8501 \\\n  -v alertlens-data:/data \\\n  ghcr.io/lsudoko/alertlens:latest`}</code></pre>
        </div>
        <div className="use-card glass reveal">
          <h3>Build it from source</h3>
          <p>Every number on this page is rebuilt from the repository. Add a local model through Ollama if you like.</p>
          <pre><code>{`git clone https://github.com/LSUDOKO/AlertLens\ncd AlertLens && make setup && make demo`}</code></pre>
          <a className="btn glass small" href="https://github.com/LSUDOKO/AlertLens" target="_blank" rel="noopener">Open the repository</a>
        </div>
      </div>
    </section>
  );
}

const SOURCES: [string, string][] = [
  ["Synthetic alert generator", "seed 42, reserved IP ranges, made-up accounts"],
  ["deepset/prompt-injections", "Hugging Face dataset, classifier training only"],
  ["Published log-injection attacks", "LogJack, LogInject, Just Testing, Watchtower, Hiding: evaluation only"],
  ["MITRE ATT&CK", "technique names and descriptions, local subset"],
  ["llama3.2 via Ollama", "real-model runs on a laptop CPU"],
  ["Archive photographs", "ENIAC, Colossus, IBM 704: public domain, Wikimedia Commons"],
];
const LIMITS = [
  "All alerts are synthetic, so scores will not carry over to a real security team as they are.",
  "Detection still misses many reworded attacks. Other layers limit the damage; detection alone is not reliable.",
  "The real-model runs are small samples on one small model.",
  "Remediation is simulated. AlertLens never touches a real system.",
  "The API has no login. The public demo is locked to simulated models and read-mostly endpoints.",
];

export function Sources() {
  return (
    <section className="section" id="data" aria-labelledby="data-h">
      <div className="section-head"><h2 id="data-h" className="reveal">Data, sources and limits</h2></div>
      <div className="data-grid">
        <ul className="sources">{SOURCES.map(([b, s]) => <li key={b}><b>{b}</b><span>{s}</span></li>)}</ul>
        <div className="limits"><h3>Known limits</h3><ul>{LIMITS.map((l) => <li key={l}>{l}</li>)}</ul></div>
      </div>
    </section>
  );
}

export function Footer() {
  return (
    <footer className="foot">
      <div className="foot-band" aria-hidden="true">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/media/mark.svg" alt="" width={72} height={72} />
        <span className="chrome">alertlens</span>
      </div>
      <p>Built for Aegython 2026, challenge Explain My Security Alert. MIT licence.</p>
      <p>Archive photographs are public domain, from Wikimedia Commons, printed here in red. Design system adapted from Pharmakon.</p>
    </footer>
  );
}
