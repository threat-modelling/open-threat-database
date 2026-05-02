import { mkdir, readFile, writeFile, copyFile, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');
const outDir = join(repoRoot, 'site');

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

interface Control {
  id: string;
  description: string;
  aliases?: string[];
}

interface Threat {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  stride: string[];
  mitreTechniques: MitreTechnique[];
  cwes?: string[];
  controls: Control[];
  references?: string[];
  aliases?: string[];
}

const STRIDE_LABELS: Record<string, string> = {
  spoofing: 'Spoofing',
  tampering: 'Tampering',
  repudiation: 'Repudiation',
  'information-disclosure': 'Information Disclosure',
  'denial-of-service': 'Denial of Service',
  'elevation-of-privilege': 'Elevation of Privilege',
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function escape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function mitreUrl(id: string): string {
  const [base, sub] = id.split('.');
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`;
}

function cweUrl(cwe: string): string {
  const num = cwe.replace(/^CWE-/, '');
  return `https://cwe.mitre.org/data/definitions/${num}.html`;
}

function layout(opts: { title: string; relRoot: string; body: string }): string {
  const { title, relRoot, body } = opts;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(title)}</title>
<link rel="stylesheet" href="${relRoot}styles.css">
</head>
<body>
<header class="site-header">
  <a href="${relRoot}" class="site-title">Open Threat Database</a>
  <nav>
    <a href="${relRoot}severity/">Severity</a>
    <a href="${relRoot}schema/">Schema</a>
    <a href="https://github.com/threat-modelling/open-threat-database" rel="noopener">GitHub</a>
  </nav>
</header>
<main>
${body}
</main>
<footer class="site-footer">
  <p>Generated from <a href="https://github.com/threat-modelling/open-threat-database" rel="noopener">threat-modelling/open-threat-database</a>. Released under the MIT License.</p>
</footer>
</body>
</html>
`;
}

function indexBody(threats: Threat[]): string {
  const sorted = [...threats].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.name.localeCompare(b.name),
  );

  const strideOpts = Object.entries(STRIDE_LABELS)
    .map(
      ([k, v]) =>
        `<label><input type="checkbox" data-filter="stride" value="${k}"> ${escape(v)}</label>`,
    )
    .join('');

  const sevOpts = (['critical', 'high', 'medium', 'low'] as const)
    .map(
      (s) =>
        `<label><input type="checkbox" data-filter="severity" value="${s}"> ${escape(s[0].toUpperCase() + s.slice(1))}</label>`,
    )
    .join('');

  const cards = sorted
    .map((t) => {
      return `<a class="threat-card" href="threats/${escape(t.id)}/" data-stride="${escape(t.stride.join(' '))}" data-severity="${escape(t.severity)}">
  <div class="card-head">
    <h3>${escape(t.name)}</h3>
    <span class="severity sev-${escape(t.severity)}">${escape(t.severity)}</span>
  </div>
  <p>${escape(t.description)}</p>
  <div class="chips">
    ${t.stride.map((s) => `<span class="chip">${escape(STRIDE_LABELS[s] ?? s)}</span>`).join('')}
  </div>
</a>`;
    })
    .join('\n');

  return `<section class="intro">
  <h1>Threat Catalogue</h1>
</section>
<section class="filters" id="filters">
  <fieldset>
    <legend>STRIDE</legend>
    ${strideOpts}
  </fieldset>
  <fieldset>
    <legend>Severity</legend>
    ${sevOpts}
  </fieldset>
  <button type="button" id="reset-filters">Clear filters</button>
</section>
<section class="grid" id="threat-grid">
${cards}
</section>
<p class="empty-state" id="empty-state" hidden>No threats match the current filters.</p>
<script src="filters.js" defer></script>
`;
}

function detailBody(threat: Threat): string {
  const strideHtml = threat.stride
    .map((s) => `<span class="chip">${escape(STRIDE_LABELS[s] ?? s)}</span>`)
    .join('');

  const mitreHtml = threat.mitreTechniques.length
    ? `<table class="kv">
  <thead><tr><th>ID</th><th>Name</th><th>Tactic</th></tr></thead>
  <tbody>
    ${threat.mitreTechniques
      .map(
        (m) => `<tr>
      <td><a href="${mitreUrl(m.id)}" rel="noopener">${escape(m.id)}</a></td>
      <td>${escape(m.name)}</td>
      <td>${escape(m.tactic)}</td>
    </tr>`,
      )
      .join('')}
  </tbody>
</table>`
    : '<p class="empty">None mapped.</p>';

  const cwesHtml = threat.cwes?.length
    ? `<ul class="inline-list">${threat.cwes
        .map((c) => `<li><a href="${cweUrl(c)}" rel="noopener">${escape(c)}</a></li>`)
        .join('')}</ul>`
    : '<p class="empty">None mapped.</p>';

  const controlsHtml = `<dl class="controls">
  ${threat.controls
    .map((c) => `<dt><code>${escape(c.id)}</code></dt><dd>${escape(c.description)}</dd>`)
    .join('')}
</dl>`;

  const refsHtml = threat.references?.length
    ? `<ul class="refs">${threat.references
        .map((r) => `<li><a href="${escape(r)}" rel="noopener">${escape(r)}</a></li>`)
        .join('')}</ul>`
    : '<p class="empty">No references provided.</p>';

  const aliasesHtml = threat.aliases?.length
    ? `<p class="aliases">Also known as: ${threat.aliases.map((a) => `<code>${escape(a)}</code>`).join(', ')}</p>`
    : '';

  return `<article class="detail">
  <p class="breadcrumb"><a href="../../">All threats</a></p>
  <header class="detail-head">
    <h1>${escape(threat.name)}</h1>
    <a class="severity sev-${escape(threat.severity)}" href="../../severity/#${escape(threat.severity)}" title="What does ${escape(threat.severity)} mean?">${escape(threat.severity)}</a>
  </header>
  <p class="threat-id"><code>${escape(threat.id)}</code></p>
  ${aliasesHtml}
  <p class="lede">${escape(threat.description)}</p>
  <div class="chips">${strideHtml}</div>

  <h2>MITRE ATT&amp;CK techniques</h2>
  ${mitreHtml}

  <h2>Common Weakness Enumeration</h2>
  ${cwesHtml}

  <h2>Mitigating controls</h2>
  ${controlsHtml}

  <h2>References</h2>
  ${refsHtml}
</article>
`;
}

function aliasRedirect(canonicalId: string): string {
  const target = `../${canonicalId}/`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Redirecting…</title>
<meta http-equiv="refresh" content="0; url=${target}">
<link rel="canonical" href="${target}">
</head>
<body>
<p>This threat has been renamed. Redirecting to <a href="${target}">${escape(canonicalId)}</a>.</p>
</body>
</html>
`;
}

function severityBody(): string {
  return `<article class="detail">
  <p class="breadcrumb"><a href="../">All threats</a></p>
  <h1>Severity rubric</h1>
  <p class="lede">Severity ranks the <strong>intrinsic impact</strong> of a threat being realised without compensating controls. Likelihood is deliberately not weighted — it depends on the consuming environment. The four levels are anchored to <a href="https://www.first.org/cvss/v3-1/specification-document" rel="noopener">CVSS v3.1</a> qualitative bands so a rating can be sanity-checked against a known industry standard.</p>
  <p>When more than one tier could fit, <strong>pick the highest</strong> that applies.</p>

  <section class="severity-tier" id="critical">
    <header class="detail-head">
      <h2>Critical</h2>
    </header>
    <p>Any of:</p>
    <ul>
      <li>Direct, persistent privileged execution on a host or control plane: root, SYSTEM, container host, cluster admin, cloud account or organisation admin, KMS key holder.</li>
      <li>Disclosure of "kingdom keys" — long-lived credentials, tokens, certificates, or secrets that <em>themselves</em> grant the privileged tier above (cluster certificates, etcd snapshots, root API keys, broad service-account keys).</li>
      <li>Wholesale loss of integrity or availability of tenant data: mass deletion, ransom encryption, control-plane wipe, destruction of backups.</li>
    </ul>
    <p class="cvss-band"><strong>CVSS-equivalent:</strong> typically C:H/I:H/A:H, often scope-changed; CVSS &ge; 9.0.</p>
  </section>

  <section class="severity-tier" id="high">
    <header class="detail-head">
      <h2>High</h2>
    </header>
    <p>Any of:</p>
    <ul>
      <li>Initial code execution or full compromise of a single workload, service, or account at non-privileged level, with realistic abuse paths to escalate.</li>
      <li>Theft of credentials, tokens, or session material that grants access to other systems but <strong>not</strong> directly to the privileged tier above.</li>
      <li>Authentication or authorisation bypass that exposes substantial protected data or functionality.</li>
      <li>Lateral pivot capability that enables — but does not by itself constitute — a privileged compromise.</li>
    </ul>
    <p class="cvss-band"><strong>CVSS-equivalent:</strong> typically two of C/I/A at High, scope unchanged; CVSS 7.0&ndash;8.9.</p>
  </section>

  <section class="severity-tier" id="medium">
    <header class="detail-head">
      <h2>Medium</h2>
    </header>
    <p>Any of:</p>
    <ul>
      <li>Unauthorised read or modification of protected application data without obtaining execution or credentials.</li>
      <li>Design or configuration weakness that <strong>expands the blast radius</strong> of other threats but is not by itself directly exploitable for access (excessive permissions, weak segmentation, unpatched non-critical CVEs).</li>
      <li>Tampering with messages, events, or workflows in transit or at processing time, without persistent access.</li>
    </ul>
    <p class="cvss-band"><strong>CVSS-equivalent:</strong> one of C/I/A at High, or two at Low; CVSS 4.0&ndash;6.9.</p>
  </section>

  <section class="severity-tier" id="low">
    <header class="detail-head">
      <h2>Low</h2>
    </header>
    <p>Any of:</p>
    <ul>
      <li>Repudiation: ability to deny or obscure an authorised action without altering data integrity (e.g. logging bypass with no further chained effect).</li>
      <li>Low-impact information disclosure: internal hostnames, version banners, fingerprintable error messages.</li>
      <li>Volumetric availability impact only — service is degraded but no confidentiality or integrity loss.</li>
    </ul>
    <p class="cvss-band"><strong>CVSS-equivalent:</strong> CVSS 0.1&ndash;3.9.</p>
  </section>

  <h2>Tie-breakers and anti-patterns</h2>
  <ul>
    <li><strong>Credential disclosure tiers on what the credential unlocks.</strong> An AWS root key is Critical. A single user's app password is High. A read-only API token to non-sensitive endpoints is Medium.</li>
    <li><strong>Don't escalate by reputation.</strong> "Ransomware" sounds scary, but the rating still has to come from the rubric (in its case: wholesale data integrity and availability loss &rarr; Critical).</li>
    <li><strong>Severity is per threat <em>class</em>, not per worst-known instance.</strong> <code>unpatched-vulnerabilities</code> is rated on the category's typical blast radius, not the worst CVE that ever shipped under that label.</li>
    <li><strong>Don't weight likelihood, exploitability, or detection difficulty.</strong> Those are environmental — the catalogue ranks impact only.</li>
  </ul>
</article>
`;
}

function schemaBody(schemaText: string): string {
  return `<article class="detail">
  <p class="breadcrumb"><a href="../">All threats</a></p>
  <h1>Schema</h1>
  <p>JSON Schema describing the structure of <code>threats.json</code>. The published package also exports this at <code>open-threat-database/schema.json</code>.</p>
  <pre class="code"><code>${escape(schemaText)}</code></pre>
</article>
`;
}

export async function build(): Promise<void> {
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });

  const threatsRaw = await readFile(join(repoRoot, 'src/threats.json'), 'utf8');
  const { threats }: { threats: Threat[] } = JSON.parse(threatsRaw);

  const schemaRaw = await readFile(join(repoRoot, 'src/schema.json'), 'utf8');
  const schemaPretty = JSON.stringify(JSON.parse(schemaRaw), null, 2);

  await writeFile(
    join(outDir, 'index.html'),
    layout({
      title: 'Open Threat Database',
      relRoot: './',
      body: indexBody(threats),
    }),
  );

  await mkdir(join(outDir, 'threats'), { recursive: true });
  for (const t of threats) {
    const dir = join(outDir, 'threats', t.id);
    await mkdir(dir, { recursive: true });
    await writeFile(
      join(dir, 'index.html'),
      layout({
        title: `${t.name} — Open Threat Database`,
        relRoot: '../../',
        body: detailBody(t),
      }),
    );
    if (t.aliases?.length) {
      for (const alias of t.aliases) {
        const aliasDir = join(outDir, 'threats', alias);
        await mkdir(aliasDir, { recursive: true });
        await writeFile(join(aliasDir, 'index.html'), aliasRedirect(t.id));
      }
    }
  }

  await mkdir(join(outDir, 'severity'), { recursive: true });
  await writeFile(
    join(outDir, 'severity/index.html'),
    layout({
      title: 'Severity rubric — Open Threat Database',
      relRoot: '../',
      body: severityBody(),
    }),
  );

  await mkdir(join(outDir, 'schema'), { recursive: true });
  await writeFile(
    join(outDir, 'schema/index.html'),
    layout({
      title: 'Schema — Open Threat Database',
      relRoot: '../',
      body: schemaBody(schemaPretty),
    }),
  );

  await copyFile(join(__dirname, 'site/styles.css'), join(outDir, 'styles.css'));
  await copyFile(join(__dirname, 'site/filters.js'), join(outDir, 'filters.js'));

  console.log(`Built ${threats.length} threat pages → ${outDir}`);
}

const isMain = import.meta.url === pathToFileURL(process.argv[1] ?? '').href;
if (isMain) {
  build().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
