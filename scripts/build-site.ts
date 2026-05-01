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
    <span class="severity sev-${escape(threat.severity)}">${escape(threat.severity)}</span>
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
