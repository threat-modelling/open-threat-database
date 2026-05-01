import { createServer, type ServerResponse } from 'node:http';
import { readFile, stat, watch } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from './build-site.ts';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const repoRoot = resolve(__dirname, '..');
const root = resolve(repoRoot, 'site');
const port = Number(process.env.PORT) || 8080;
const watchMode = process.argv.includes('--watch');

const RELOAD_SNIPPET =
  `<script>(()=>{const es=new EventSource('/__reload');` +
  `es.addEventListener('reload',()=>location.reload());` +
  `es.addEventListener('error',()=>{});})();</script>`;

const sseClients = new Set<ServerResponse>();

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

const server = createServer(async (req, res) => {
  if (watchMode && req.url === '/__reload') {
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    });
    res.write('retry: 1000\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const pathname = decodeURIComponent(url.pathname);

    let filePath = resolve(root, '.' + normalize(pathname));
    if (filePath !== root && !filePath.startsWith(root + sep)) {
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    const s = await stat(filePath).catch(() => null);
    if (s?.isDirectory()) filePath = join(filePath, 'index.html');

    const data = await readFile(filePath);
    const type = MIME[extname(filePath)] ?? 'application/octet-stream';

    if (watchMode && type.startsWith('text/html')) {
      const injected = data
        .toString('utf8')
        .replace('</body>', `${RELOAD_SNIPPET}</body>`);
      res.writeHead(200, { 'content-type': type });
      res.end(injected);
      return;
    }

    res.writeHead(200, { 'content-type': type });
    res.end(data);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT' || code === 'EISDIR' || code === 'ENOTDIR') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('Not found');
    } else {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end('Internal error');
    }
  }
});

server.listen(port, () => {
  const suffix = watchMode ? ' (watch mode — auto-reloads on source change)' : '';
  console.log(`Serving ${root} at http://localhost:${port}/${suffix}`);
});

if (watchMode) {
  let scheduled: NodeJS.Timeout | null = null;
  let building = false;

  function notifyReload() {
    for (const client of sseClients) {
      client.write('event: reload\ndata: 1\n\n');
    }
  }

  async function rebuild() {
    if (building) return;
    building = true;
    try {
      await build();
      notifyReload();
    } catch (err) {
      console.error('[watch] build failed:', err);
    } finally {
      building = false;
    }
  }

  function schedule() {
    if (scheduled) clearTimeout(scheduled);
    scheduled = setTimeout(() => {
      scheduled = null;
      void rebuild();
    }, 150);
  }

  const watchTargets = [
    resolve(repoRoot, 'src'),
    resolve(repoRoot, 'scripts/site'),
    resolve(repoRoot, 'scripts/build-site.ts'),
  ];

  for (const target of watchTargets) {
    (async () => {
      try {
        const watcher = watch(target, { recursive: true });
        for await (const _event of watcher) schedule();
      } catch (err) {
        console.error('[watch] error watching', target, err);
      }
    })();
  }

  console.log('[watch] watching src/, scripts/site/, scripts/build-site.ts');
  console.log('[watch] note: edits to scripts/build-site.ts itself require a server restart');
}
