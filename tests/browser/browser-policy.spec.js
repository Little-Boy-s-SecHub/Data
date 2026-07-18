const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const ROOT = path.resolve(__dirname, '..', '..');

function lessonPayload(relativePath, payloadId, language) {
  const lesson = fs.readFileSync(path.join(ROOT, relativePath), 'utf8');
  const escapedId = payloadId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(
    '<!-- payload-id: ' + escapedId + ' -->[\\s\\S]*?```' + language
      + '\\n([\\s\\S]*?)\\n\\s*```',
  );
  const match = lesson.match(pattern);
  if (!match) {
    throw new Error(`Payload not found: ${payloadId}`);
  }
  return match[1];
}

function listen(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        server,
        origin: `http://127.0.0.1:${port}`,
      });
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

test('a CORS-safelisted text/plain POST is sent without preflight', async ({ page }) => {
  const observed = { options: 0, posts: 0 };
  const victim = await listen((request, response) => {
    if (request.method === 'OPTIONS') {
      observed.options += 1;
      response.writeHead(403).end();
      return;
    }
    if (request.method === 'POST') {
      observed.posts += 1;
      request.resume();
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end('{"changed":true}');
      return;
    }
    response.writeHead(404).end();
  });
  const attacker = await listen((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    response.end('<!doctype html><title>local browser fixture</title>');
  });

  try {
    await page.goto(attacker.origin);
    const result = await page.evaluate(async (url) => {
      try {
        await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: '{"fixture":"synthetic"}',
        });
        return 'response-readable';
      } catch (_error) {
        return 'response-blocked-by-cors';
      }
    }, `${victim.origin}/change`);

    expect(result).toBe('response-blocked-by-cors');
    expect(observed.options).toBe(0);
    expect(observed.posts).toBe(1);
  } finally {
    await close(attacker.server);
    await close(victim.server);
  }
});

test('a non-safelisted JSON request is preflighted and the POST is withheld', async ({ page }) => {
  const observed = { options: 0, posts: 0 };
  const victim = await listen((request, response) => {
    if (request.method === 'OPTIONS') {
      observed.options += 1;
      response.writeHead(403).end();
      return;
    }
    if (request.method === 'POST') {
      observed.posts += 1;
    }
    request.resume();
    response.writeHead(200).end();
  });
  const attacker = await listen((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    response.end('<!doctype html><title>local browser fixture</title>');
  });

  try {
    await page.goto(attacker.origin);
    const result = await page.evaluate(async (url) => {
      try {
        await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'fixture' },
          body: '{"fixture":"synthetic"}',
        });
        return 'unexpected-success';
      } catch (_error) {
        return 'preflight-rejected';
      }
    }, `${victim.origin}/change`);

    expect(result).toBe('preflight-rejected');
    expect(observed.options).toBe(1);
    expect(observed.posts).toBe(0);
  } finally {
    await close(attacker.server);
    await close(victim.server);
  }
});

test('nonce CSP runs the matching script and blocks an unnonced inline script', async ({ page }) => {
  const fixture = await listen((_request, response) => {
    response.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "script-src 'nonce-local-fixture'; object-src 'none'; base-uri 'none'",
    });
    response.end(`<!doctype html>
      <script nonce="local-fixture">window.allowedByNonce = true;</script>
      <script>window.blockedWithoutNonce = true;</script>`);
  });

  try {
    await page.goto(fixture.origin);
    expect(await page.evaluate(() => window.allowedByNonce)).toBe(true);
    expect(await page.evaluate(() => window.blockedWithoutNonce)).toBe(undefined);
  } finally {
    await close(fixture.server);
  }
});

async function test_dom_xss_payload_fixture(page) {
  const payload = lessonPayload(
    '05-injection/xss/dom-based/README.md',
    'WEB-A05-DOM-XSS-001',
    'html',
  );
  const fixture = await listen((request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    if (request.url.startsWith('/secure')) {
      response.end(`<!doctype html><body><main id="sink"></main><script>
        document.getElementById('sink').textContent = decodeURIComponent(location.hash.slice(1));
      </script></body>`);
      return;
    }
    response.end(`<!doctype html><body><main id="sink"></main><script>
      document.getElementById('sink').innerHTML = decodeURIComponent(location.hash.slice(1));
    </script></body>`);
  });

  try {
    const fragment = encodeURIComponent(payload);
    await page.goto(`${fixture.origin}/vulnerable#${fragment}`);
    await expect.poll(() => page.evaluate(() => document.body.dataset.labExecuted)).toBe('true');

    await page.goto(`${fixture.origin}/secure#${fragment}`);
    expect(await page.evaluate(() => document.body.dataset.labExecuted)).toBe(undefined);
    expect(await page.locator('#sink').textContent()).toContain('dataset.labExecuted');
  } finally {
    await close(fixture.server);
  }
}

test('the annotated DOM XSS payload executes only in the vulnerable local sink', async ({ page }) => {
  await test_dom_xss_payload_fixture(page);
});

async function test_csrf_text_plain_form_fixture(page) {
  const payload = lessonPayload(
    '07-authentication-failures/csrf/README.md',
    'WEB-A07-CSRF-001',
    'html',
  );
  const observed = { options: 0, posts: 0, body: '', contentType: '' };
  const victim = await listen((request, response) => {
    if (request.method === 'OPTIONS') {
      observed.options += 1;
      response.writeHead(403).end();
      return;
    }
    if (request.method !== 'POST') {
      response.writeHead(404).end();
      return;
    }
    observed.posts += 1;
    observed.contentType = request.headers['content-type'] || '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      observed.body += chunk;
    });
    request.on('end', () => {
      response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      response.end('synthetic account updated');
    });
  });
  const attacker = await listen((_request, response) => {
    const localPayload = payload.replace('https://victim.lab.test', victim.origin);
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><body>${localPayload}</body>`);
  });

  try {
    await page.goto(attacker.origin);
    await expect.poll(() => observed.posts).toBe(1);
    expect(observed.options).toBe(0);
    expect(observed.contentType).toMatch(/^text\/plain(?:;|$)/);
    expect(JSON.parse(observed.body.trim())).toEqual({
      email: 'fixture@untrusted.lab.test',
      _dummy: '=',
    });
  } finally {
    await close(attacker.server);
    await close(victim.server);
  }
}

test('the annotated CSRF form sends valid text/plain JSON without preflight', async ({ page }) => {
  await test_csrf_text_plain_form_fixture(page);
});
