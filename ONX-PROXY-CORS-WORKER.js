/*
 * ONX PROXY ELITE Worker v7
 * Cloudflare Worker + D1 analytics/admin support.
 * Secrets: PASSWORD and TOKEN_SECRET (both Cloudflare secrets).
 * Bindings: DB (Cloudflare D1 database).
 */
const UPSTREAM = 'https://api.telegramvpn.org';
const TOKEN_TTL_SECONDS = 8 * 60 * 60;
const ALLOWED_EVENT_TYPES = new Set(['page_view', 'proxy_open', 'speed_test']);
const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8' };

function response(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...extra } });
}
function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400'
  };
}
function withCors(request, result) {
  const headers = new Headers(result.headers);
  for (const [key, value] of Object.entries(corsHeaders(request))) headers.set(key, value);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Cache-Control', 'no-store');
  return new Response(result.body, { status: result.status, headers });
}
function b64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function fromB64url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function hmac(secret, message) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message)));
}
async function constantTimeEqual(a, b) {
  const left = new TextEncoder().encode(String(a));
  const right = new TextEncoder().encode(String(b));
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) diff |= (left[i] || 0) ^ (right[i] || 0);
  return diff === 0;
}
async function issueToken(env) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ sub: 'onx-admin', exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS })));
  const signature = b64url(await hmac(env.TOKEN_SECRET || env.PASSWORD, payload));
  return `${payload}.${signature}`;
}
async function verifyToken(request, env) {
  const header = request.headers.get('Authorization') || '';
  const match = header.match(/^Bearer\s+([A-Za-z0-9_.-]+)$/i);
  if (!match) return false;
  const [payload, signature] = match[1].split('.');
  if (!payload || !signature) return false;
  const expected = b64url(await hmac(env.TOKEN_SECRET || env.PASSWORD, payload));
  if (!(await constantTimeEqual(signature, expected))) return false;
  try {
    const data = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    return data.sub === 'onx-admin' && Number(data.exp) > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
function validVisitorId(value) {
  return typeof value === 'string' && value.length >= 12 && value.length <= 80 && /^[A-Za-z0-9_-]+$/.test(value);
}
async function readJson(request, maxBytes = 8192) {
  const raw = await request.text();
  if (raw.length > maxBytes) throw new Error('Request body too large');
  return JSON.parse(raw || '{}');
}
async function upstream(path) {
  const url = new URL(path, UPSTREAM);
  const result = await fetch(url.toString(), { headers: { Accept: 'application/json' }, cf: { cacheTtl: 0, cacheEverything: false } });
  const text = await result.text();
  if (!result.ok) return response({ error: 'Upstream request failed', status: result.status, detail: text.slice(0, 300) }, 502);
  try { return response(JSON.parse(text)); }
  catch { return response({ error: 'Upstream returned invalid JSON', detail: text.slice(0, 200) }, 502); }
}
async function writeAudit(db, action, targetId = null) {
  await db.prepare('INSERT INTO audit_log (action, target_id, created_at) VALUES (?, ?, ?)')
    .bind(action, targetId, new Date().toISOString()).run();
}
async function getAnalytics(env) {
  if (!env.DB) return { enabled: false, metrics: { unique_visitors: 0, page_views: 0, proxy_opens: 0 }, visitors: [], blocked_visitors: [], events: [], audit_log: [] };
  const db = env.DB;
  const [unique, newVisitors, views, opens, visitors, blocked, events, audit] = await Promise.all([
    db.prepare('SELECT COUNT(*) AS n FROM visitors').first(),
    db.prepare("SELECT COUNT(*) AS n FROM visitors WHERE julianday(first_seen) > julianday('now','-1 day')").first(),
    db.prepare("SELECT COUNT(*) AS n FROM events WHERE event_type = 'page_view'").first(),
    db.prepare("SELECT COUNT(*) AS n FROM events WHERE event_type = 'proxy_open'").first(),
    db.prepare('SELECT visitor_id, first_seen, last_seen, visit_count, blocked FROM visitors ORDER BY last_seen DESC LIMIT 100').all(),
    db.prepare('SELECT visitor_id, blocked_at FROM blocked_visitors ORDER BY blocked_at DESC LIMIT 100').all(),
    db.prepare('SELECT id, visitor_id, event_type, details_json, created_at FROM events ORDER BY id DESC LIMIT 60').all(),
    db.prepare('SELECT id, action, target_id, created_at FROM audit_log ORDER BY id DESC LIMIT 60').all()
  ]);
  return {
    enabled: true,
    metrics: { unique_visitors: unique?.n || 0, new_visitors: newVisitors?.n || 0, page_views: views?.n || 0, proxy_opens: opens?.n || 0 },
    visitors: visitors.results || [], blocked_visitors: blocked.results || [],
    events: (events.results || []).map(row => ({ ...row, details: safeJson(row.details_json) })),
    audit_log: audit.results || []
  };
}
function safeJson(value) { try { return JSON.parse(value || '{}'); } catch { return {}; } }

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const method = request.method.toUpperCase();
  if (method === 'OPTIONS') return new Response(null, { status: 204 });
  if (method === 'GET' && path === '/health') return response({ ok: true, service: 'ONX PROXY Worker', version: '7', database: !!env.DB });
  if (method === 'POST' && path === '/admin/login') {
    if (!env.PASSWORD) return response({ error: 'PASSWORD secret is not configured' }, 503);
    let body;
    try { body = await readJson(request, 2048); } catch { return response({ error: 'Invalid JSON' }, 400); }
    if (!(await constantTimeEqual(body.password || '', env.PASSWORD))) return response({ error: 'Invalid password' }, 401);
    if (env.DB) await writeAudit(env.DB, 'admin_login');
    return response({ token: await issueToken(env), expires_in: TOKEN_TTL_SECONDS });
  }
  if (method === 'POST' && path === '/events') {
    if (!env.DB) return response({ error: 'Analytics database is not configured. Bind D1 as DB.' }, 503);
    let body;
    try { body = await readJson(request, 4096); } catch { return response({ error: 'Invalid JSON or body too large' }, 400); }
    const visitorId = body.visitor_id;
    const eventType = body.event_type;
    if (!validVisitorId(visitorId) || !ALLOWED_EVENT_TYPES.has(eventType)) return response({ error: 'Invalid visitor_id or event_type' }, 400);
    const blocked = await env.DB.prepare('SELECT visitor_id FROM blocked_visitors WHERE visitor_id = ?').bind(visitorId).first();
    if (blocked) return response({ error: 'This browser is blocked from the website' }, 403);
    const now = new Date().toISOString();
    const details = body.details && typeof body.details === 'object' ? body.details : {};
    // Store only allow-listed, low-risk event metadata; never store IP addresses or Telegram account identifiers.
    const safeDetails = {
      path: typeof details.path === 'string' ? details.path.slice(0, 160) : undefined,
      method: typeof details.method === 'string' ? details.method.slice(0, 40) : undefined,
      proxy_id: typeof details.proxy_id === 'string' ? details.proxy_id.slice(0, 100) : undefined,
      server: typeof details.server === 'string' ? details.server.slice(0, 120) : undefined,
      port: Number.isFinite(Number(details.port)) ? Number(details.port) : undefined,
      started_at: typeof details.started_at === 'string' ? details.started_at.slice(0, 40) : undefined
    };
    const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM events WHERE visitor_id = ? AND julianday(created_at) > julianday('now','-1 minute')").bind(visitorId).first();
    if ((recent?.n || 0) > 45) return response({ error: 'Event rate limit exceeded' }, 429);
    await env.DB.prepare(`INSERT INTO visitors (visitor_id, first_seen, last_seen, visit_count, blocked)
      VALUES (?, ?, ?, ?, 0)
      ON CONFLICT(visitor_id) DO UPDATE SET last_seen = excluded.last_seen,
      visit_count = visitors.visit_count + excluded.visit_count`)
      .bind(visitorId, now, now, eventType === 'page_view' ? 1 : 0).run();
    const result = await env.DB.prepare('INSERT INTO events (visitor_id, event_type, details_json, created_at) VALUES (?, ?, ?, ?)')
      .bind(visitorId, eventType, JSON.stringify(safeDetails), now).run();
    return response({ ok: true, event_id: result.meta?.last_row_id || null });
  }
  if (method === 'GET' && path === '/stats') return upstream('/stats');
  if (method === 'GET' && path === '/proxies') {
    const allowed = ['page', 'per', 'sort', 'status', 'for'];
    const query = new URLSearchParams();
    for (const key of allowed) if (url.searchParams.has(key)) query.set(key, url.searchParams.get(key));
    return upstream('/proxies' + (query.size ? '?' + query.toString() : ''));
  }
  if (path.startsWith('/admin/')) {
    if (!(await verifyToken(request, env))) return response({ error: 'Unauthorized' }, 401);
    if (method === 'GET' && path === '/admin/overview') {
      const [statsResponse, proxiesResponse, analytics] = await Promise.all([
        upstream('/stats'), upstream('/proxies?page=1&per=100'), getAnalytics(env)
      ]);
      const stats = await statsResponse.json().catch(() => ({}));
      const proxyPayload = await proxiesResponse.json().catch(() => ({}));
      if (env.DB) await writeAudit(env.DB, 'admin_view_overview');
      return response({
        stats: stats.stats || stats.data || stats,
        overview: stats.stats || stats.data || stats,
        proxies: proxyPayload.proxies || proxyPayload.data || proxyPayload,
        users: analytics.visitors,
        ...analytics,
        data_sources: { proxy_api: 'api.telegramvpn.org', analytics_database: analytics.enabled ? 'Cloudflare D1' : 'not_configured', telegram_user_identity: false }
      });
    }
    const visitorAction = path.match(/^\/admin\/visitors\/([A-Za-z0-9_-]{12,80})\/(block|unblock)$/);
    if (visitorAction && method === 'POST') {
      if (!env.DB) return response({ error: 'D1 database is not configured' }, 503);
      const visitorId = visitorAction[1];
      const action = visitorAction[2];
      const now = new Date().toISOString();
      if (action === 'block') {
        await env.DB.prepare('INSERT INTO blocked_visitors (visitor_id, blocked_at) VALUES (?, ?) ON CONFLICT(visitor_id) DO UPDATE SET blocked_at = excluded.blocked_at').bind(visitorId, now).run();
        await env.DB.prepare('UPDATE visitors SET blocked = 1 WHERE visitor_id = ?').bind(visitorId).run();
        await writeAudit(env.DB, 'block_website_visitor', visitorId);
      } else {
        await env.DB.prepare('DELETE FROM blocked_visitors WHERE visitor_id = ?').bind(visitorId).run();
        await env.DB.prepare('UPDATE visitors SET blocked = 0 WHERE visitor_id = ?').bind(visitorId).run();
        await writeAudit(env.DB, 'unblock_website_visitor', visitorId);
      }
      return response({ ok: true, visitor_id: visitorId, action });
    }
    if (method === 'GET' && path === '/admin/events') {
      if (!env.DB) return response({ error: 'D1 database is not configured' }, 503);
      const result = await env.DB.prepare('SELECT id, visitor_id, event_type, details_json, created_at FROM events ORDER BY id DESC LIMIT 100').all();
      return response({ events: (result.results || []).map(row => ({ ...row, details: safeJson(row.details_json) })) });
    }
    return response({ error: 'Admin route not found' }, 404);
  }
  return response({ error: 'Not found', routes: ['/health', '/stats', '/proxies', '/events', '/admin/login', '/admin/overview'] }, 404);
}

export default {
  async fetch(request, env) {
    try {
      const result = await handle(request, env);
      return withCors(request, result);
    } catch (error) {
      return withCors(request, response({ error: 'Internal Worker error', message: String(error?.message || error) }, 500));
    }
  }
};
