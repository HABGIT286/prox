
const UPSTREAM = "https://api.telegramvpn.org";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin"
};

const SESSION_HOURS = 8;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    try {
      // فحص وجود كلمة مرور المدير
      if (!env.PASSWORD) {
        return json({
          success: false,
          error: "Admin password is not configured"
        }, 503);
      }

      // تسجيل دخول المدير
      if (path === "/admin/login" && request.method === "POST") {
        let data;

        try {
          data = await request.json();
        } catch {
          return json({
            success: false,
            error: "Invalid JSON"
          }, 400);
        }

        const supplied = String(data.password || "");

        if (!supplied || supplied.length > 1024) {
          return json({
            success: false,
            error: "Invalid password"
          }, 401);
        }

        if (!constantTimeEqual(supplied, env.PASSWORD)) {
          return json({
            success: false,
            error: "Incorrect password"
          }, 401);
        }

        const expiresAt =
          Math.floor(Date.now() / 1000) +
          SESSION_HOURS * 60 * 60;

        const payload = {
          role: "admin",
          exp: expiresAt
        };

        const token = await createToken(
          payload,
          env.PASSWORD
        );

        return json({
          success: true,
          token,
          expires_at: expiresAt,
          expires_in: SESSION_HOURS * 60 * 60
        });
      }

      // حماية بقية مسارات الإدارة
      if (path.startsWith("/admin/")) {
        const authorized = await verifyToken(
          request,
          env.PASSWORD
        );

        if (!authorized) {
          return json({
            success: false,
            error: "Unauthorized",
            message: "Please login again"
          }, 401);
        }
      }

      // لوحة معلومات البروكسيات
      if (
        path === "/admin/overview" &&
        request.method === "GET"
      ) {
        const [statsResult, proxiesResult] =
          await Promise.all([
            fetchUpstream("/stats"),
            fetchUpstream("/proxies?page=1&per=100")
          ]);

        return json({
          success: true,
          stats: statsResult.data,
          overview: statsResult.data,
          proxies: proxiesResult.data,
          users: [],
          updated_at: new Date().toISOString(),
          data_sources: {
            stats: statsResult.ok,
            proxies: proxiesResult.ok
          }
        });
      }

      // لا يمكن حظر مستخدم MTProto من هذا المصدر وحده
      if (
        path.startsWith("/admin/users/") &&
        path.endsWith("/block")
      ) {
        return json({
          success: false,
          error: "User blocking is not supported by the current upstream API"
        }, 501);
      }

      // المسارات الأصلية للبروكسيات
      if (request.method !== "GET") {
        return json({
          success: false,
          error: "Method not allowed"
        }, 405);
      }

      if (path !== "/proxies" && path !== "/stats") {
        return json({
          success: false,
          error: "Endpoint not allowed"
        }, 404);
      }

      const target = new URL(UPSTREAM + path);

      if (path === "/proxies") {
        const allowedParams = [
          "page",
          "per",
          "sort",
          "status",
          "for"
        ];

        for (const key of allowedParams) {
          const value = url.searchParams.get(key);

          if (value !== null) {
            target.searchParams.set(key, value);
          }
        }
      }

      const upstreamResponse = await fetch(target.toString(), {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "Origin": "https://telegramvpn.org",
          "Referer": "https://telegramvpn.org/"
        },
        redirect: "follow"
      });

      const body = await upstreamResponse.text();

      return new Response(body, {
        status: upstreamResponse.status,
        headers: {
          ...CORS_HEADERS,
          "Content-Type":
            upstreamResponse.headers.get("Content-Type") ||
            "application/json; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });

    } catch (error) {
      return json({
        success: false,
        error: "Worker internal error",
        details: String(error)
      }, 500);
    }
  }
};

// جلب بيانات المصدر الأصلي
async function fetchUpstream(path) {
  try {
    const response = await fetch(UPSTREAM + path, {
      headers: {
        "Accept": "application/json",
        "Origin": "https://telegramvpn.org",
        "Referer": "https://telegramvpn.org/"
      }
    });

    const text = await response.text();

    let data;

    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }

    return {
      ok: response.ok,
      status: response.status,
      data
    };
  } catch (error) {
    return {
      ok: false,
      status: 502,
      data: {
        error: String(error)
      }
    };
  }
}

// مقارنة آمنة لكلمة المرور
function constantTimeEqual(a, b) {
  const encoder = new TextEncoder();
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);

  let diff = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);

  for (let i = 0; i < length; i++) {
    diff |=
      (aa[i % (aa.length || 1)] || 0) ^
      (bb[i % (bb.length || 1)] || 0);
  }

  return diff === 0;
}

// إنشاء جلسة موقعة
async function createToken(payload, secret) {
  const encoded = base64url(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  const key = await getSigningKey(secret);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(encoded)
  );

  return encoded + "." + base64url(
    new Uint8Array(signature)
  );
}

// التحقق من جلسة المدير
async function verifyToken(request, secret) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) {
    return false;
  }

  const token = header.slice(7);
  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  try {
    const key = await getSigningKey(secret);

    const signature = unbase64url(parts[1]);

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(parts[0])
    );

    if (!valid) return false;

    const payload = JSON.parse(
      new TextDecoder().decode(
        unbase64url(parts[0])
      )
    );

    return (
      payload.role === "admin" &&
      Number(payload.exp) > Math.floor(Date.now() / 1000)
    );
  } catch {
    return false;
  }
}

async function getSigningKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign", "verify"]
  );
}

function base64url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function unbase64url(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const binary = atob(
    normalized + "=".repeat((4 - normalized.length % 4) % 4)
  );

  return Uint8Array.from(
    binary,
    char => char.charCodeAt(0)
  );
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}
