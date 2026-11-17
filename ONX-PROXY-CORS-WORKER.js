
const UPSTREAM = "https://api.telegramvpn.org";

// غيّر * إلى عنوان موقعك على GitHub Pages بعد معرفة رابطه
const ALLOWED_ORIGIN = "*";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin"
};

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // السماح بطلبات CORS التمهيدية
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    if (request.method !== "GET") {
      return json({
        success: false,
        error: "Method not allowed"
      }, 405);
    }

    // السماح فقط بالمسارات المطلوبة
    const allowedPaths = ["/proxies", "/stats"];

    if (!allowedPaths.includes(url.pathname)) {
      return json({
        success: false,
        error: "Endpoint not allowed"
      }, 404);
    }

    // منع تمرير معاملات غير ضرورية
    const target = new URL(UPSTREAM + url.pathname);

    if (url.pathname === "/proxies") {
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

    try {
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
        error: "Upstream connection failed",
        details: String(error)
      }, 502);
    }
  }
};

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
