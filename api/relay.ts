// فایل: api/relay.ts

export const config = {
  runtime: 'edge', // این خط به ورسل می‌فهماند که کد را در محیط سبک و سریع Edge اجرا کند
};

const PSK = "KG,u~=8)E46Q2.Mu>k#huy1Hbmfmi^!%46z.jAx+1YC}q~@Cd-?G-MKm6mgpC]!FL]UQ-V5ZKtm=_zn>K#P>XEUNE+)}aJe@#G4W";

const STRIP_HEADERS = new Set([
  "host", "connection", "content-length", "transfer-encoding",
  "proxy-connection", "proxy-authorization", "x-forwarded-for",
  "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
  "x-real-ip", "forwarded", "via",
]);

function decodeBase64ToBytes(input: string): Uint8Array {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeBytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function sanitizeHeaders(h: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h || typeof h !== "object") return out;
  for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
    if (!k) continue;
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  }
  return out;
}

// تابع اصلی شما که حالا به عنوان export default برای ورسل تعریف شده است
export default async function handleExitNodeRequest(req: Request): Promise<Response> {
  try {
    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "*",
        },
      });
    }

    if (req.method !== "POST") {
      return Response.json({ e: "method_not_allowed" }, { status: 405 });
    }

    const body = await req.json();
    if (!body || typeof body !== "object") {
      return Response.json({ e: "bad_json" }, { status: 400 });
    }

    const k = String((body as any).k ?? "");
    const u = String((body as any).u ?? "");
    const m = String((body as any).m ?? "GET").toUpperCase();
    const h = sanitizeHeaders((body as any).h);
    const b64 = (body as any).b;

    if (k !== PSK) {
      return Response.json({ e: "unauthorized" }, { status: 401 });
    }
    if (!/^https?:\/\//i.test(u)) {
      return Response.json({ e: "bad url" }, { status: 400 });
    }

    let payload: Uint8Array | undefined;
    if (typeof b64 === "string" && b64.length > 0) {
      payload = decodeBase64ToBytes(b64);
    }

    const resp = await fetch(u, {
      method: m,
      headers: h,
      body: payload,
      redirect: "manual",
    });

    const data = new Uint8Array(await resp.arrayBuffer());
    const respHeaders: Record<string, any> = {};
    
    resp.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (lower === "content-encoding" || lower === "content-length") return;
      respHeaders[key] = value;
    });

    // منطق عالی شما برای مدیریت کوکی‌ها
    if (typeof resp.headers.getSetCookie === "function") {
      const cookies = resp.headers.getSetCookie();
      if (cookies && cookies.length > 0) {
        respHeaders["set-cookie"] = cookies;
      }
    }

    return Response.json({
      s: resp.status,
      h: respHeaders,
      b: encodeBytesToBase64(data),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return Response.json({ e: message }, { status: 500 });
  }
}