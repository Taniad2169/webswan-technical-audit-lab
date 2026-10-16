import type { Config, Context } from "@netlify/functions";
import dns from "node:dns/promises";
import net from "node:net";
import { analyze } from "../lib/analyze.mjs"; import { STATES, cleanOtherName } from "../lib/states.mjs";

const MAX_BYTES = 2_000_000;
const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 12_000;
const UA = "WebSwanAuditLab/1.0 (public-page checker; contact thewebswann.com)";

function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  const l = ip.toLowerCase();
  if (l.startsWith("::ffff:")) return isPrivateIp(l.slice(7));
  return l === "::1" || l === "::" || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe8") || l.startsWith("fe9") || l.startsWith("fea") || l.startsWith("feb");
}

async function assertPublic(urlStr: string): Promise<URL> {
  let u: URL;
  try { u = new URL(urlStr); } catch { throw new Error("That does not look like a valid web address."); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http and https addresses can be scanned.");
  if (u.username || u.password) throw new Error("Addresses with a username or password are not allowed.");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal") || host.endsWith(".local")) throw new Error("That address is not a public website.");
  const ips = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true }).catch(() => { throw new Error("That website address could not be found."); })).map((r) => r.address);
  if (!ips.length || ips.some(isPrivateIp)) throw new Error("That address is not a public website.");
  return u;
}

async function readCapped(res: Response): Promise<{ text: string; bytes: number }> {
  const reader = res.body?.getReader();
  if (!reader) return { text: "", bytes: 0 };
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BYTES) { chunks.push(value.slice(0, value.length - (total - MAX_BYTES))); try { await reader.cancel(); } catch { /* ignore */ } break; }
    chunks.push(value);
  }
  return { text: new TextDecoder("utf-8").decode(Buffer.concat(chunks)), bytes: Math.min(total, MAX_BYTES) };
}

async function safeFetch(start: string) {
  let current = start;
  const redirects: string[] = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const u = await assertPublic(current);
    const res = await fetch(u.toString(), {
      redirect: "manual",
      headers: { "user-agent": UA, accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5", "accept-language": "en-US,en;q=0.8" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      redirects.push(current);
      current = new URL(res.headers.get("location") as string, u).toString();
      continue;
    }
    const headers: Record<string, string | string[]> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const sc = (res.headers as any).getSetCookie?.();
    if (sc && sc.length) headers["set-cookie"] = sc;
    const { text, bytes } = await readCapped(res);
    return { url: u.toString(), status: res.status, headers, html: text, bytes, redirects, contentType: res.headers.get("content-type") || "" };
  }
  throw new Error("The site redirected too many times.");
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
}

export default async (req: Request, _context: Context) => {
  if (req.method !== "POST") return json({ error: "Use POST." }, 405);
  let body: { url?: string; state?: string; other?: string };
  try { body = await req.json(); } catch { return json({ error: "Send the website address as JSON." }, 400); }
  let input = String(body.url || "").trim();
  if (!input) return json({ error: "Enter a website address." }, 400);
  if (input.length > 2000) return json({ error: "That address is too long." }, 400);
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) input = "https://" + input; const state = String(body.state || "").toUpperCase().slice(0, 8); if (state && state !== "OTHER" && !STATES.some((s) => s.code === state)) return json({ error: "Choose a state from the list." }, 400); const other = cleanOtherName(body.other); if (state === "OTHER" && !other) return json({ error: "Type the state name (up to 12 words)." }, 400);

  try {
    const page = await safeFetch(input);
    if (!/html|xml/i.test(page.contentType) && page.html.indexOf("<") === -1) {
      return json({ error: `That address did not return a web page (it returned ${page.contentType || "unknown content"}).` }, 422);
    }

    // Read the privacy policy page too, if the home page links to one.
    let privacy: { url: string; html: string } | null = null;
    try {
      const { load } = await import("cheerio");
      const $ = load(page.html);
      const cand = $("a[href]").toArray()
        .map((el) => ({ t: ($(el).text() || "").trim(), href: $(el).attr("href") || "" }))
        .find((l) => (/privacy/i.test(l.t) || /privacy/i.test(l.href)) && !/^(mailto:|tel:|javascript:|#)/i.test(l.href));
      if (cand) {
        const target = new URL(cand.href, page.url);
        const sameSite = target.hostname.replace(/^www\./, "") === new URL(page.url).hostname.replace(/^www\./, "");
        if (sameSite || target.protocol === "https:") {
          const pp = await safeFetch(target.toString());
          if (pp.status < 400) privacy = { url: pp.url, html: pp.html };
        }
      }
    } catch { /* privacy page unreadable: the report says so */ }

    const result = analyze({ url: page.url, status: page.status, headers: page.headers, html: page.html, bytes: page.bytes, privacy, redirects: page.redirects, state, other });
    result.meta.finalUrl = page.url;
    return json(result);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "The scan failed.";
    const friendly = /timeout|aborted/i.test(msg) ? "The site took too long to respond." : /fetch failed/i.test(msg) ? "The site could not be reached." : msg;
    return json({ error: friendly }, 422);
  }
};

export const config: Config = {
  path: "/api/scan",
  method: "POST",
  rateLimit: { windowLimit: 12, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
