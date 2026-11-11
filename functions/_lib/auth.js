const encoder = new TextEncoder();

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      "Pragma": "no-cache",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "same-origin",
      ...headers,
    },
  });
}

export function readCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookie = cookieHeader.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  if (!cookie) return null;
  try { return decodeURIComponent(cookie.slice(name.length + 1)); }
  catch { return null; }
}

export async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomHex(bytes = 32) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)),
    (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function hashPassword(password, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/.{2}/g), (b) => parseInt(b, 16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, key, 256
  );
  return Array.from(new Uint8Array(bits), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function sessionCookie(token, maxAge) {
  return [`__Host-twg_session=${encodeURIComponent(token)}`, "Path=/", "HttpOnly",
    "Secure", "SameSite=Lax", `Max-Age=${maxAge}`].join("; ");
}

export function clearSessionCookie() {
  return ["__Host-twg_session=", "Path=/", "HttpOnly", "Secure",
    "SameSite=Lax", "Max-Age=0"].join("; ");
}

export function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true; // Non-browser clients may omit Origin; authenticate with the session token.
  try { return new URL(origin).origin === new URL(request.url).origin; }
  catch { return false; }
}

export async function currentUser(request, env) {
  if (!env.DB) throw new Error("Cloudflare D1 binding DB is not configured.");
  const token = readCookie(request, "__Host-twg_session");
  if (!token) return null;
  const tokenHash = await sha256(token);
  const user = await env.DB.prepare(`
    SELECT users.id, users.full_name, users.email, users.phone, users.role, users.status
    FROM sessions INNER JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ? LIMIT 1
  `).bind(tokenHash, new Date().toISOString()).first();
  return user && user.status === "active" ? user : null;
}

export function requireAdmin(user) {
  return Boolean(user && user.role === "admin" && user.status === "active");
}
