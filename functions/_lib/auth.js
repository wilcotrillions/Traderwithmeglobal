const encoder = new TextEncoder();

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

export function readCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const cookie = cookieHeader
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));

  if (!cookie) return null;

  try {
    return decodeURIComponent(cookie.slice(name.length + 1));
  } catch {
    return null;
  }
}

export async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function randomHex(bytes = 32) {
  const values = crypto.getRandomValues(new Uint8Array(bytes));

  return Array.from(values)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function hashPassword(password, saltHex) {
  const salt = Uint8Array.from(
    saltHex.match(/.{2}/g),
    (byte) => parseInt(byte, 16)
  );

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 310000,
      hash: "SHA-256",
    },
    key,
    256
  );

  return Array.from(new Uint8Array(derivedBits))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function sessionCookie(token, maxAge) {
  return [
    `__Host-twg_session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

export function clearSessionCookie() {
  return [
    "__Host-twg_session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}

export async function currentUser(request, env) {
  if (!env.DB) {
    throw new Error("Cloudflare D1 binding DB is not configured.");
  }

  const token = readCookie(request, "__Host-twg_session");

  if (!token) return null;

  const tokenHash = await sha256(token);

  const user = await env.DB.prepare(`
    SELECT
      users.id,
      users.full_name,
      users.email,
      users.role,
      users.status
    FROM sessions
    INNER JOIN users
      ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
    LIMIT 1
  `)
    .bind(tokenHash, new Date().toISOString())
    .first();

  if (!user || user.status !== "active") {
    return null;
  }

  return user;
}

export function requireAdmin(user) {
  return Boolean(user && user.role === "admin" && user.status === "active");
}
