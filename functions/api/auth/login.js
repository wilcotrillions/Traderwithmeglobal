import { hashPassword, json, randomHex, sessionCookie, sha256, constantTimeEqual, sameOrigin } from "../../_lib/auth.js";

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: "Login is temporarily unavailable." }, 503);
  if (!sameOrigin(request)) return json({ error: "Request origin is not allowed." }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password || password.length > 128) {
    return json({ error: "Enter a valid email address and password." }, 400);
  }

  const user = await env.DB.prepare(`
    SELECT id, password_hash, password_salt, status FROM users WHERE email = ? LIMIT 1
  `).bind(email).first();
  const salt = user?.password_salt || "00000000000000000000000000000000";
  const candidateHash = await hashPassword(password, salt);
  if (!user || !constantTimeEqual(candidateHash, user.password_hash)) {
    return json({ error: "Email or password is incorrect." }, 401);
  }
  if (user.status !== "active") {
    return json({
      error: user.status === "pending"
        ? "Your account is awaiting administrator approval."
        : "This account is not active. Please contact support."
    }, 403);
  }

  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const maxAge = 60 * 60 * 24 * 7;
  const expiresAt = new Date(Date.now() + maxAge * 1000).toISOString();
  try {
    await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(new Date().toISOString()).run();
    await env.DB.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)
    `).bind(crypto.randomUUID(), user.id, tokenHash, expiresAt).run();
  } catch (error) {
    console.error("Login session error:", error);
    return json({ error: "Unable to sign in. Please try again." }, 500);
  }
  return json({ message: "Login successful.", redirect: "/dashboard/" }, 200, {
    "Set-Cookie": sessionCookie(token, maxAge)
  });
}
