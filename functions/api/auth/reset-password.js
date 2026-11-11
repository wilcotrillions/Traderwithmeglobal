import { hashPassword, json, randomHex, sha256, sameOrigin } from "../../_lib/auth.js";

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: "Password reset is temporarily unavailable." }, 503);
  if (!sameOrigin(request)) return json({ error: "Request origin is not allowed." }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
  const token = String(body.token || "");
  const password = String(body.password || "");
  if (!/^[a-f0-9]{64}$/i.test(token)) return json({ error: "This reset link is invalid or expired." }, 400);
  if (password.length < 12 || password.length > 128 ||
      !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    return json({ error: "Use 12–128 characters with uppercase, lowercase and a number." }, 400);
  }

  const tokenHash = await sha256(token);
  const record = await env.DB.prepare(`
    SELECT id, user_id FROM password_reset_tokens
    WHERE token_hash = ? AND expires_at > ? LIMIT 1
  `).bind(tokenHash, new Date().toISOString()).first();
  if (!record) return json({ error: "This reset link is invalid or expired." }, 400);

  const salt = randomHex(16);
  const passwordHash = await hashPassword(password, salt);
  try {
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(passwordHash, salt, record.user_id),
      env.DB.prepare("DELETE FROM password_reset_tokens WHERE user_id = ?").bind(record.user_id),
      env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(record.user_id)
    ]);
    return json({ message: "Password updated. Please sign in with your new password." });
  } catch (error) {
    console.error("Password reset error:", error);
    return json({ error: "Unable to reset your password. Please request a new link." }, 500);
  }
}
