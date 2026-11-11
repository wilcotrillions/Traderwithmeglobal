import { json, randomHex, sha256, sameOrigin } from "../../_lib/auth.js";

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: "Password recovery is temporarily unavailable." }, 503);
  if (!sameOrigin(request)) return json({ error: "Request origin is not allowed." }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }
  const email = String(body.email || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Enter a valid email address." }, 400);

  const user = await env.DB.prepare("SELECT id, email, full_name FROM users WHERE email = ? LIMIT 1").bind(email).first();
  // Always return the same response for existing and unknown email addresses.
  if (!user) return json({ message: "If an eligible account exists, password-reset instructions will be sent." });

  if (!env.RESEND_API_KEY || !env.AUTH_FROM_EMAIL) {
    console.error("Password recovery requires RESEND_API_KEY and AUTH_FROM_EMAIL environment secrets.");
    return json({ error: "Password recovery email is not configured yet. Please contact support." }, 503);
  }

  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  const appUrl = (env.PUBLIC_APP_URL || new URL(request.url).origin).replace(/\/$/, "");
  const resetUrl = `${appUrl}/reset-password/?token=${token}`;
  try {
    await env.DB.prepare("DELETE FROM password_reset_tokens WHERE user_id = ? OR expires_at <= ?")
      .bind(user.id, new Date().toISOString()).run();
    await env.DB.prepare(`
      INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
      VALUES (?, ?, ?, ?)
    `).bind(crypto.randomUUID(), user.id, tokenHash, expiresAt).run();

    const mail = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: env.AUTH_FROM_EMAIL,
        to: [user.email],
        subject: "Reset your TradeWithMe Global password",
        html: `<p>Hello ${escapeHtml(user.full_name)},</p><p>Use the link below to reset your password. It expires in 30 minutes and can only be used once.</p><p><a href="${resetUrl}">Reset password</a></p><p>If you did not request this, you can ignore this email.</p>`
      })
    });
    if (!mail.ok) {
      await env.DB.prepare("DELETE FROM password_reset_tokens WHERE token_hash = ?").bind(tokenHash).run();
      console.error("Password reset email provider returned:", mail.status);
      return json({ error: "Unable to send the reset email right now. Please try again later." }, 502);
    }
    return json({ message: "If an eligible account exists, password-reset instructions will be sent." });
  } catch (error) {
    console.error("Password reset request error:", error);
    return json({ error: "Unable to process your request right now." }, 500);
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}
