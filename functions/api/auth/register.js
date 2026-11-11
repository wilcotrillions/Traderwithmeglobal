import { hashPassword, json, randomHex, sameOrigin } from "../../_lib/auth.js";

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: "Registration is temporarily unavailable." }, 503);
  if (!sameOrigin(request)) return json({ error: "Request origin is not allowed." }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request body." }, 400); }

  const fullName = String(body.fullName || "").trim().replace(/\s+/g, " ");
  const email = String(body.email || "").trim().toLowerCase();
  const phone = String(body.phone || "").trim();
  const password = String(body.password || "");
  const acceptedTerms = body.acceptedTerms === true;

  if (fullName.length < 2 || fullName.length > 100) return json({ error: "Enter your full name (2–100 characters)." }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return json({ error: "Enter a valid email address." }, 400);
  if (phone.length > 30) return json({ error: "Phone number is too long." }, 400);
  if (password.length < 12 || password.length > 128) return json({ error: "Password must contain 12–128 characters." }, 400);
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    return json({ error: "Use at least one uppercase letter, one lowercase letter and one number." }, 400);
  }
  if (!acceptedTerms) return json({ error: "Please accept the Terms and Privacy Policy." }, 400);

  const id = crypto.randomUUID();
  const salt = randomHex(16);
  const passwordHash = await hashPassword(password, salt);
  try {
    await env.DB.prepare(`
      INSERT INTO users (id, full_name, email, phone, password_hash, password_salt, role, status)
      VALUES (?, ?, ?, ?, ?, ?, 'customer', 'pending')
    `).bind(id, fullName, email, phone || null, passwordHash, salt).run();
    return json({
      message: "Your account has been created and is awaiting administrator approval.",
      status: "pending"
    }, 201);
  } catch (error) {
    if (String(error).toLowerCase().includes("unique")) return json({ error: "An account with this email already exists." }, 409);
    console.error("Registration error:", error);
    return json({ error: "Unable to create your account. Please try again." }, 500);
  }
}
