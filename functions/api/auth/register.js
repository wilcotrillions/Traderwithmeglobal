import { hashPassword, json, randomHex } from "../../_lib/auth.js";

export async function onRequestPost({ request, env }) {
  if (!env.DB) {
    return json({ error: "Registration is temporarily unavailable." }, 503);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid request body." }, 400);
  }

  const fullName = String(body.fullName || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (fullName.length < 2 || fullName.length > 100) {
    return json({ error: "Enter your full name." }, 400);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ error: "Enter a valid email address." }, 400);
  }

  if (password.length < 12 || password.length > 128) {
    return json({
      error: "Password must contain at least 12 characters."
    }, 400);
  }

  const id = crypto.randomUUID();
  const salt = randomHex(16);
  const passwordHash = await hashPassword(password, salt);

  try {
    await env.DB.prepare(`
      INSERT INTO users (
        id,
        full_name,
        email,
        password_hash,
        password_salt,
        role,
        status
      )
      VALUES (?, ?, ?, ?, ?, 'customer', 'pending')
    `)
      .bind(id, fullName, email, passwordHash, salt)
      .run();

  } catch (error) {
    if (String(error).toLowerCase().includes("unique")) {
      return json({
        error: "An account with this email already exists."
      }, 409);
    }

    console.error("Registration error:", error);

    return json({
      error: "Unable to create account. Please try again."
    }, 500);
  }

  return json({
    message: "Registration successful. Your account is pending administrator approval.",
    status: "pending"
  }, 201);
}
