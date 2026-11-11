import { json, currentUser } from "../../_lib/auth.js";

export async function onRequestGet({ request, env }) {
  try {
    const user = await currentUser(request, env);
    if (!user) return json({ error: "You are not signed in." }, 401);
    return json({ authenticated: true, user: {
      id: user.id, fullName: user.full_name, email: user.email,
      phone: user.phone || "", role: user.role, status: user.status
    }});
  } catch (error) {
    console.error("Session verification error:", error);
    return json({ error: "Unable to verify your session." }, 503);
  }
}
