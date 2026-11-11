import {
  json,
  readCookie,
  sha256,
  clearSessionCookie,
} from "../../_lib/auth.js";

export async function onRequestPost({ request, env }) {
  if (!env.DB) {
    return json(
      { error: "Logout is temporarily unavailable." },
      503
    );
  }

  const token = readCookie(
    request,
    "__Host-twg_session"
  );

  if (token) {
    const tokenHash = await sha256(token);

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `)
      .bind(tokenHash)
      .run();
  }

  return json(
    { message: "You have successfully signed out." },
    200,
    {
      "Set-Cookie": clearSessionCookie(),
    }
  );
}
