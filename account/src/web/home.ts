// The pages of account.openentity.org besides /approve: the home page (sign-in, or the signed-in account) and the
// /app/auth landing that the Apple return and App Links reach when they open in a browser.
import { esc, page } from "./page.ts";
import { homeClient } from "./home-client.ts";

const ERRORS: Record<string, string> = {
  state_invalid: "That sign-in expired.", id_token_invalid: "Apple did not confirm the sign-in.", nonce_invalid: "That sign-in expired.",
  account_exists: "This email already has an OpenEntity account. Sign in with its method, then add Apple in Settings.",
  provider_error: "Apple could not finish the sign-in.",
};

export function homePage(o: { serviceDid: string; rpId: string; turnstile: string | null; google: string | null; error: string | null; testSignIn: boolean }) {
  return page({
    title: "OpenEntity account",
    body: `
<p id="loading">Loading.</p>
<p id="page-error" class="error" hidden></p>
<section id="signin" hidden>
  <h1>Sign in to OpenEntity</h1>
  <p>One account for Moltbot Den, Secure My Agent, Agent Secret Store and ClawGRC.</p>
  <p id="signin-error" class="error" hidden></p>
  <button id="apple">Continue with Apple</button>
  <div id="google-row" hidden><button id="google">Continue with Google</button></div>
  <button id="passkey">Sign in with a passkey</button>
  <form id="email-form"><input id="email" type="email" required autocomplete="username webauthn" placeholder="you@example.com" aria-label="Email"><button class="primary">Email me a code</button></form>
  <form id="code-form" hidden><input id="code" inputmode="numeric" pattern="[0-9]{8}" maxlength="8" required autocomplete="one-time-code" placeholder="8-digit code" aria-label="Code"><button class="primary">Sign in</button></form>
  <div id="turnstile"></div>
  <form id="test-signin" class="panel" hidden><p class="note">Staging only: sign in as a test owner (an address at test.openentity.org).</p><input id="test-email" type="email" required placeholder="qa-1@test.openentity.org" aria-label="Test email"><button>Test sign-in</button></form>
  <p class="note">New here? Signing in creates your account. There are no passwords.</p>
</section>
<section id="account" hidden>
  <h1 id="who"></h1>
  <p class="mono" id="owner"></p>
  <h2>Approvals</h2>
  <p id="approvals-error" class="error" hidden></p>
  <div id="approvals-off" hidden>
    <p>Turn on approvals with a passkey. It becomes the root of your approvals, and it can approve on this site.</p>
    <p class="warn">There is no reset. If you lose this passkey and every approver, nobody can restore approvals for this account, including us. You would start a new account. Add a backup next.</p>
    <button id="turn-on" class="primary">Turn on approvals with a passkey</button>
  </div>
  <div id="approvals-on" hidden>
    <ul class="list" id="approvers"></ul>
    <p id="backup" class="warn" hidden>Add a backup: a second passkey or another approver device.</p>
    <button id="add-approver">Add a passkey approver</button>
    <div id="enroll" class="panel" hidden><p>On a phone that is already an approver, open the OpenEntity app and check that it shows this code:</p><p class="code" id="enroll-code"></p><p id="enroll-state" class="note" hidden></p></div>
  </div>
  <h2>Sign-in methods</h2>
  <ul class="list" id="methods"></ul>
  <p class="note">Add or remove sign-in methods in the OpenEntity app.</p>
  <h2>Sessions</h2>
  <ul class="list" id="sessions"></ul>
  <h2>Delete account</h2>
  <p id="deletion-state" class="warn" hidden></p>
  <p id="deletion-error" class="error" hidden></p>
  <button id="delete" class="danger">Delete my account</button>
  <button id="request-deletion" hidden>My approvers are lost: delete in 7 days</button>
  <button id="cancel-deletion" hidden>Cancel the deletion</button>
  <button id="signout">Sign out</button>
</section>`,
    client: homeClient,
    config: o,
    csp: {
      "script-src": ["https://challenges.cloudflare.com", "https://accounts.google.com/gsi/client"],
      "frame-src": ["https://challenges.cloudflare.com", "https://accounts.google.com/gsi/"],
      "connect-src": ["https://accounts.google.com/gsi/"],
      "style-src": ["https://accounts.google.com/gsi/style"],
    },
  });
}

/** /app/auth in a browser: the Apple return's error, or a login code meant for the Android app. */
export function appAuthPage(q: { error?: string; login_code?: string }) {
  const text = q.login_code
    ? "Return to the OpenEntity app on your phone to finish signing in. If it did not open, open it now."
    : `${ERRORS[q.error ?? ""] ?? "Sign-in did not finish."} Try again.`;
  return page({ title: "OpenEntity sign-in", body: `<h1>Sign in</h1><p>${esc(text)}</p><p><a class="button" href="/">Back to sign-in</a></p>` });
}
