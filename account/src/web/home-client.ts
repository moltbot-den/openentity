// Browser code for / (account.openentity.org), serialized by page.ts: it may use only its own locals and browser globals.
// Signed out: Apple, Google, passkeys (conditional UI) and the email code, with Turnstile for sign-up. Signed in: the
// account, sessions, approvals (turn on with a passkey, add a passkey approver), deletion and sign-out.
export function homeClient(cfg: { serviceDid: string; rpId: string; turnstile: string | null; google: string | null; error: string | null }) {
  const $ = (id: string) => document.getElementById(id) as HTMLElement & HTMLInputElement & HTMLButtonElement;
  const show = (id: string, on = true) => { $(id).hidden = !on; };
  const say = (id: string, text: string) => { $(id).textContent = text; show(id, !!text); };
  const b64u = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b instanceof Uint8Array ? b : new Uint8Array(b)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const bytes = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (ch) => ch.charCodeAt(0));
  const sha256 = async (s: string | Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest("SHA-256", typeof s === "string" ? new TextEncoder().encode(s) : s));
  const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  // RFC 8785 for the values a key log entry holds (objects, arrays, strings, integers, booleans, null).
  const jcs = (v: unknown): string => v === null || typeof v !== "object" ? JSON.stringify(v)
    : Array.isArray(v) ? `[${v.map(jcs).join(",")}]`
    : `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs((v as Record<string, unknown>)[k])}`).join(",")}}`;
  const base32 = (b: Uint8Array) => {
    const A = "abcdefghijklmnopqrstuvwxyz234567";
    let out = "", bits = 0, value = 0;
    for (const x of b) { value = (value << 8) | x; bits += 8; while (bits >= 5) out += A[(value >> (bits -= 5)) & 31]; value &= (1 << bits) - 1; }
    return bits ? out + A[(value << (5 - bits)) & 31] : out;
  };
  const web = { platform: "web" };
  let token = "";
  const api = async (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) => {
    const r = await fetch(path, { method, credentials: "same-origin", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    let v: any = null;
    try { v = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
    if (!r.ok) throw Object.assign(new Error(v?.message ?? `request failed (${r.status})`), { code: v?.error, status: r.status });
    return v;
  };
  const MESSAGES: Record<string, string> = {
    state_invalid: "That sign-in expired. Try again.", id_token_invalid: "Apple did not confirm the sign-in. Try again.",
    account_exists: "This email already has an OpenEntity account. Sign in with that account's method, then add Apple in Settings.",
    provider_error: "Apple could not finish the sign-in. Try again.", nonce_invalid: "That sign-in expired. Try again.",
    turnstile_required: "Complete the human check first.", turnstile_invalid: "The human check did not pass. Try again.",
    code_invalid: "Wrong code. Check the email and try again.", code_expired: "That code expired. Ask for a new one.", code_locked: "Too many wrong tries. Ask for a new code.",
    reauth_required: "For safety, sign out, sign in again, then delete within 5 minutes.",
  };
  const message = (e: any) => MESSAGES[e?.code] ?? (e?.name === "NotAllowedError" ? "The passkey prompt was closed or timed out." : e?.message ?? String(e));

  // WebAuthn JSON (base64url fields) to and from the browser's binary form.
  const getOptions = (o: any): PublicKeyCredentialRequestOptions => ({ ...o, challenge: bytes(o.challenge), allowCredentials: (o.allowCredentials ?? []).map((c: any) => ({ ...c, id: bytes(c.id) })) });
  const createOptions = (o: any): PublicKeyCredentialCreationOptions => ({
    ...o, challenge: bytes(o.challenge), user: { ...o.user, id: bytes(o.user.id) }, excludeCredentials: (o.excludeCredentials ?? []).map((c: any) => ({ ...c, id: bytes(c.id) })),
  });
  const assertionJson = (c: PublicKeyCredential) => {
    const r = c.response as AuthenticatorAssertionResponse;
    return { id: c.id, rawId: b64u(c.rawId), type: c.type, clientExtensionResults: {}, response: { authenticatorData: b64u(r.authenticatorData), clientDataJSON: b64u(r.clientDataJSON), signature: b64u(r.signature), userHandle: r.userHandle ? b64u(r.userHandle) : undefined } };
  };
  const registrationJson = (c: PublicKeyCredential) => {
    const r = c.response as AuthenticatorAttestationResponse;
    return { id: c.id, rawId: b64u(c.rawId), type: c.type, clientExtensionResults: {}, response: { attestationObject: b64u(r.attestationObject), clientDataJSON: b64u(r.clientDataJSON), transports: r.getTransports?.() ?? [] } };
  };
  // Key log entries accept only a low S (keylog-1): an authenticator's DER signature with s > n/2 is sent as n - s.
  const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const lowS = (der: Uint8Array) => {
    const rLen = der[3], r = der.slice(4, 4 + rLen), sBytes = der.slice(6 + rLen, 6 + rLen + der[5 + rLen]);
    const s = BigInt(`0x${hex(sBytes)}`);
    if (s <= N >> 1n) return der;
    const h = (N - s).toString(16).padStart(64, "0");
    let low = Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
    while (low.length > 1 && low[0] === 0 && !(low[1] & 0x80)) low = low.slice(1);
    if (low[0] & 0x80) low = Uint8Array.of(0, ...low);
    const body = [0x02, r.length, ...r, 0x02, low.length, ...low];
    return Uint8Array.from([0x30, body.length, ...body]);
  };
  /** A passkey assertion whose challenge is `digest`, by one of `credentialIds`: the webauthn form fields. */
  const signWithPasskey = async (digest: Uint8Array<ArrayBuffer>, credentialIds: string[]) => {
    const c = (await navigator.credentials.get({ publicKey: { challenge: digest, rpId: cfg.rpId, allowCredentials: credentialIds.map((id) => ({ type: "public-key" as const, id: bytes(id) })), userVerification: "required", timeout: 120_000 } })) as PublicKeyCredential;
    const r = c.response as AuthenticatorAssertionResponse;
    return { id: c.id, signature: b64u(lowS(new Uint8Array(r.signature))), authenticator_data: b64u(r.authenticatorData), client_data_json: b64u(r.clientDataJSON) };
  };

  // ---------------------------------------------------------------- signed out
  // Turnstile tokens are single use: each call that spends one resets the widget for the next.
  const human = () => (window as any).__ts ?? "";
  const fresh = () => { (window as any).__ts = ""; try { (window as any).turnstile?.reset(); } catch { /* not loaded */ } };
  (window as any).onTurnstile = (v: string) => { (window as any).__ts = v; };

  const signedIn = () => location.replace("/");
  let challengeId = "";
  const signOut = async () => { await api("POST", "/v1/revoke", {}).catch(() => null); location.replace("/"); };

  const signInView = async () => {
    show("signin");
    if (cfg.error) say("signin-error", MESSAGES[cfg.error] ?? "Sign-in did not finish. Try again.");
    if (cfg.turnstile) {
      const s = document.createElement("script");
      s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad&render=explicit";
      (window as any).onTurnstileLoad = () => (window as any).turnstile.render("#turnstile", { sitekey: cfg.turnstile, callback: (window as any).onTurnstile, "refresh-expired": "auto" });
      document.head.append(s);
    }
    $("apple").addEventListener("click", async () => {
      try {
        const n = await api("POST", "/v1/auth/nonce", { client: web, flow: "apple_web", return_to: "/", turnstile_token: human() });
        location.assign(n.authorize_url);
      } catch (e) { fresh(); say("signin-error", message(e)); }
    });
    if (cfg.google) {
      const g = document.createElement("script");
      g.src = "https://accounts.google.com/gsi/client";
      document.head.append(g);
      show("google-row");
      $("google").addEventListener("click", async () => {
        try {
          const n = await api("POST", "/v1/auth/nonce", { client: web, turnstile_token: human() });
          fresh();
          const g = (window as any).google?.accounts?.id;
          if (!g) throw new Error("Google sign-in did not load. Check your connection and try again.");
          g.initialize({
            client_id: cfg.google, nonce: hex(await sha256(n.nonce)), use_fedcm_for_prompt: true,
            callback: async (resp: { credential: string }) => {
              try { await api("POST", "/v1/auth/google", { id_token: resp.credential, nonce: n.nonce, client: web }); signedIn(); } catch (e) { say("signin-error", message(e)); }
            },
          });
          g.prompt();
        } catch (e) { fresh(); say("signin-error", message(e)); }
      });
    }
    const passkey = async (mediation?: "conditional") => {
      const o = await api("POST", "/v1/auth/passkey/options", { mode: "authenticate", client: web });
      const c = (await navigator.credentials.get({ publicKey: getOptions(o.options), ...(mediation ? { mediation } : {}) })) as PublicKeyCredential | null;
      if (!c) return;
      await api("POST", "/v1/auth/passkey/verify", { challenge_id: o.challenge_id, response: assertionJson(c), client: web });
      signedIn();
    };
    $("passkey").addEventListener("click", () => passkey().catch((e) => say("signin-error", message(e))));
    if ((await (PublicKeyCredential as any).isConditionalMediationAvailable?.().catch(() => false))) passkey("conditional").catch(() => { /* the user picked another way */ });
    $("email-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      try {
        const r = await api("POST", "/v1/auth/email/start", { email: $("email").value, client: web, turnstile_token: human() });
        fresh();
        challengeId = r.challenge_id;
        show("code-form");
        $("code").focus();
      } catch (e) { fresh(); say("signin-error", message(e)); }
    });
    $("code-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      try {
        await api("POST", "/v1/auth/email/verify", { challenge_id: challengeId, code: $("code").value.trim(), client: web, turnstile_token: human() });
        signedIn();
      } catch (e) { fresh(); say("signin-error", message(e)); }
    });
  };

  // ---------------------------------------------------------------- signed in
  const accountView = async () => {
    show("account");
    const me = await api("GET", "/v1/me");
    $("who").textContent = me.email ?? "Your account";
    $("owner").textContent = me.owner_did ?? "Approvals are off";
    for (const m of me.methods) {
      const li = document.createElement("li");
      li.textContent = `${m.type === "email" ? "Email" : m.type === "apple" ? "Apple" : m.type === "google" ? "Google" : "Passkey"}: ${m.label}`;
      $("methods").append(li);
    }
    const sessions = await api("GET", "/v1/sessions");
    for (const s of sessions.sessions) {
      const li = document.createElement("li"), span = document.createElement("span"), end = document.createElement("button");
      span.textContent = `${s.platform === "web" ? "Browser" : s.platform === "ios" ? "iPhone" : "Android"}${s.device_model ? ` (${s.device_model})` : ""}${s.current ? ", this one" : ""}, last used ${new Date(s.last_used_at * 1000).toLocaleString()}`;
      end.textContent = s.current ? "Sign out" : "End";
      end.addEventListener("click", async () => { if (s.current) return signOut(); await api("DELETE", `/v1/sessions/${s.id}`); li.remove(); });
      li.append(span, end);
      $("sessions").append(li);
    }
    $("signout").addEventListener("click", signOut);

    // Approvals: the key log names the approvers; passkey approvers can sign here.
    let passkeys: { kid: string; credential_id: string }[] = [];
    if (me.owner_did) {
      const id = me.owner_did.split(":o:")[1];
      const [doc, log] = await Promise.all([api("GET", `/o/${id}/did.json`), fetch(`/o/${id}/log`).then((r) => r.text())]);
      const creds = new Map<string, any>();
      for (const line of log.trim().split("\n")) {
        const e = JSON.parse(line), b = e.body ?? {};
        for (const c of [b.root, b.approver, ...(b.approvers ?? [])]) if (c?.kid) creds.set(c.kid, c);
      }
      const current = (doc.assertionMethod ?? []).map((v: string) => creds.get(v.split("#")[1])).filter(Boolean);
      passkeys = current.filter((c: any) => c.type === "webauthn");
      for (const c of current) {
        const li = document.createElement("li");
        li.textContent = `${c.label ?? (c.type === "webauthn" ? "Passkey" : "Device")}${c.platform ? ` (${c.platform})` : ""}, key ${c.kid.slice(0, 8)}`;
        $("approvers").append(li);
      }
      show("approvals-on");
      if (me.backup_needed) show("backup");
    } else {
      show("approvals-off");
    }

    // Turn on approvals on the web: the root passkey, and a genesis entry it signs alone (PLAN 2.3, web-only owners).
    $("turn-on").addEventListener("click", async () => {
      try {
        const o = await api("POST", "/v1/auth/passkey/options", { mode: "register", client: web });
        const c = (await navigator.credentials.create({ publicKey: createOptions(o.options) })) as PublicKeyCredential;
        const reg = await api("POST", "/v1/auth/passkey/verify", { challenge_id: o.challenge_id, response: registrationJson(c), client: web });
        const unsigned = { v: 1, seq: 1, prev: null, op: "genesis", ts: Math.floor(Date.now() / 1000), body: { approver: null, root: reg.credential } };
        const a = await signWithPasskey(await sha256(jcs(unsigned)), [reg.credential.credential_id]);
        const line = jcs({ ...unsigned, auth: { kid: reg.credential.kid, form: "webauthn", signature: a.signature, authenticator_data: a.authenticator_data, client_data_json: a.client_data_json } });
        await api("POST", `/o/${base32(await sha256(line))}/log`, { line });
        location.reload();
      } catch (e) { say("approvals-error", message(e)); }
    });

    // Add a passkey approver: register it, offer it to the log, and wait while an approver checks the code and signs.
    $("add-approver").addEventListener("click", async () => {
      try {
        const o = await api("POST", "/v1/auth/passkey/options", { mode: "register", client: web });
        const c = (await navigator.credentials.create({ publicKey: createOptions(o.options) })) as PublicKeyCredential;
        const reg = await api("POST", "/v1/auth/passkey/verify", { challenge_id: o.challenge_id, response: registrationJson(c), client: web });
        const en = await api("POST", "/v1/keylog/enrollments", { purpose: "approver", credential: { ...reg.credential, label: "Passkey (web)" } });
        $("enroll-code").textContent = en.code;
        show("enroll");
        const poll = setInterval(async () => {
          const s = await api("GET", `/v1/keylog/enrollments/${en.enrollment_id}`).catch(() => null);
          if (!s || s.state === "pending") return;
          clearInterval(poll);
          say("enroll-state", s.state === "completed" ? "Added. This passkey can now approve." : s.state === "waiting" ? `Added through recovery: it takes effect ${new Date(s.effective_at * 1000).toLocaleString()} unless cancelled.` : "The code expired or was cancelled. Start again.");
          if (s.state === "completed") setTimeout(() => location.reload(), 1500);
        }, 2000);
      } catch (e) { say("approvals-error", message(e)); }
    });

    // Step-up on the web: an approval/2.0 over the request, signed by a passkey in the key log.
    const stepUp = async (action: string, params: object = {}) => {
      if (!passkeys.length) throw new Error("This needs a passkey approver. Use the OpenEntity app, or add a passkey approver here first.");
      const req = await api("POST", "/v1/step-up", { action, params });
      const digest = await sha256(["approval/2.0", req.verifier_did, req.owner_did, req.request_id, req.payload_digest, "approve", String(req.expires_at)].join("|"));
      const a = await signWithPasskey(digest, passkeys.map((p) => p.credential_id));
      const kid = passkeys.find((p) => p.credential_id === a.id)?.kid ?? "";
      const approval = { version: "approval/2.0", verifier_did: req.verifier_did, owner_did: req.owner_did, request_id: req.request_id, payload_digest: req.payload_digest, decision: "approve", expires_at: req.expires_at, device_id: kid, form: "webauthn", signature: a.signature, authenticator_data: a.authenticator_data, client_data_json: a.client_data_json };
      return { "x-oe-approval": b64u(new TextEncoder().encode(JSON.stringify(approval))) };
    };

    // Deletion: step-up with a key log, a fresh sign-in without one, or a 7-day request when no approver can sign here.
    if (me.deletion) {
      say("deletion-state", `Deletion requested. It happens ${new Date(me.deletion.effective_at * 1000).toLocaleString()} unless you cancel it.`);
      show("cancel-deletion");
    }
    if (me.owner_did) show("request-deletion");
    $("delete").addEventListener("click", async () => {
      if (!confirm("Delete your OpenEntity account? This cannot be undone.")) return;
      try {
        await api("POST", "/v1/account/delete", undefined, me.owner_did ? await stepUp("account.delete") : {});
        location.replace("/");
      } catch (e) { say("deletion-error", message(e)); }
    });
    $("request-deletion").addEventListener("click", async () => {
      try { await api("POST", "/v1/account/deletion-request", {}); location.reload(); } catch (e) { say("deletion-error", message(e)); }
    });
    $("cancel-deletion").addEventListener("click", async () => {
      try { await api("POST", "/v1/account/deletion-request/cancel", {}, await stepUp("deletion.cancel")); location.reload(); } catch (e) { say("deletion-error", message(e)); }
    });
  };

  (async () => {
    try {
      const r = await api("POST", "/v1/token", { grant_type: "refresh_token", audience: [cfg.serviceDid] });
      token = r.tokens[0].access_token;
    } catch { /* signed out */ }
    show("loading", false);
    await (token ? accountView() : signInView()).catch((e) => say("page-error", message(e)));
  })();
}
