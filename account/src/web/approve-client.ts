// Browser code for /approve, serialized by page.ts: it may use only its own locals and browser globals.
export function approveClient(cfg: { products: Record<string, string> }) {
  const $ = (id: string) => document.getElementById(id) as HTMLElement;
  const b64u = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const bytes = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (ch) => ch.charCodeAt(0));
  const show = (id: string) => { for (const s of ["loading", "error", "request", "done"]) $(s).hidden = s !== id; };
  const stop = (text: string) => { $("error-text").textContent = text; show("error"); };
  const messages: Record<string, string> = {
    envelope_expired: "This request expired. Start again from the product.",
    unknown_verifier: "This request does not come from a product that uses OpenEntity approvals.",
    owner_unknown: "This OpenEntity account does not exist or was deleted.",
  };

  (async () => {
    const request = new URLSearchParams(location.hash.slice(1)).get("request");
    if (!request) return stop("This link has no approval request. Open it again from the product.");
    let v: any;
    try {
      const r = await fetch("/v1/approve/check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request }) });
      v = await r.json();
      if (!r.ok) return stop(messages[v.error] ?? v.message ?? "The request could not be checked.");
    } catch {
      return stop("The request could not be checked. Check your connection and try again.");
    }

    $("title").textContent = `${cfg.products[v.verifier_did] ?? v.verifier_did} asks for your approval`;
    for (const [k, val] of Object.entries(v.payload as Record<string, unknown>)) {
      const dt = document.createElement("dt"), dd = document.createElement("dd");
      dt.textContent = k.replace(/_/g, " ");
      dd.textContent = typeof val === "string" ? val : JSON.stringify(val);
      $("summary").append(dt, dd);
    }
    $("request-id").textContent = v.request_id;
    $("verifier").textContent = v.verifier_did;
    $("no-passkey").hidden = v.allow_credentials.length > 0;

    const buttons = [$("approve"), $("deny")] as HTMLButtonElement[];
    let busy = false;
    const tick = () => {
      const left = v.expires_at - Math.floor(Date.now() / 1000);
      $("expiry").textContent = left > 0 ? `Expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}.` : "Expired. Start again from the product.";
      for (const b of buttons) b.disabled = busy || left <= 0 || !v.allow_credentials.length;
    };
    tick();
    setInterval(tick, 1000);

    // The decision goes back as a form POST (ApproveReturnForm), so the product receives it on its own origin.
    const back = (fields: Record<string, string>) => {
      const f = document.createElement("form");
      f.method = "post";
      f.action = v.return_url;
      const all: Record<string, string> = { ...fields, request_id: v.request_id };
      if (typeof v.state === "string") all.state = v.state;
      for (const [name, value] of Object.entries(all)) {
        const i = document.createElement("input");
        i.type = "hidden";
        i.name = name;
        i.value = value;
        f.append(i);
      }
      document.body.append(f);
      show("done");
      f.submit();
    };

    const decide = async (decision: "approve" | "deny") => {
      busy = true;
      tick();
      $("decide-error").hidden = true;
      try {
        const cred = (await navigator.credentials.get({
          publicKey: {
            challenge: bytes(v.challenges[decision]),
            rpId: v.rp_id,
            allowCredentials: v.allow_credentials.map((id: string) => ({ type: "public-key", id: bytes(id) })),
            userVerification: "required",
            timeout: 120_000,
          },
        })) as PublicKeyCredential | null;
        const device = cred && v.kids[cred.id];
        if (!cred || !device) throw new Error("This passkey is not an approver on this account.");
        const a = cred.response as AuthenticatorAssertionResponse;
        back({
          approval: JSON.stringify({
            version: "approval/2.0", verifier_did: v.verifier_did, owner_did: v.owner_did, request_id: v.request_id,
            payload_digest: v.payload_digest, decision, expires_at: v.expires_at, device_id: device, form: "webauthn",
            signature: b64u(a.signature), authenticator_data: b64u(a.authenticatorData), client_data_json: b64u(a.clientDataJSON),
          }),
        });
      } catch (e) {
        $("decide-error").textContent = (e as DOMException).name === "NotAllowedError" ? "The passkey prompt was closed or timed out. Try again." : (e as Error).message;
        $("decide-error").hidden = false;
        busy = false;
        tick();
      }
    };
    $("approve").addEventListener("click", () => decide("approve"));
    $("deny").addEventListener("click", () => decide("deny"));
    $("cancel").addEventListener("click", () => back({ error: "cancelled" }));
    show("request");
  })();
}
