"use strict";
let access = null, sessionId = null, subjectId = null, clearTimer, leaseTimer, revealGeneration = 0;
const element = (id) => document.getElementById(id);
const bytes = (value) => new TextEncoder().encode(value);
const b64 = (value) => btoa(String.fromCharCode(...new Uint8Array(value)));
async function pbkdf(key, salt, iterations) {
  const imported = await crypto.subtle.importKey("raw", key, "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({name: "PBKDF2", hash: "SHA-256", salt, iterations}, imported, 256);
}
async function api(path, body, method = body === undefined ? "GET" : "POST") {
  const response = await fetch(path, {method, cache: "no-store", headers: {"Content-Type": "application/json", ...(access ? {Authorization: `Bearer ${access}`} : {})}, body: body === undefined ? undefined : JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result.data === undefined ? result : result.data;
}
function clearReveal() { revealGeneration++; clearTimeout(clearTimer); element("reveal").textContent = ""; }
function button(text, action) { const node = document.createElement("button"); node.textContent = text; node.addEventListener("click", () => action().catch(showError)); return node; }
function showError(error) { element("status").textContent = error.message; }
function card(container, text) { const node = document.createElement("article"); const label = document.createElement("p"); label.textContent = text; node.append(label); container.append(node); return node; }
function renderLeases(leases) {
  clearTimeout(leaseTimer);
  element("leases").replaceChildren();
  let nextExpiry = Infinity;
  for (const lease of leases) {
    const expires = Date.parse(lease.expires_at);
    const status = lease.status === "active" && expires <= Date.now() ? "expired" : lease.status;
    const row = card(element("leases"), `${lease.mount_id} / ${lease.role_id}: ${status}, expires ${lease.expires_at}`);
    if (status === "active") {
      nextExpiry = Math.min(nextExpiry, expires);
      row.append(button("Revoke", async () => { await api(`/human/leases/${lease.id}`, undefined, "DELETE"); await refresh(); }));
      if (lease.renewable) row.append(button("Renew", async () => { const ttl = Number(prompt("New lifetime in seconds", "300")); await api(`/human/leases/${lease.id}/renew`, {requested_ttl: ttl}); await refresh(); }));
    }
  }
  if (Number.isFinite(nextExpiry)) leaseTimer = setTimeout(() => renderLeases(leases), Math.min(2_147_483_647, Math.max(0, nextExpiry - Date.now())));
}
async function refresh() {
  clearReveal();
  const [capabilities, leases, approvals] = await Promise.all([api("/human/capabilities"), api("/human/leases"), api("/human/approvals")]);
  for (const id of ["capabilities", "leases", "approvals"]) element(id).replaceChildren();
  for (const capability of capabilities) {
    const row = card(element("capabilities"), `${capability.mount_id} / ${capability.role_id} (maximum ${capability.max_ttl}s)`);
    row.append(button(capability.require_approval ? "Request approval" : "Request credential", async () => {
      const ttl = Number(prompt("Lifetime in seconds", Math.min(900, capability.max_ttl)));
      if (!Number.isInteger(ttl) || ttl < 1 || ttl > capability.max_ttl) throw new Error("Invalid lifetime");
      const reference = await api("/human/dynamic/references", {mount_id: capability.mount_id, role_id: capability.role_id, requested_ttl: ttl});
      const request = {request_id: crypto.randomUUID()};
      if (capability.require_approval) { await api(`/human/dynamic/references/${reference.id}/approval`, request); await refresh(); }
      else { const issued = await api(`/human/dynamic/references/${reference.id}/request`, request); await showReveal(issued); }
    }));
  }
  renderLeases(leases);
  for (const approval of approvals) {
    const row = card(element("approvals"), `${approval.mount_id} / ${approval.role_id}: ${approval.status}, expires ${approval.expires_at}`);
    if (approval.status === "pending" && approval.subject_id !== subjectId) for (const action of ["approve", "deny"]) row.append(button(action, async () => { await api(`/human/approvals/${approval.id}/${action}`, {}); await refresh(); }));
    if (approval.status === "approved" && approval.subject_id === subjectId && approval.session_id === sessionId) row.append(button("Issue approved request", async () => {
      const reference = await api("/human/dynamic/references", {mount_id: approval.mount_id, role_id: approval.role_id, requested_ttl: approval.requested_ttl});
      const issued = await api(`/human/dynamic/references/${reference.id}/request`, {request_id: approval.request_id, approval_id: approval.id});
      await showReveal(issued);
    }));
  }
}
async function showReveal(issued) {
  const pendingRefresh = refresh(), generation = revealGeneration, sessionAccess = access;
  await pendingRefresh;
  if (generation !== revealGeneration || sessionAccess !== access) return;
  const revealed = await api("/human/dynamic/reveal", {token: issued.reveal_token});
  if (generation !== revealGeneration || sessionAccess !== access) return;
  element("reveal").textContent = JSON.stringify(revealed.credentials, null, 2);
  clearTimer = setTimeout(clearReveal, 30000);
}
element("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = element("email").value.trim().toLowerCase(); let password = element("password").value; element("password").value = "";
  try {
    const kdf = await api("/api/accounts/prelogin", {email});
    if (kdf.kdf !== 0) throw new Error("Unsupported key derivation");
    const master = await pbkdf(bytes(password), bytes(email), kdf.kdfIterations);
    const verifier = b64(await pbkdf(master, bytes(password), 1)); password = null;
    let device = localStorage.getItem("secrethub-human-device");
    if (!device) { device = crypto.randomUUID(); localStorage.setItem("secrethub-human-device", device); }
    const result = await api("/identity/connect/token", {grant_type: "password", username: email, password: verifier, deviceIdentifier: device, deviceName: "Human web", deviceType: 10});
    access = result.access_token;
    const claims = JSON.parse(atob(access.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); sessionId = claims.sid; subjectId = claims.sub;
    element("login").hidden = true; element("workspace").hidden = false; element("status").textContent = "Signed in"; await refresh();
  } catch (error) { password = null; showError(error); }
});
element("refresh").addEventListener("click", () => refresh().catch(showError));
element("clear").addEventListener("click", clearReveal);
element("logout").addEventListener("click", async () => { try { if (access) await api(`/human/sessions/${sessionId}`, undefined, "DELETE"); } finally { access = null; sessionId = null; subjectId = null; clearReveal(); clearTimeout(leaseTimer); element("workspace").hidden = true; element("login").hidden = false; element("status").textContent = "Signed out"; } });
window.addEventListener("pagehide", () => { clearReveal(); clearTimeout(leaseTimer); });
