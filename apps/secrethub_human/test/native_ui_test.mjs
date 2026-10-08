import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";

function browser(leases, fetchOverride) {
  class Node {
    children = [];
    listeners = {};
    textContent = "";
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    addEventListener(event, callback) { this.listeners[event] = callback; }
  }
  const elements = new Map();
  const timers = new Map();
  const windowListeners = new Map();
  let now = 1_000;
  let timerId = 0;
  class Clock extends Date { static now() { return now; } }
  const context = vm.createContext({
    document: {getElementById(id) { if (!elements.has(id)) elements.set(id, new Node()); return elements.get(id); }, createElement() { return new Node(); }},
    window: {addEventListener(event, callback) { windowListeners.set(event, callback); }}, Date: Clock, TextEncoder,
    async fetch(path) { if (fetchOverride) { const response = fetchOverride(path); if (response) return response; } return {ok: true, async json() { return {data: path === "/human/leases" ? leases : []}; }}; },
    setTimeout(callback, delay) { timers.set(++timerId, {callback, delay}); return timerId; },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(readFileSync(new URL("../priv/static/human.js", import.meta.url), "utf8"), context);
  return {context, elements, timers, windowListeners, advance(value) { now = value; }};
}

test("native lease expires and removes renewal actions without a refresh request", async () => {
  const lease = {id: "lease", mount_id: "postgres", role_id: "reader", status: "active", renewable: true, expires_at: new Date(2_000).toISOString()};
  const page = browser([lease]);
  await page.context.refresh();
  let [row] = page.elements.get("leases").children;
  assert.match(row.children[0].textContent, /active/);
  assert.deepEqual(row.children.slice(1).map(node => node.textContent), ["Revoke", "Renew"]);
  assert.equal(page.timers.size, 1);
  const [{callback, delay}] = page.timers.values();
  assert.equal(delay, 1_000);
  page.advance(2_000);
  callback();
  [row] = page.elements.get("leases").children;
  assert.match(row.children[0].textContent, /expired/);
  assert.equal(row.children.length, 1);
  assert.equal(page.timers.size, 0);
});

test("elapsed lease is expired on initial render and revoked lease stays revoked", async () => {
  const page = browser([
    {status: "active", renewable: true, expires_at: new Date(999).toISOString()},
    {status: "revoked", renewable: true, expires_at: new Date(999).toISOString()},
  ]);
  await page.context.refresh();
  const [expired, revoked] = page.elements.get("leases").children;
  assert.match(expired.children[0].textContent, /expired/);
  assert.match(revoked.children[0].textContent, /revoked/);
  assert.equal(expired.children.length, 1);
  assert.equal(revoked.children.length, 1);
  assert.equal(page.timers.size, 0);
});

for (const exit of ["logout", "clear", "pagehide"]) {
  test(`pending reveal cannot restore credentials after ${exit}`, async () => {
    let resolveReveal, revealStarted;
    const started = new Promise(resolve => { revealStarted = resolve; });
    const pending = new Promise(resolve => { resolveReveal = resolve; });
    const page = browser([], path => {
      if (path === "/human/dynamic/reveal") { revealStarted(); return pending; }
    });
    vm.runInContext('access = "session-token"; sessionId = "session";', page.context);
    const reveal = page.context.showReveal({reveal_token: "one-use-token"});
    await started;
    if (exit === "pagehide") page.windowListeners.get("pagehide")();
    else await page.elements.get(exit).listeners.click();
    assert.equal(page.elements.get("reveal").textContent, "");
    resolveReveal({ok: true, async json() { return {data: {credentials: {password: "late-secret"}}}; }});
    await reveal;
    assert.equal(page.elements.get("reveal").textContent, "");
    assert.equal(page.timers.size, 0);
  });
}

test("current reveal renders credentials and clears them on timeout", async () => {
  const page = browser([], path => path === "/human/dynamic/reveal" ?
    {ok: true, async json() { return {data: {credentials: {password: "current-secret"}}}; }} : undefined);
  vm.runInContext('access = "session-token";', page.context);
  await page.context.showReveal({reveal_token: "one-use-token"});
  assert.match(page.elements.get("reveal").textContent, /current-secret/);
  const [{callback, delay}] = page.timers.values();
  assert.equal(delay, 30_000);
  callback();
  assert.equal(page.elements.get("reveal").textContent, "");
  assert.equal(page.timers.size, 0);
});
