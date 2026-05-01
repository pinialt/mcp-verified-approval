// Phase-1 step-5 end-to-end browser harness.
// Drives the running Vite client at :5173 via CDP on :9224 to exercise
// (a) approve, (b) cancel-button decline, (c) escape-key decline.

const CDP_BASE = "http://localhost:9224";
const PAGE_URL = "http://localhost:5173/";

const tabs = await fetch(`${CDP_BASE}/json`).then((r) => r.json());
let target = tabs.find((t) => t.type === "page");
if (!target) {
  const created = await fetch(`${CDP_BASE}/json/new?about:blank`, { method: "PUT" }).then((r) =>
    r.json(),
  );
  target = created;
}

const ws = new WebSocket(target.webSocketDebuggerUrl);
const pending = new Map();
const events = [];
let id = 0;
ws.addEventListener("message", (e) => {
  const m = JSON.parse(e.data);
  if (m.id !== undefined && pending.has(m.id)) {
    pending.get(m.id).resolve(m);
    pending.delete(m.id);
  } else if (m.method) {
    events.push(m);
  }
});
await new Promise((r) => ws.addEventListener("open", r));
function send(method, params = {}) {
  return new Promise((resolve) => {
    const reqId = ++id;
    pending.set(reqId, { resolve });
    ws.send(JSON.stringify({ id: reqId, method, params }));
  });
}
async function evalJS(expr) {
  const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) {
    throw new Error("page exception: " + r.result.exceptionDetails.text);
  }
  return r.result?.result?.value;
}
async function dispatchKey(text) {
  // Dispatches a key event via CDP — for Escape, the key + windowsVirtualKeyCode + nativeVirtualKeyCode.
  await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 });
  await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 });
}

await send("Page.enable");
await send("Page.navigate", { url: PAGE_URL });
// wait for initial render + connect
await new Promise((r) => setTimeout(r, 1500));

console.log("=== initial UI state ===");
console.log("status:", await evalJS(`document.querySelector("#status").innerText`));
console.log("tools:", await evalJS(`document.querySelector("#tools").innerText`));
console.log("submit disabled:", await evalJS(`document.querySelector("#submit").disabled`));

async function fillAndSubmit({ symbol, qty, limit, side = "buy" }) {
  await evalJS(`document.querySelector("input[name=symbol]").value = ${JSON.stringify(symbol)}`);
  await evalJS(`document.querySelector("select[name=side]").value = ${JSON.stringify(side)}`);
  await evalJS(`document.querySelector("input[name=quantity]").value = ${JSON.stringify(String(qty))}`);
  await evalJS(`document.querySelector("input[name=limit]").value = ${JSON.stringify(String(limit))}`);
  await evalJS(`document.querySelector("#submit").click()`);
}

async function dialogOpen() {
  return await evalJS(`document.querySelector("#approval-dialog").open`);
}

async function dialogText() {
  return await evalJS(`document.querySelector("#approval-display-text").innerText`);
}

// ---------------- (a) APPROVE PATH ----------------
console.log("\n=== (a) approve path ===");
await fillAndSubmit({ symbol: "GOOG", qty: 7, limit: 2780, side: "buy" });
await new Promise((r) => setTimeout(r, 400));
console.log("dialog open:", await dialogOpen());
console.log("dialog text:", await dialogText());
await evalJS(`document.querySelector("#approval-approve").click()`);
await new Promise((r) => setTimeout(r, 600));
console.log("dialog open after approve:", await dialogOpen());
console.log("trades-list:", await evalJS(`document.querySelector("#trades").innerText`));
const tradesAfterApprove = await fetch("http://localhost:3030/trades").then((r) => r.json());
console.log("server /trades count:", tradesAfterApprove.length);
console.log("server last trade.symbol:", tradesAfterApprove[tradesAfterApprove.length - 1]?.symbol);

// ---------------- (b) CANCEL-BUTTON PATH ----------------
console.log("\n=== (b) cancel path ===");
await fillAndSubmit({ symbol: "TSLA", qty: 3, limit: 250, side: "sell" });
await new Promise((r) => setTimeout(r, 400));
console.log("dialog open:", await dialogOpen());
console.log("dialog text:", await dialogText());
await evalJS(`document.querySelector("#approval-cancel").click()`);
await new Promise((r) => setTimeout(r, 400));
console.log("dialog open after cancel:", await dialogOpen());
const tradesAfterCancel = await fetch("http://localhost:3030/trades").then((r) => r.json());
console.log("server /trades count (should equal previous):", tradesAfterCancel.length);

// ---------------- (c) ESCAPE PATH ----------------
console.log("\n=== (c) escape path ===");
await fillAndSubmit({ symbol: "NVDA", qty: 2, limit: 950, side: "buy" });
await new Promise((r) => setTimeout(r, 400));
console.log("dialog open:", await dialogOpen());
await dispatchKey("Escape");
await new Promise((r) => setTimeout(r, 400));
console.log("dialog open after escape:", await dialogOpen());
const tradesAfterEscape = await fetch("http://localhost:3030/trades").then((r) => r.json());
console.log("server /trades count (should equal previous):", tradesAfterEscape.length);

// ---------------- final log ----------------
console.log("\n=== final UI log ===");
console.log(await evalJS(`document.querySelector("#log").innerText`));

ws.close();
