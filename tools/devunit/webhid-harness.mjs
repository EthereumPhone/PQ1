// Run tools/devunit/pq1-fwupdate.html's own <script> under Node against a
// real PQ1 on Linux, with a minimal DOM and a WebHID shim over /dev/hidrawN.
// It exercises the page's exact package parsing, framing and install flow,
// which a browser test cannot drive past Chrome's device chooser.
//
//   node tools/devunit/webhid-harness.mjs <file.pq1fw>
//
// Exit 0 when the page reports "Done: the PQ1 runs <new version>".
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, "pq1-fwupdate.html"), "utf8");
const script = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"));
const pkgPath = process.argv[2];

// --- minimal DOM --------------------------------------------------------------
class El {
  constructor(id) {
    this.id = id; this.children = []; this.listeners = {}; this.style = {}; this.dataset = {};
    this.className = ""; this._text = ""; this._html = ""; this.disabled = false;
  }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  set textContent(v) {
    this._text = String(v);
    if (["run", "dev", "pkg"].includes(this.id)) console.log(`[${this.id}] ${v}`);
  }
  get textContent() { return this._text; }
  set innerHTML(v) {
    this._html = v;
    this.children = this.id === "dl" ? [new El("dt"), new El("dd"), new El("dt"), new El("dd")] : [];
  }
  get innerHTML() { return this._html; }
  appendChild(c) { this.children.push(c); return c; }
  async fire(t, ev) { for (const f of this.listeners[t] || []) await f(ev); }
}
const els = {};
globalThis.document = {
  getElementById: (id) => (els[id] ||= new El(id)),
  createElement: (tag) => new El(tag),
};

// --- WebHID shim over hidraw ------------------------------------------------------
function findHidraw() {
  for (const d of fs.readdirSync("/sys/class/hidraw")) {
    try {
      const u = fs.readFileSync(`/sys/class/hidraw/${d}/device/uevent`, "utf8").toUpperCase();
      if (u.includes("1209") && u.includes("7051")) return `/dev/${d}`;
    } catch {}
  }
  return null;
}
class ShimDevice {
  constructor(p) { this.path = p; this.vendorId = 0x1209; this.productId = 0x7051; this.opened = false; this.listeners = []; }
  async open() {
    // Non-blocking fd + polling: a blocking read parked in libuv's thread
    // pool would keep the process alive after the run is over.
    this.fd = fs.openSync(this.path, fs.constants.O_RDWR | fs.constants.O_NONBLOCK);
    this.opened = true;
    const b = Buffer.alloc(64);
    this.timer = setInterval(() => {
      for (;;) {
        let n;
        try { n = fs.readSync(this.fd, b, 0, 64, null); } catch (e) {
          if (e.code !== "EAGAIN") this.close();
          return;
        }
        if (n <= 0) return;
        const u8 = new Uint8Array(b.subarray(0, n));
        for (const l of this.listeners) l({ data: new DataView(u8.buffer, u8.byteOffset, u8.byteLength) });
      }
    }, 2);
  }
  async close() {
    if (!this.opened) return;
    this.opened = false;
    clearInterval(this.timer);
    try { fs.closeSync(this.fd); } catch {}
  }
  addEventListener(t, f) { if (t === "inputreport") this.listeners.push(f); }
  removeEventListener(t, f) { this.listeners = this.listeners.filter((x) => x !== f); }
  async sendReport(id, data) { fs.writeSync(this.fd, Buffer.concat([Buffer.from([id]), Buffer.from(data)])); }
}
let current = null;
function shim() {
  const p = findHidraw();
  if (!p) return [];
  if (!current || current.path !== p || !current.opened) current = new ShimDevice(p);
  return [current];
}
Object.defineProperty(globalThis, "navigator", {
  value: { hid: { requestDevice: async () => shim(), getDevices: async () => shim() } },
});

// --- run the page ----------------------------------------------------------------
(0, eval)(script);
const $ = (id) => els[id];
const data = fs.readFileSync(pkgPath);
const ab = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
await $("file").fire("change", { target: { files: [{ arrayBuffer: async () => ab }] } });
await $("connect").fire("click");
if ($("install").disabled) {
  console.error("install button disabled");
  process.exit(1);
}
const t0 = Date.now();
await $("install").fire("click");
console.log(`[harness] install flow finished in ${((Date.now() - t0) / 1000).toFixed(1)} s; bar ${$("bar").style.width}`);
if (current) await current.close();
process.exit($("run").textContent.startsWith("Done:") ? 0 : 1);
