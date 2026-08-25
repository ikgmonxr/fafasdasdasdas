const express = require("express");
const cors = require("cors");
const path = require("path");
const { obfuscate } = require("./obfuscate");

const app = express();
const PORT = process.env.PORT || 10000;
app.use(cors({ origin: true }));
app.use(express.json({ limit: "2mb" }));

app.get("/api/health", (req, res) => res.json({ ok: true, service: "QyrexObf", version: "9.0.0" }));

app.post("/api/obfuscate", (req, res) => {
  try {
    const code = (req.body && (req.body.code || req.body.source)) || "";
    const candidate = req.body && req.body.options;
    const opts = candidate && typeof candidate === "object" && !Array.isArray(candidate) ? { ...candidate } : {};
    if (req.body && req.body.antiTamper === false) opts.antiTamper = false;
    if (!String(code).trim()) return res.status(400).json({ success: false, error: "code required" });
    const result = obfuscate(code, opts);
    const outCode = (result && result.code) ? result.code : String(result || "");
    res.json({ success: true, code: outCode, stats: (result && result.stats) || null, brand: "QyrexObf v9" });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message || "fail" });
  }
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.listen(PORT, "0.0.0.0", () => console.log("QyrexObf v9 on", PORT));
