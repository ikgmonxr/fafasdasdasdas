/* QyrexObf v4 — real Lua lexer (strings/comments-aware) */
const KW = new Set([
  "and","break","do","else","elseif","end","false","for","function","goto",
  "if","in","local","nil","not","or","repeat","return","then","true","until","while",
]);

function lex(src) {
  const toks = [];
  let i = 0;
  const n = src.length;
  const isSpace = (c) => c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v";
  const isDigit = (c) => c >= "0" && c <= "9";
  const isHex = (c) => isDigit(c) || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
  const isIdStart = (c) => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || c === "_";
  const isIdCont = (c) => isIdStart(c) || isDigit(c);

  while (i < n) {
    const c = src[i];

    if (isSpace(c)) {
      let j = i;
      while (j < n && isSpace(src[j])) j++;
      toks.push({ type: "ws", val: src.slice(i, j) });
      i = j;
      continue;
    }

    if (c === "-" && src[i + 1] === "-") {
      if (src[i + 2] === "[") {
        let k = i + 3, eq = 0;
        while (src[k] === "=") { eq++; k++; }
        if (src[k] === "[") {
          const close = "]" + "=".repeat(eq) + "]";
          const end = src.indexOf(close, k + 1);
          const stop = end === -1 ? n : end + close.length;
          toks.push({ type: "lcomment", val: src.slice(i, stop) });
          i = stop;
          continue;
        }
      }
      let j = i;
      while (j < n && src[j] !== "\n") j++;
      toks.push({ type: "comment", val: src.slice(i, j) });
      i = j;
      continue;
    }

    if (c === "'" || c === '"') {
      const q = c;
      let j = i + 1;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === q) { j++; break; }
        j++;
      }
      toks.push({ type: "string", val: src.slice(i, j) });
      i = j;
      continue;
    }

    if (c === "[") {
      let k = i + 1, eq = 0;
      while (src[k] === "=") { eq++; k++; }
      if (src[k] === "[") {
        const close = "]" + "=".repeat(eq) + "]";
        const end = src.indexOf(close, k + 1);
        const stop = end === -1 ? n : end + close.length;
        toks.push({ type: "lstring", val: src.slice(i, stop) });
        i = stop;
        continue;
      }
    }

    if (isDigit(c) || (c === "." && isDigit(src[i + 1] || ""))) {
      let j = i;
      if (c === "0" && (src[i + 1] === "x" || src[i + 1] === "X")) {
        j += 2;
        while (j < n && isHex(src[j])) j++;
      } else {
        while (j < n && isDigit(src[j])) j++;
        if (src[j] === ".") { j++; while (j < n && isDigit(src[j])) j++; }
        if (src[j] === "e" || src[j] === "E") {
          j++;
          if (src[j] === "+" || src[j] === "-") j++;
          while (j < n && isDigit(src[j])) j++;
        }
      }
      toks.push({ type: "num", val: src.slice(i, j) });
      i = j;
      continue;
    }

    if (isIdStart(c)) {
      let j = i + 1;
      while (j < n && isIdCont(src[j])) j++;
      const v = src.slice(i, j);
      toks.push({ type: KW.has(v) ? "kw" : "ident", val: v });
      i = j;
      continue;
    }

    const two = src.slice(i, i + 2);
    if (["==", "~=", "<=", ">=", "..", "::"].includes(two)) {
      toks.push({ type: "sym", val: two });
      i += 2;
      continue;
    }
    if (src.slice(i, i + 3) === "...") {
      toks.push({ type: "sym", val: "..." });
      i += 3;
      continue;
    }

    toks.push({ type: "sym", val: c });
    i++;
  }
  return toks;
}

function decodeLuaString(literal) {
  if (literal.startsWith("[")) {
    const m = /^\[(=*)\[/.exec(literal);
    if (!m) return null;
    const eq = m[1].length;
    let body = literal.slice(2 + eq, literal.length - 2 - eq);
    if (body.startsWith("\n")) body = body.slice(1);
    else if (body.startsWith("\r\n")) body = body.slice(2);
    const bytes = [];
    for (let i = 0; i < body.length; i++) {
      const code = body.charCodeAt(i);
      if (code > 0xff) return null;
      bytes.push(code);
    }
    return bytes;
  }
  const q = literal[0];
  if (q !== "'" && q !== '"') return null;
  const s = literal.slice(1, -1);
  const out = [];
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (ch !== "\\") {
      const code = ch.charCodeAt(0);
      if (code > 0xff) return null;
      out.push(code);
      i++;
      continue;
    }
    const nx = s[i + 1];
    if (nx === undefined) return null;
    const map = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, "\\": 92, '"': 34, "'": 39, "\n": 10 };
    if (map[nx] !== undefined) { out.push(map[nx]); i += 2; continue; }
    if (nx === "x") {
      const hex = s.slice(i + 2, i + 4);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) return null;
      out.push(parseInt(hex, 16));
      i += 4;
      continue;
    }
    if (nx >= "0" && nx <= "9") {
      let j = i + 1, num = "";
      while (j < s.length && num.length < 3 && s[j] >= "0" && s[j] <= "9") { num += s[j]; j++; }
      const v = parseInt(num, 10);
      if (v > 255) return null;
      out.push(v);
      i = j;
      continue;
    }
    return null;
  }
  return out;
}

const R = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

function makeIdFactory(prefix = "_v") {
  const used = new Set();
  return () => {
    for (;;) {
      const chars = "IlOo";
      let s = prefix;
      for (let i = 0; i < 8; i++) s += chars[R(0, 3)];
      s += R(100, 9999).toString();
      if (!used.has(s)) { used.add(s); return s; }
    }
  };
}

function encryptStrings(toks, sName) {
  const pool = [];
  const key = R(37, 211);
  const out = toks.map((t) => {
    if (t.type !== "string" && t.type !== "lstring") return t;
    const bytes = decodeLuaString(t.val);
    if (!bytes || bytes.length === 0 || bytes.length > 4096) return t;
    if (!bytes.some((b) => (b >= 65 && b <= 90) || (b >= 97 && b <= 122))) return t;
    const idx = pool.length;
    pool.push(bytes.map((b, i) => b ^ key ^ ((i * 7) % 251)));
    return { type: "ident", val: `${sName}[${idx}]` };
  });
  if (!pool.length) return { toks, header: null };

  // pure Lua XOR decoder (no bit32)
  const header = [
    `local ${sName}; do`,
    ` local __k=${key}`,
    ` local __p={${pool.map((arr) => "{" + arr.join(",") + "}").join(",")}}`,
    ` local __o={}`,
    ` for i=1,#__p do`,
    `  local t=__p[i] local r={}`,
    `  for j=1,#t do`,
    `   local x=t[j] local y=__k local z=((j-1)*7)%251`,
    `   local a,b,c=x,y,z local o=0 local p=1`,
    `   for _=1,8 do`,
    `    local bx=a%2 local by=b%2 local bz=c%2`,
    `    local rbit=((bx+by+bz)%2)`,
    `    o=o+rbit*p`,
    `    a=(a-bx)/2; b=(b-by)/2; c=(c-bz)/2; p=p*2`,
    `   end`,
    `   r[j]=string.char(o)`,
    `  end`,
    `  __o[i-1]=table.concat(r)`,
    ` end`,
    ` ${sName}=__o`,
    `end`,
  ].join("\n") + "\n";
  return { toks: out, header };
}

function numbersToExpr(toks) {
  return toks.map((t) => {
    if (t.type !== "num") return t;
    if (!/^\d+$/.test(t.val)) return t;
    const v = parseInt(t.val, 10);
    if (v < 12 || v > 50000 || Math.random() > 0.55) return t;
    const a = R(1, v - 1);
    return { type: "sym", val: `(${a}+${v - a})` };
  });
}

function renameLocals(toks) {
  const nextId = makeIdFactory("_l");
  const scopes = [new Map()];
  const out = [];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.type === "kw" && (t.val === "function" || t.val === "do" || t.val === "then" || t.val === "repeat")) {
      scopes.push(new Map());
      out.push(t);
      continue;
    }
    if (t.type === "kw" && t.val === "end") {
      if (scopes.length > 1) scopes.pop();
      out.push(t);
      continue;
    }
    if (t.type === "kw" && t.val === "local") {
      out.push(t);
      // rename following idents until = or function or newline-ish end of local stmt
      let j = i + 1;
      while (j < toks.length && toks[j].type === "ws") { out.push(toks[j]); j++; }
      if (j < toks.length && toks[j].type === "kw" && toks[j].val === "function") {
        // local function name
        out.push(toks[j]); j++;
        while (j < toks.length && toks[j].type === "ws") { out.push(toks[j]); j++; }
        if (j < toks.length && toks[j].type === "ident") {
          const name = toks[j].val;
          const neu = nextId();
          scopes[scopes.length - 1].set(name, neu);
          out.push({ type: "ident", val: neu });
          j++;
        }
        i = j - 1;
        continue;
      }
      while (j < toks.length) {
        const tj = toks[j];
        if (tj.type === "ident") {
          const neu = nextId();
          scopes[scopes.length - 1].set(tj.val, neu);
          out.push({ type: "ident", val: neu });
          j++;
          continue;
        }
        if (tj.type === "ws" || tj.val === "," || tj.val === "=") {
          out.push(tj);
          if (tj.val === "=") { j++; break; }
          j++;
          continue;
        }
        break;
      }
      i = j - 1;
      continue;
    }
    if (t.type === "ident") {
      let mapped = null;
      for (let s = scopes.length - 1; s >= 0; s--) {
        if (scopes[s].has(t.val)) { mapped = scopes[s].get(t.val); break; }
      }
      out.push(mapped ? { type: "ident", val: mapped } : t);
      continue;
    }
    out.push(t);
  }
  return out;
}

function stringifyTokens(toks) {
  return toks.map((t) => t.val).join("");
}

function antiTamper() {
  return `do
 local function __d(r) error(tostring(r or "blocked"), 0) end
 local rg,pc,ty = rawget, pcall, type
 for _,k in ipairs({"lune","lute","wally","rojo","selene","darklua","lemur","fetch","console","window","document","navigator","__dirname","localStorage"}) do
  if rg(_G,k) ~= nil then __d("sb") end
 end
 if ty(process) == "table" then __d("sb") end
 if getfenv and ty(getfenv) ~= "function" then __d("gf") end
 for _,k in ipairs({"fenv","hookenv","scriptenv"}) do if rg(_G,k) ~= nil then __d("lk") end end
 for _,n in ipairs({"print","loadstring","setmetatable","pcall"}) do
  local f = rg(_G, n)
  if f ~= nil and ty(f) ~= "function" then __d("hk") end
 end
 if getgenv and debug and debug.getinfo then
  local h = getgenv()
  local mt = getmetatable(h)
  if mt and (mt.__index or mt.__newindex) then __d("gv") end
 end
 if not game or not typeof or game.ClassName ~= "DataModel" then __d("rb") end
 if not pc(function() local p = Instance.new("Part"); p:Destroy() end) then __d("in") end
end`;
}

function junk() {
  const a = makeIdFactory("_j")();
  const b = makeIdFactory("_j")();
  const n = R(100, 9000);
  return `do local ${a}=${n} local ${b}=${a}-${a} if ${b}~=0 then return end end`;
}

function wrap(code) {
  const n = makeIdFactory("_w")();
  return `local function ${n}(...)\n${code}\nend\nreturn ${n}(...)`;
}

function controlFlow(code) {
  const k = R(1000, 9999);
  return `do local __cf=${k}\nif __cf==${k} then\n${code}\nelse while true do end end\nend`;
}

function obfuscate(source, opts = {}) {
  const src = String(source || "");
  if (!src.trim()) throw new Error("Empty code");
  if (src.length > 800000) throw new Error("Too large (max 800KB)");

  const O = {
    antiTamper: opts.antiTamper !== false,
    strings: opts.strings !== false,
    numbers: opts.numbers !== false,
    renameLocals: opts.renameLocals !== false,
    controlFlow: opts.controlFlow !== false,
    junk: opts.junk !== false,
  };

  let toks = lex(src);
  const beforeStr = toks.filter((t) => t.type === "string" || t.type === "lstring").length;
  const beforeNum = toks.filter((t) => t.type === "num").length;

  const sName = "_S" + R(100, 999);
  let stringsHeader = null;
  if (O.strings) {
    const r = encryptStrings(toks, sName);
    toks = r.toks;
    stringsHeader = r.header;
  }
  if (O.numbers) toks = numbersToExpr(toks);

  let localsRenamed = 0;
  if (O.renameLocals) {
    toks = renameLocals(toks);
    localsRenamed = toks.filter((t) => t.type === "ident" && t.val.startsWith("_l")).length;
  }

  let code = stringifyTokens(toks);
  if (stringsHeader) code = stringsHeader + code;

  let out = "";
  if (O.antiTamper) out += antiTamper() + "\n";
  const body = O.controlFlow ? controlFlow(wrap(code)) : code;
  out += (O.junk ? junk() + "\n" : "") + body + (O.junk ? "\n" + junk() : "");

  return {
    code: "-- Protect by QyrexObf v4\n" + out,
    stats: {
      inputBytes: src.length,
      outputBytes: out.length,
      stringsEncrypted: stringsHeader ? Math.max(0, beforeStr - toks.filter((t) => t.type === "string" || t.type === "lstring").length) : 0,
      localsRenamed,
      numbersMutated: O.numbers ? Math.max(0, beforeNum - toks.filter((t) => t.type === "num").length) : 0,
    },
  };
}

module.exports = { obfuscate };
