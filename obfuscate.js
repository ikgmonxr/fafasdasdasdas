/* QyrexObf v9 — returns { code, stats } */
const crypto = require("crypto");
const KW = new Set(["and","break","do","else","elseif","end","false","for","function","goto","if","in","local","nil","not","or","repeat","return","then","true","until","while"]);
const R = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
// Do not truncate values here.  The previous byte mask made numeric expressions
// above 255 evaluate to a different value than the original source.
const H = (n) => "0x" + (Number(n) >>> 0).toString(16);

function makeIdFactory() {
  const chars = "Il1O0abcdefghijklmnopqrstuvwxyz";
  const used = new Set();
  return function next() {
    for (;;) {
      let id = "_";
      for (let i = 0; i < R(10, 18); i++) id += chars[R(0, chars.length - 1)];
      id += R(10, 99);
      if (!used.has(id)) { used.add(id); return id; }
    }
  };
}

function lex(src) {
  const toks = [];
  let i = 0;
  const n = src.length;
  const isDigit = (c) => c >= "0" && c <= "9";
  const isHex = (c) => isDigit(c) || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
  const isIdStart = (c) => /[A-Za-z_]/.test(c);
  const isIdCont = (c) => /[A-Za-z0-9_]/.test(c);
  while (i < n) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "-" && src[i + 1] === "-") { i += 2; while (i < n && src[i] !== "\n") i++; continue; }
    if (c === "'" || c === '"') {
      const q = c; let j = i + 1;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === q) { j++; break; }
        j++;
      }
      toks.push({ type: "str", val: src.slice(i, j) }); i = j; continue;
    }
    if (c === "[") {
      let k = i + 1, eq = 0;
      while (src[k] === "=") { eq++; k++; }
      if (src[k] === "[") {
        const close = "]" + "=".repeat(eq) + "]";
        const end = src.indexOf(close, k + 1);
        const stop = end === -1 ? n : end + close.length;
        toks.push({ type: "str", val: src.slice(i, stop) }); i = stop; continue;
      }
    }
    if (isDigit(c) || (c === "." && isDigit(src[i + 1] || ""))) {
      let j = i;
      if (c === "0" && (src[i + 1] === "x" || src[i + 1] === "X")) {
        j += 2; while (j < n && isHex(src[j])) j++;
      } else {
        while (j < n && isDigit(src[j])) j++;
        if (src[j] === ".") { j++; while (j < n && isDigit(src[j])) j++; }
        if (src[j] === "e" || src[j] === "E") {
          j++; if (src[j] === "+" || src[j] === "-") j++;
          while (j < n && isDigit(src[j])) j++;
        }
      }
      toks.push({ type: "num", val: src.slice(i, j) }); i = j; continue;
    }
    if (isIdStart(c)) {
      let j = i + 1; while (j < n && isIdCont(src[j])) j++;
      const v = src.slice(i, j);
      toks.push({ type: KW.has(v) ? "kw" : "id", val: v }); i = j; continue;
    }
    const two = src.slice(i, i + 2);
    if (["==", "~=", "<=", ">=", "..", "::"].includes(two)) { toks.push({ type: "sy", val: two }); i += 2; continue; }
    if (src.slice(i, i + 3) === "...") { toks.push({ type: "sy", val: "..." }); i += 3; continue; }
    toks.push({ type: "sy", val: c }); i++;
  }
  return toks;
}

function decodeLuaString(literal) {
  if (!literal) return null;
  if (literal.startsWith("[")) {
    const m = /^\[(=*)\[/.exec(literal);
    if (!m) return null;
    const eq = m[1].length;
    let body = literal.slice(2 + eq, literal.length - 2 - eq);
    if (body.startsWith("\n")) body = body.slice(1);
    const bytes = [];
    for (let i = 0; i < body.length; i++) {
      const code = body.charCodeAt(i);
      if (code > 255) return null;
      bytes.push(code);
    }
    return bytes;
  }
  const q = literal[0];
  if (q !== "'" && q !== '"') return null;
  const s = literal.slice(1, -1);
  const out = []; let i = 0;
  const map = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, "\\": 92, '"': 34, "'": 39 };
  while (i < s.length) {
    const ch = s[i];
    if (ch !== "\\") { out.push(ch.charCodeAt(0)); i++; continue; }
    const nx = s[i + 1];
    if (!nx) return null;
    if (map[nx] !== undefined) { out.push(map[nx]); i += 2; continue; }
    if (nx === "x") {
      const h = s.slice(i + 2, i + 4);
      if (!/^[0-9a-fA-F]{2}$/.test(h)) return null;
      out.push(parseInt(h, 16)); i += 4; continue;
    }
    if (nx >= "0" && nx <= "9") {
      let j = i + 1, num = "";
      while (j < s.length && num.length < 3 && s[j] >= "0" && s[j] <= "9") num += s[j++];
      const v = parseInt(num, 10);
      if (v > 255) return null;
      out.push(v); i = j; continue;
    }
    return null;
  }
  return out;
}

function encryptStrings(toks) {
  const pool = [];
  const key = R(40, 200);
  const arrName = "_S" + R(1000, 9999);
  let count = 0;
  const out = toks.map((t) => {
    if (t.type !== "str") return t;
    const bytes = decodeLuaString(t.val);
    if (!bytes || !bytes.length || bytes.length > 4000) return t;
    if (!bytes.some((b) => (b >= 65 && b <= 90) || (b >= 97 && b <= 122))) return t;
    const idx = pool.length;
    pool.push(bytes.map((b, i) => b ^ key ^ ((i * 7) % 251)));
    count++;
    return { type: "id", val: arrName + "[" + idx + "]" };
  });
  if (!pool.length) return { toks: out, header: "", count: 0 };
  const parts = pool.map((a) => "{" + a.map(H).join(",") + "}");
  const header = "local " + arrName + ";do local __k=" + H(key) + " local __p={" + parts.join(",") + "} local __o={} for i=1,#__p do local t=__p[i] local r={} for j=1,#t do local x,y,z=t[j],__k,((j-1)*7)%251 local o,p=0,1 for _=1,8 do local bx,by,bz=x%2,y%2,z%2 o=o+((bx+by+bz)%2)*p x=(x-bx)/2 y=(y-by)/2 z=(z-bz)/2 p=p*2 end r[j]=string.char(o) end __o[i-1]=table.concat(r) end " + arrName + "=__o end\n";
  return { toks: out, header, count };
}

function obfuscateNumbers(toks) {
  let count = 0;
  const out = toks.map((t) => {
    if (t.type !== "num" || !/^\d+$/.test(t.val)) return t;
    const v = parseInt(t.val, 10);
    if (v < 16 || v > 50000) return t;
    count++;
    const a = R(1, Math.max(1, v - 1));
    return { type: "sy", val: "(" + H(a) + "+" + H(v - a) + ")" };
  });
  return { toks: out, count };
}

/*
 * The lexer intentionally drops whitespace and comments.  That is fine only if
 * we put back a separator when two neighbouring tokens would otherwise become
 * one token ("local" + "name" => "localname"), a comment ("-" + "-"), or
 * an ambiguous number/concatenation expression.  Keeping this in one renderer
 * makes every transformation use the same, syntax-safe output path.
 */
function renderTokens(toks) {
  let code = "";
  let previous = null;
  for (const token of toks) {
    if (previous) {
      const a = previous.val;
      const b = token.val;
      const aLast = a[a.length - 1] || "";
      const bFirst = b[0] || "";
      const wordA = /[A-Za-z0-9_]/.test(aLast);
      const wordB = /[A-Za-z0-9_]/.test(bFirst);
      const needsWordSpace = wordA && wordB;
      const needsCommentSpace = aLast === "-" && bFirst === "-";
      const needsNumberSpace = previous.type === "num" && (bFirst === "." || bFirst === "e" || bFirst === "E");
      if (needsWordSpace || needsCommentSpace || needsNumberSpace) code += " ";
    }
    code += token.val;
    previous = token;
  }
  return code;
}

function renameLocals(toks) {
  /*
   * A lexer alone cannot rename Lua/Luau locals safely: declarations are not
   * visible in their own RHS, function parameters introduce scopes, and a dot
   * field is not an identifier reference.  The old implementation changed
   * programs in all three cases.  The encrypted VM shell already removes the
   * source identifiers from the delivered file, so preserve semantics here
   * until this is backed by a real Lua/Luau AST parser.
   */
  return { toks, count: 0 };
}

function antiTamper() {
  return [
    "do",
    "local function __d(r) error(tostring(r or 0XDEAD),0) end",
    "local rg,pc,ty=rawget,pcall,type",
    'for _,k in ipairs({"lune","lute","wally","rojo","selene","darklua","lemur","fetch","console","window","document"}) do if rg(_G,k)~=nil then __d(1) end end',
    'if ty(process)=="table" then __d(2) end',
    'if not game or not typeof or game.ClassName~="DataModel" then __d(3) end',
    'if not pc(function() local p=Instance.new("Part") p:Destroy() end) then __d(4) end',
    "end"
  ].join("\n");
}

function vmShell(source) {
  let data = Buffer.from(String(source), "utf8");
  const rounds = 4;
  const keys = [];
  for (let r = 0; r < rounds; r++) {
    const key = crypto.randomBytes(16);
    keys.push(key);
    const out = Buffer.alloc(data.length);
    const salt = (r + 3) & 0xff;
    for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length] ^ ((i * salt) & 0xff);
    data = out;
  }
  const payload = [...data].map((b) => H(b)).join(",");
  const keyLits = keys.map((k) => "{" + [...k].map((b) => H(b)).join(",") + "}").join(",");
  const bx = "_bx" + R(10, 99);
  const dec = "_dec" + R(10, 99);
  const lines = [];
  lines.push("return(function()");
  lines.push("local function " + bx + "(a,b)");
  lines.push("local o,p,i,j=0,1,a,b");
  lines.push("for t=1,8 do local c,r=i%2,j%2 o=o+((c+r)%2)*p i=(i-c)/2 j=(j-r)/2 p=p*2 end");
  lines.push("return o end");
  lines.push("local function " + dec + "(p,k,s)");
  lines.push("local o={} for j=1,#p do local t=p[j] local a=k[((j-1)%#k)+1] local b=((j-1)*s)%256");
  lines.push("o[j]=string.char(" + bx + "(" + bx + "(t,a),b)) end return table.concat(o) end");
  lines.push("local K={" + keyLits + "}");
  lines.push("local D={" + payload + "}");
  lines.push("for i=#K,1,-1 do");
  lines.push("D=" + dec + "(D,K[i],(i+2))");
  lines.push("if i>1 then local t={} for j=1,#D do t[j]=string.byte(D,j) end D=t end");
  lines.push("end");
  lines.push("local f=(loadstring or load)(D)");
  lines.push("if not f then error(0XBAD,0) end");
  lines.push("return f()");
  lines.push("end)()");
  return lines.join("\n");
}

function obfuscate(source, opts) {
  opts = opts || {};
  const src = String(source || "");
  if (!src.trim()) throw new Error("code required");
  if (src.length > 600000) throw new Error("too large");
  let toks = lex(src);
  let stringsEncrypted = 0, localsRenamed = 0, numbersMutated = 0;
  let header = "";
  if (opts.strings !== false) {
    const r = encryptStrings(toks);
    toks = r.toks; header = r.header || ""; stringsEncrypted = r.count || 0;
  }
  if (opts.numbers !== false) {
    const r = obfuscateNumbers(toks);
    toks = r.toks; numbersMutated = r.count || 0;
  }
  if (opts.renameLocals !== false) {
    const r = renameLocals(toks);
    toks = r.toks; localsRenamed = r.count || 0;
  }
  let code = renderTokens(toks);
  if (header) code = header + code;
  if (opts.antiTamper !== false) code = antiTamper() + "\n" + code;
  const final = vmShell(code);
  const out = "-- Protect by QyrexObf v9\n" + final;
  return {
    code: out,
    stats: {
      inputBytes: src.length,
      outputBytes: out.length,
      stringsEncrypted,
      localsRenamed,
      numbersMutated,
      mode: "vm-shell"
    }
  };
}

module.exports = { obfuscate };
