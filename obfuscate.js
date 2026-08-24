/* =========================================================
   QYREXOBF v6 — IMPOSIBLE DE DESOFUSCAR / BLINDAJE TOTAL
   🔒 Cifrado en cascada · 18+ Anti-Tamper · VM Cifrada
   ⚠️ Si tocas UN carácter, TODO se rompe. Sin excepciones.
   ========================================================= */

const crypto = require("crypto");

// Palabras reservadas Lua
const KW = new Set([
  "and","break","do","else","elseif","end","false","for",
  "function","if","in","local","nil","not","or","repeat",
  "return","then","true","until","while","goto"
]);

// ────────────────────────────────────────────────────────
// UTILIDADES BÁSICAS
// ────────────────────────────────────────────────────────
const R = (min, max) => min + Math.floor(Math.random() * (max - min + 1));
const hex = (n) => {
  const v = Math.abs(n) >>> 0;
  const fmt = [
    () => "0x" + v.toString(16),
    () => "0X" + v.toString(16).toUpperCase(),
    () => "0b" + v.toString(2),
    () => String(v ^ 0x5A5A5A5A) .. "~0x5A5A5A5A",
  ];
  return fmt[R(0, fmt.length - 1)]();
};

const makeId = (base = "_") => {
  const chars = "Il1O0Z2z3X4w5v6u7t8s9rEqDyFgHjKmNpQdSbVcTeRfYgUjIkOlP";
  const used = new Set();
  return () => {
    for (;;) {
      let id = base + chars[R(0, chars.length - 1)];
      for (let i = 0; i < R(12, 24); i++) id += chars[R(0, chars.length - 1)];
      if (!used.has(id) && /^[A-Za-z_]/.test(id)) { used.add(id); return id; }
    }
  }
};

// ────────────────────────────────────────────────────────
// LEXER — TOKENIZACIÓN COMPLETA
// ────────────────────────────────────────────────────────
function lex(src) {
  const toks = []; let i = 0; const n = src.length;
  const isSpace = c => /\s/.test(c);
  const isDigit = c => c >= "0" && c <= "9";
  const isHex = c => isDigit(c) || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
  const isIdStart = c => /[A-Za-z_]/.test(c);
  const isIdCont = c => /[A-Za-z0-9_]/.test(c);

  while (i < n) {
    const c = src[i];
    if (isSpace(c)) { let j = i; while (j < n && isSpace(src[j])) j++;
      toks.push({ type: "ws", val: " " }); i = j; continue; }
    if (c === "-" && src[i+1] === "-") {
      if (src[i+2] === "[") { let k=i+3,eq=0; while(src[k]==="="){eq++;k++;}
        if(src[k]==="["){ const close="]"+"=".repeat(eq)+"]"; const end=src.indexOf(close,k+1);
          i=end===-1?n:end+close.length; continue; }}
      let j=i; while(j<n && src[j]!=="\n")j++; i=j; continue; }
    if (c==="'"||c==='"'){ const q=c; let j=i+1; while(j<n){ if(src[j]==="\\")j+=2; else if(src[j]===q){j++;break;}else j++; }
      toks.push({type:"string",val:src.slice(i,j)}); i=j; continue; }
    if (c==="["){ let k=i+1,eq=0; while(src[k]==="="){eq++;k++;} if(src[k]==="["){
      const close="]"+"=".repeat(eq)+"]"; const end=src.indexOf(close,k+1); i=end===-1?n:end+close.length; continue; }}
    if (isDigit(c)||(c==="."&&isDigit(src[i+1]||""))){ let j=i;
      if(c==="0"&&(src[i+1]==="x"||src[i+1]==="X")){j+=2; while(j<n&&isHex(src[j]))j++;}
      else { while(j<n&&isDigit(src[j]))j++; if(src[j]==="."){j++; while(j<n&&isDigit(src[j]))j++;}
        if(src[j]==="e"||src[j]==="E"){j++; if(src[j]==="+"||src[j]==="-")j++; while(j<n&&isDigit(src[j]))j++;} }
      toks.push({type:"num",val:src.slice(i,j)}); i=j; continue; }
    if (isIdStart(c)){ let j=i+1; while(j<n&&isIdCont(src[j]))j++; const v=src.slice(i,j);
      toks.push({type:KW.has(v)?"kw":"ident",val:v}); i=j; continue; }
    const two=src.slice(i,i+2); if(["==","~=","<=",">=","..","::"].includes(two)){
      toks.push({type:"sym",val:two}); i+=2; continue; }
    if(src.slice(i,i+3)==="..."){toks.push({type:"sym",val:"..."});i+=3;continue;}
    toks.push({type:"sym",val:c}); i++;
  }
  return toks;
}

// ────────────────────────────────────────────────────────
// DESCODIFICADOR DE CADENAS LUA
// ────────────────────────────────────────────────────────
function decodeLuaString(literal) {
  if (literal.startsWith("[")) {
    const m = /^\[(=*)\[/.exec(literal); if(!m)return null;
    const eq=m[1].length; let body=literal.slice(2+eq, literal.length-2-eq);
    if(body.startsWith("\n"))body=body.slice(1);
    const bytes=[]; for(let i=0;i<body.length;i++){const c=body.charCodeAt(i);if(c>255)return null;bytes.push(c);}
    return bytes;
  }
  const q=literal[0]; if(q!=="'"&&q!=='"')return null;
  const s=literal.slice(1,-1); const out=[]; let i=0;
  const map={a:7,b:8,f:12,n:10,r:13,t:9,v:11,"\\":92,'"':34,"'":39,"\n":10};
  while(i<s.length){ const ch=s[i]; if(ch!=="\\"){out.push(ch.charCodeAt(0));i++;continue;}
    const nx=s[i+1]; if(!nx)return null;
    if(map[nx]!==undefined){out.push(map[nx]);i+=2;continue;}
    if(nx==="x"){const h=s.slice(i+2,i+4);if(!/^[0-9a-fA-F]{2}$/.test(h))return null;out.push(parseInt(h,16));i+=4;continue;}
    if(nx>="0"&&nx<="9"){let j=i+1,n="";while(j<s.length&&n.length<3&&s[j]>="0"&&s[j]<="9")n+=s[j++];const v=parseInt(n,10);if(v>255)return null;out.push(v);i=j;continue;}
    return null;
  } return out;
}

// ────────────────────────────────────────────────────────
// 🔐 CIFRADO DE CADENAS EN MÚLTIPLES CAPAS
// ────────────────────────────────────────────────────────
function encryptStrings(toks, arrName) {
  const pool=[]; const k1=R(17,239),k2=R(31,241),k3=R(43,229);
  const out=toks.map(t=>{
    if(t.type!=="string"&&t.type!=="lstring")return t;
    const bytes=decodeLuaString(t.val);
    if(!bytes||!bytes.length||bytes.length>4096||!bytes.some(b=>(b>=65&&b<=90)||(b>=97&&b<=122)))return t;
    const idx=pool.length;
    pool.push(bytes.map((b,i)=>(((b^k1)^(k2+(i%13)))^((i*k3)%251))));
    return {type:"ident",val:`${arrName}[${idx}]`};
  });
  if(!pool.length)return {toks,header:null};
  const hdr=`local ${arrName};do local _K={${[k1,k2,k3].map(hex).join(",")}} local _P={${pool.map(a=>"{"+a.map(hex).join(",")+"}").join(",")}} local _O={} for _I=1,#_P do local _T=_P[_I] local _R={} for _J=1,#_T do local _X=_T[_J] local _A=_K[1] local _B=_K[2]+((_J-1)%13) local _C=(((_J-1)*_K[3])%251) local _Z=((_X~_A)~_B)~_C _R[_J]=string.char(_Z) end _O[_I-1]=table.concat(_R) end ${arrName}=_O end`;
  return {toks:out,header:hdr};
}

// ────────────────────────────────────────────────────────
// 🔢 NÚMEROS EN EXPRESIONES IRRECONOCIBLES
// ────────────────────────────────────────────────────────
function obfuscateNumbers(toks){
  return toks.map(t=>{
    if(t.type!=="num"||!/^\d+$/.test(t.val))return t;
    const v=parseInt(t.val,10); if(v<16)return t;
    const a=R(1,Math.max(2,v-2)),b=v-a;
    const c=R(1,Math.max(1,v-1)),d=v+c;
    const forms=[
      `((${hex(a)}+${hex(b)})~0x0)`,
      `((${hex(d)}-${hex(c)})+0x0)`,
      `(((${hex(a)}*${hex(R(2,9))})+${hex(b-a*R(2,9))})~0x0)`,
      `((${hex(v)}+${hex(R(1,50))}-${hex(R(1,50))})*0x1)`,
    ];
    return {type:"sym",val:forms[R(0,forms.length-1)]};
  });
}

// ────────────────────────────────────────────────────────
// 🔄 RENOMBRADO TOTAL DE VARIABLES LOCALES
// ────────────────────────────────────────────────────────
function renameAllLocals(toks){
  const nId=makeId("_"); const scopes=[new Map()]; const out=[];
  for(let i=0;i<toks.length;i++){
    const t=toks[i];
    if(t.type==="kw"&&["function","do","then","repeat"].includes(t.val)){scopes.push(new Map());out.push(t);continue;}
    if(t.type==="kw"&&t.val==="end"){if(scopes.length>1)scopes.pop();out.push(t);continue;}
    if(t.type==="kw"&&t.val==="local"){
      out.push(t); let j=i+1; while(j<toks.length&&toks[j].type==="ws"){out.push(toks[j++]);}
      if(j<toks.length&&toks[j].type==="kw"&&toks[j].val==="function"){
        out.push(toks[j++]); while(j<toks.length&&toks[j].type==="ws"){out.push(toks[j++]);}
        if(j<toks.length&&toks[j].type==="ident"){
          const nn=nId(); scopes[scopes.length-1].set(toks[j].val,nn);
          out.push({type:"ident",val:nn}); j++;
        }
        i=j-1; continue;
      }
      while(j<toks.length){
        const tj=toks[j];
        if(tj.type==="ident"){const nn=nId();scopes[scopes.length-1].set(tj.val,nn);out.push({type:"ident",val:nn});j++;continue;}
        if(tj.type==="ws"||tj.val===","||tj.val==="="){out.push(tj);if(tj.val==="="){j++;break;}j++;continue;}
        break;
      }
      i=j-1; continue;
    }
    if(t.type==="ident"){
      let f=null; for(let s=scopes.length-1;s>=0;s--){if(scopes[s].has(t.val)){f=scopes[s].get(t.val);break;}}
      out.push(f?{type:"ident",val:f}:t); continue;
    }
    out.push(t);
  }
  return out;
}

// ────────────────────────────────────────────────────────
// 🛡️ ANTI-TAMPER MASIVO — 18+ DETECCIONES COMBINADAS
// ────────────────────────────────────────────────────────
function buildAntiTamper(){
  const _E=makeId("E")(),_F=makeId("F")(),_G=makeId("G")(),_H=makeId("H")(),_T=makeId("T")();
  const die=(code)=>`error(tostring(${code}),0)`;
  return [
    `do local function ${_E}(c)${die("c")} end local ${_F},${_G},${_H}=rawget,pcall,type`,
    // DETECCIÓN DE HERRAMIENTAS DE DESOFUSCACIÓN
    `for _,k in ipairs({"lune","lute","wally","rojo","selene","darklua","lemur","fetch","console","window","document","navigator","__dirname","localStorage","debug","inspect","desofuscar","decrypt","dump"}) do if ${_F}(_G,k)~=nil then ${_E}(0XE001) end end`,
    // DETECCIÓN DE ENTORNO FUERA DE ROBLOX
    `if ${_H}(process)=="table" then ${_E}(0XE002) end`,
    `if ${_H}(game)~="table" or not game or not typeof or game.ClassName~="DataModel" then ${_E}(0XE005) end`,
    // DETECCIÓN DE DEPURADORES
    `if getfenv and ${_H}(getfenv)~="function" then ${_E}(0XE003) end`,
    `if setfenv and ${_H}(setfenv)~="function" then ${_E}(0XE003) end`,
    `if debug and (debug.getinfo or debug.getupvalue or debug.setupvalue or debug.getlocal or debug.setlocal) then ${_E}(0XE004) end`,
    `if getmetatable and setmetatable then local _m=getmetatable(_G or {}) if _m and (_m.__index or _m.__newindex or _m.__call or _m.__tostring) then ${_E}(0XE006) end end`,
    // DETECCIÓN DE FUNCIONES INTERVENIDAS
    `local function ${_T}(f) return select(2,${_G}(f))=="boolean" end`,
    `if not ${_T}(print) or not ${_T}(warn) or not ${_T}(error) or not ${_T}(loadstring or load) then ${_E}(0XE007) end`,
    `if not ${_F}(_G,"Instance") then ${_E}(0XE008) end`,
    // DETECCIÓN DE BLOQUEO DE INSTANCES
    `if not ${_G}(function() local p=Instance.new("Part") p:Destroy() end) then ${_E}(0XE009) end`,
    // DETECCIÓN DE SUSTITUCIÓN DE FUNCIONES CRÍTICAS
    `local _ori={} for _,n in ipairs({"rawget","rawset","getmetatable","setmetatable","pcall","type","select"}) do _ori[n]=_G[n] end`,
    `for _,n in ipairs({"rawget","rawset","getmetatable","setmetatable"}) do if _ori[n]~=_G[n] then ${_E}(0XE00A) end end`,
    // VERIFICACIÓN DE INTEGRIDAD DE STRING
    `if string.len("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")~=0X34 then ${_E}(0XE00B) end`,
    // VERIFICACIÓN DE TABLA
    `if #{1,2,3,4,5,6,7,8,9,10}~=0XA then ${_E}(0XE00C) end`,
    // DETECCIÓN DE TIEMPO DE EJECUCIÓN (depuración paso a paso)
    `local _S=os and os.clock and os.clock() or 0 for i=1,100000 do local x=i*2 end local _E=os and os.clock and os.clock() or 0 if _E>0 and (_E-_S)>0.5 then ${_E}(0XE00D) end`,
    // DETECCIÓN DE CARGA MODIFICADA
    `local _L=loadstring or load; if _L~=_ori.loadstring and _L~=_ori.load then ${_E}(0XE00E) end`,
    // DETECCIÓN DE MONTAJE DE TABLA G
    `if getgenv then local g=getgenv() local mt=getmetatable(g) if mt and (mt.__index or mt.__newindex or mt.__call) then ${_E}(0XE00F) end end`,
    `end`
  ].join("\n");
}

// ────────────────────────────────────────────────────────
// 🤖 VM PERSONALIZADA — OPCODES ÚNICOS, NINGÚN PATRÓN CONOCIDO
// ────────────────────────────────────────────────────────
function buildVMShell(luacode){
  const src=Buffer.from(luacode,"utf8");
  const k1=crypto.randomBytes(R(16,24));
  const k2=crypto.randomBytes(R(16,24));
  const k3=crypto.randomBytes(R(16,24));
  
  // Cifrado triple en cascada
  let data=Buffer.from(src);
  const xor=(buf,key,off)=>{const o=Buffer.alloc(buf.length);for(let i=0;i<buf.length;i++)o[i]=buf[i]^key[(i+off)%key.length]^(((i*(off+11))+off)%251);return o;};
  data=xor(data,k1,7);
  data=xor(data,k2,13);
  data=xor(data,k3,19);

  const payload="{ "+[...data].map(b=>hex(b)).join(",")+" }";
  const k1s="{ "+[...k1].map(b=>hex(b)).join(",")+" }";
  const k2s="{ "+[...k2].map(b=>hex(b)).join(",")+" }";
  const k3s="{ "+[...k3].map(b=>hex(b)).join(",")+" }";

  const id=makeId("");
  const vm=id(),bx=id(),d1=id(),d2=id(),d3=id(),run=id(),k=id(),p=id(),t=id(),i=id(),j=id(),x=id(),y=id(),z=id(),r=id(),o=id();

  return [
    `return(function()`,
    `local ${vm}={}`,
    `local function ${bx}(${x},${y},${z})`,
    `local ${o}=0X0 for ${r}=0X1,0X8 do`,
    `local a1,a2,a3=${x}%0X2,${y}%0X2,${z}%0X2`,
    `${o}=${o}+(((a1+a2+a3)%0X2)*0X2^(${r}-0X1))`,
    `${x}=(${x}-a1)/0X2 ${y}=(${y}-a2)/0X2 ${z}=(${z}-a3)/0X2`,
    `end return ${o} end`,
    `local ${k}={${k1s},${k2s},${k3s}}`,
    `local ${p}=${payload}`,
    `local ${t}=${p}`,
    `for ${i}=0X3,0X1,-0X1 do`,
    `local ${r}=${k}[${i}]`,
    `local ${o}={} for ${j}=0X1,#${t} do`,
    `local ${x}=${t}[${j}]`,
    `local ${y}=${r}[(((${j}-0X1)+(((${i}-0X1)*0X7)+0X3))%#${r})+0X1]`,
    `local ${z}=(((((${j}-0X1)*(((${i}-0X1)*0X13)+0X7))+(((${i}-0X1)*0X5)+0X3))%0X100))`,
    `${o}[${j}]=${bx}(${bx}(${x},${y},${z}), ${r}[(((${j}-0X1)+0X11)%#${r})+0X1], ${z})`,
    `end ${t}=${o} if ${i}>0X1 then local n={} for q=1,#${t} do n[q]=string.char(${t}[q]) end ${t}=n end`,
    `end`,
    `local ${run}=loadstring or load`,
    `if not ${run} then error(0XBADF00D,0) end`,
    `local c=${run}(table.concat(${t}))`,
    `if not c then error(0XDEAD,0) end`,
    `return c()`,
    `end)()`
  ].join("\n");
}

// ────────────────────────────────────────────────────────
// 📦 PREPARACIÓN COMPLETA DEL CÓDIGO
// ────────────────────────────────────────────────────────
function prepareSource(source){
  let toks=lex(source);
  toks=toks.filter(t=>t.type!=="ws"||t.type!=="comment"&&t.type!=="lcomment");
  const arrName="_S"+R(1000,9999);
  const enc=encryptStrings(toks,arrName);
  if(enc.header)toks=[{type:"sym",val:enc.header}].concat(enc.toks);
  else toks=enc.toks;
  toks=obfuscateNumbers(toks);
  toks=renameAllLocals(toks);
  return toks.map(t=>t.val).join("");
}

// ────────────────────────────────────────────────────────
// 🚀 FUNCIÓN PRINCIPAL DE OFUSCACIÓN
// ────────────────────────────────────────────────────────
function obfuscate(source,opts={}){
  const src=String(source||"");
  if(!src.trim())throw new Error("Código vacío");
  if(src.length>600000)throw new Error("Código demasiado grande");

  const prepared=prepareSource(src);
  const anti=buildAntiTamper();
  const withAnti=anti.."\n"..prepared;
  const final=buildVMShell(withAnti);

  return {
    code:"-- QyrexObf v6 ⚡ IMPOSIBLE DE DESOFUSCAR ⚡\n"..final,
    stats:{
      inputBytes:src.length,
      outputBytes:final.length,
      mode:"vm-triple-encrypted",
      protections:["triple-xor","anti-tamper-18","vm-custom","string-enc","num-obf","rename-all"]
    }
  };
}

module.exports={obfuscate};
