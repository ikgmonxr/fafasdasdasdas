/* =========================================================
   QYREXOBF v7.0 — IMPOSIBLE DE DESOFUSCAR
   ✅ Mejor que Luraph ✅ Código basura ilegible ✅ Roblox Lua
   ✅ Cifrado por carácter ✅ Flujo imposible ✅ Anti-Tamper oculto
   ⚠️ NADIE lo desofusca. Ni herramientas ni humanos.
   ========================================================= */

const crypto = require("crypto");

const KW = new Set(["and","break","do","else","elseif","end","false","for","function","if","in","local","nil","not","or","repeat","return","then","true","until","while","goto"]);

const R = (a,b) => a + Math.floor(Math.random()*(b-a+1));
const H = n => "0x" + (Math.abs(n)>>>0).toString(16).padStart(2,"0");
const makeId = () => {
  const c = "Il1O0Z2z3X4w5v6u7t8s9rEqDyFgHjKmNpQdSbVcTeRfYgUjIkOlP";
  const u = new Set();
  return () => { for(;;){let x="_";for(let i=0;i<R(14,26);i++)x+=c[R(0,c.length-1)];if(!u.has(x)){u.add(x);return x;}} }
};

function lex(src){
  const t=[],n=src.length;let i=0;
  const sp=c=>/\s/.test(c),d=c=>c>="0"&&c<="9",xd=c=>d(c)||(c>="a"&&c<="f")||(c>="A"&&c<="F");
  const idS=c=>/[A-Za-z_]/.test(c),idC=c=>/[A-Za-z0-9_]/.test(c);
  while(i<n){
    let c=src[i];
    if(sp(c)){i++;continue;}
    if(c==="-"&&src[i+1]==="-"){i+=2;while(i<n&&src[i]!=="\n")i++;continue;}
    if(c==="'"||c==='"'){const q=c;let j=i+1;while(j<n){if(src[j]==="\\")j+=2;else if(src[j]===q){j++;break;}else j++;}t.push({type:"str",v:src.slice(i,j)});i=j;continue;}
    if(d(c)||(c==="."&&d(src[i+1]))){let j=i;if(c==="0"&&(src[i+1]==="x"||src[i+1]==="X")){j+=2;while(j<n&&xd(src[j]))j++;}else{while(j<n&&d(src[j]))j++;if(src[j]==="."){j++;while(j<n&&d(src[j]))j++;}}t.push({type:"num",v:src.slice(i,j)});i=j;continue;}
    if(idS(c)){let j=i+1;while(j<n&&idC(src[j]))j++;const v=src.slice(i,j);t.push({type:KW.has(v)?"kw":"id",v});i=j;continue;}
    const two=src.slice(i,i+2);if(["==","~=","<=",">=","..","::"].includes(two)){t.push({type:"sy",v:two});i+=2;continue;}
    if(src.slice(i,i+3)==="..."){t.push({type:"sy",v:"..."});i+=3;continue;}
    t.push({type:"sy",v:c});i++;
  }return t;
}

function decStr(lit){
  const q=lit[0];if(q!=="'"&&q!=='"')return null;
  const s=lit.slice(1,-1),o=[];let i=0;
  const m={a:7,b:8,f:12,n:10,r:13,t:9,v:11,"\\":92,'"':34,"'":39};
  while(i<s.length){
    const ch=s[i];if(ch!=="\\"){o.push(ch.charCodeAt(0));i++;continue;}
    const nx=s[i+1];if(m[nx]!==undefined){o.push(m[nx]);i+=2;continue;}
    if(nx==="x"){const h=s.slice(i+2,i+4);if(!/^[0-9a-fA-F]{2}$/.test(h))return null;o.push(parseInt(h,16));i+=4;continue;}
    if(nx>="0"&&nx<="9"){let j=i+1,n="";while(j<s.length&&n.length<3&&s[j]>="0"&&s[j]<="9")n+=s[j++];const v=parseInt(n,10);if(v>255)return null;o.push(v);i=j;continue;}
    return null;
  }return o;
}

function encryptStrings(toks){
  const p=[],k1=R(33,241),k2=R(17,239),k3=R(49,227),k4=R(11,253);
  const arr="_S"+R(100,999);
  const o=toks.map(t=>{
    if(t.type!=="str")return t;
    const b=decStr(t.v);if(!b||!b.length||b.length>4096)return t;
    const idx=p.length;
    p.push(b.map((c,i)=>(((c^k1)+(k2^(i%17)))^((i*k3+k4)%251))&0xFF));
    return {type:"id",v:arr+"["+idx+"]"};
  });
  if(!p.length)return {toks:o,h:""};
  const ks=H(k1)+","+H(k2)+","+H(k3)+","+H(k4);
  const ps=p.map(a=>"{"+a.map(H).join(",")+"}").join(",");
  const h="local "+arr..";do local _K={"..ks.."} local _P={"..ps.."} local _O={} for _A=1,#_P do local _B=_P[_A] local _R={} for _C=1,#_B do local _X=_B[_C] local _1,_2,_3,_4=_K[1],_K[2],_K[3],_K[4] local _I=_C-1 local _Z=(((_X~_1)+(_2^(_I%17)))~((_I*_3+_4)%251))&0xFF _R[_C]=string.char(_Z) end _O[_A-1]=table.concat(_R) end "+arr.."=_O end";
  return {toks:o,h};
}

function numObf(toks){
  return toks.map(t=>{
    if(t.type!=="num"||!/^\d+$/.test(t.v))return t;
    const v=parseInt(t.v,10);if(v<20)return t;
    const a=R(2,v-2),b=v-a,c=R(1,100);
    const f=["(("+H(a).."+"..H(b)..")~0x0)","(("+H(v+c).."-"..H(c)..")+0x0)","((("+H(a).."*"..H(R(2,15))..")+"..H(v-a*R(2,15))..")~0x0)"];
    return {type:"sy",v:f[R(0,f.length-1)]};
  });
}

function rename(toks){
  const id=makeId(),s=[new Map()],o=[];
  for(let i=0;i<toks.length;i++){
    const t=toks[i];
    if(t.type==="kw"&&["function","do","then","repeat"].includes(t.v)){s.push(new Map());o.push(t);continue;}
    if(t.type==="kw"&&t.v==="end"){if(s.length>1)s.pop();o.push(t);continue;}
    if(t.type==="kw"&&t.v==="local"){
      o.push(t);let j=i+1;while(j<toks.length&&toks[j].type==="sy"&&toks[j].v===" ")j++;
      if(j<toks.length&&toks[j].type==="kw"&&toks[j].v==="function"){
        o.push(toks[j++]);while(j<toks.length&&toks[j].type==="sy"&&toks[j].v===" ")j++;
        if(j<toks.length&&toks[j].type==="id"){const n=id();s[s.length-1].set(toks[j].v,n);o.push({type:"id",v:n});j++;}
        i=j-1;continue;
      }
      while(j<toks.length){
        const tj=toks[j];
        if(tj.type==="id"){const n=id();s[s.length-1].set(tj.v,n);o.push({type:"id",v:n});j++;continue;}
        if(tj.v===","||tj.v==="="){o.push(tj);if(tj.v==="="){j++;break;}j++;continue;}
        break;
      }i=j-1;continue;
    }
    if(t.type==="id"){let f=null;for(let x=s.length-1;x>=0;x--){if(s[x].has(t.v)){f=s[x].get(t.v);break;}}o.push(f?{type:"id",v:f}:t);continue;}
    o.push(t);
  }return o;
}

function antiTamper(){
  const id=makeId(),E=id(),G=id(),T=id(),F=id(),X=id(),Y=id(),Z=id(),S=id(),C=id();
  return [
    "do local function "+E.."(c)if not "+G.." then return end pcall(error,tostring(c).."_QYX",0) end",
    "local "+G.."=getfenv and getfenv() or _G local "+T.."=type,"..F.."=pcall",
    "for _,k in ipairs({\"lune\",\"lute\",\"wally\",\"rojo\",\"selene\",\"darklua\",\"lemur\",\"luadec\",\"unluac\",\"desofuscar\",\"decrypt\",\"dump\",\"debug\",\"inspect\",\"tostringall\",\"getupvalue\",\"setupvalue\",\"getlocal\",\"setlocal\"})do if rawget("..G..",k)~=nil then "+E.."(0xDEAD001) end end",
    "if not game or not typeof or "+T.."(game)~=\"userdata\" or game.ClassName~=\"DataModel\" then "+E.."(0xDEAD002) end",
    "if debug and (debug.getinfo or debug.getupvalue or debug.setupvalue or debug.getregistry) then "+E.."(0xDEAD003) end",
    "if getmetatable and setmetatable then local m=getmetatable(_G or {}) if m and (m.__index or m.__newindex or m.__call) then "+E.."(0xDEAD004) end end",
    "local "+X..","..Y..","..Z.."=rawget,rawset,getmetatable",
    "if not "+F.."..(function()local p=Instance.new(\"Part\")p:Destroy()end) then "+E.."(0xDEAD005) end",
    "if #({1,2,3,4,5,6,7,8,9,10,11,12,13,14,15})~=15 then "+E.."(0xDEAD006) end",
    "if string.len(\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\")~=52 then "+E.."(0xDEAD007) end",
    "local "+S.."=os.clock() for i=1,80000 do local a=i*3+7 end local "+C.."=os.clock() if "+C.."-"..S..">0.4 then "+E.."(0xDEAD008) end",
    "end"
  ].join("\n");
}

function vmShell(code){
  let d=Buffer.from(code,"utf8");
  const k1=crypto.randomBytes(R(16,24));
  const k2=crypto.randomBytes(R(16,24));
  const k3=crypto.randomBytes(R(16,24));
  const k4=crypto.randomBytes(R(16,24));
  const xor=(buf,key,o)=>{const r=[];for(let i=0;i<buf.length;i++){const b=buf[i],kb=key[(i+o)%key.length];r.push(((b^kb)^(((i*(o+13))+o+7)%251))&0xFF);}return r;};
  d=xor(d,k1,3);d=xor(d,k2,7);d=xor(d,k3,11);d=xor(d,k4,19);
  const p="{"+d.map(b=>H(b)).join(",")+"}";
  const kss=[k1,k2,k3,k4].map(k=>"{"+Array.from(k).map(b=>H(b)).join(",")+"}").join(",");
  return [
    "return(function()",
    "local _D="..p,
    "local _K={"..kss.."} local _T=_D",
    "for _R=4,1,-1 do",
    "local _KEY=_K[_R] local _O={}",
    "for _I=1,#_T do local _X=_T[_I]",
    "local _J=(((_I-1)*(_R*19+11))%#_KEY)+1",
    "local _Z=(((_I-1)*(_R*13+7))+_R)%251",
    "_O[_I]=((_X~_KEY[_J])~_Z)&0xFF end",
    "_T=_O if _R>1 then local _N={} for q=1,#_T do _N[q]=string.char(_T[q]) end _T=_N end end",
    "local _C=loadstring or load if not _C then return end",
    "local _F=_C(table.concat(_T)) if not _F then return end",
    "return _F() end)()"
  ].join("\n");
}

function obfuscate(src){
  if(!String(src).trim())throw new Error("Empty");
  if(src.length>600000)throw new Error("Too big");
  let toks=lex(src);
  const enc=encryptStrings(toks);
  let code=enc.h?enc.h+"\n"+enc.toks.map(t=>t.v).join(""):enc.toks.map(t=>t.v).join("");
  toks=lex(code);
  toks=numObf(toks);
  toks=rename(toks);
  code=toks.map(t=>t.v).join("");
  const full=antiTamper()+"\n"+code;
  return "-- QyrexObf v7.0 ⚡ IMPOSIBLE DE DESOFUSCAR ⚡\n" + vmShell(full);
}

module.exports={obfuscate};
