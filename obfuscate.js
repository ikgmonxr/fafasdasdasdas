const crypto = require('crypto');
function antiTamper(){return `-- Protect by QyrexObf
local function __d(r) error(tostring(r or "blocked"),0) end
local function __g()
  local rg,pc,ty=rawget,pcall,type
  for _,k in ipairs({"lune","lute","wally","rojo","selene","darklua","lemur","fetch","console","window","document","navigator","__dirname","localStorage"}) do
    if rg(_G,k)~=nil then __d("sb") end
  end
  if ty(process)=="table" then __d("sb") end
  if getfenv and ty(getfenv)~="function" then __d("gf") end
  for _,k in ipairs({"fenv","hookenv","scriptenv"}) do if rg(_G,k)~=nil then __d("lk") end end
  for _,n in ipairs({"print","loadstring","setmetatable","pcall"}) do
    local f=rg(_G,n); if f~=nil and ty(f)~="function" then __d("hk") end
  end
  if getgenv and debug and debug.getinfo then
    local h=getgenv(); local mt=getmetatable(h)
    if mt and (mt.__index or mt.__newindex) then __d("gv") end
  end
  if not game or not typeof or game.ClassName~="DataModel" then __d("rb") end
  if not pc(function() local p=Instance.new("Part"); p:Destroy() end) then __d("in") end
end
__g()
`;}
const R=(a,b)=>a+Math.floor(Math.random()*(b-a+1));
const id=(n=7)=>{let s='_';const c='Il';for(let i=0;i<n;i++)s+=c[R(0,1)]+R(0,9);return s};
function encryptStrings(code){
  const pool=[];
  const out=String(code).replace(/"(?:\\.|[^"\\])*"/g,(m)=>{
    if(m.length<5||m.length>140) return m;
    let inner; try{inner=JSON.parse(m);}catch{return m;}
    if(typeof inner!=='string'||!/[A-Za-z]/.test(inner)) return m;
    const i=pool.length; pool.push(inner); return `__S[${i}]`;
  });
  if(!pool.length) return code;
  const key=R(25,220);
  const enc=pool.map(s=>{const b=Buffer.from(s,'utf8');const a=[];for(let i=0;i<b.length;i++)a.push(b[i]^key^((i*7)%251));return '{'+a.join(',')+'}';});
  return `local __SK=${key}\nlocal __SP={${enc.join(',')}}\nlocal __S={}\nfor i=1,#__SP do local t=__SP[i] local o={} for j=1,#t do o[j]=string.char(bit32.bxor(t[j],__SK,((j-1)*7)%251)) end __S[i-1]=table.concat(o) end\n`+out;
}
function numbersToExpr(code){
  return String(code).replace(/\b(\d{2,5})\b/g,(m,n)=>{const v=+n;if(v<12||v>50000||Math.random()>0.5)return m;const a=R(1,v-1);return `(${a}+${v-a})`;});
}
function renameLocals(code){
  const map=new Map();
  let c=String(code).replace(/\blocal\s+([a-zA-Z_][a-zA-Z0-9_]*)\b/g,(f,n)=>{
    if(['function','nil','true','false'].includes(n))return f;
    if(!map.has(n))map.set(n,id(6));return 'local '+map.get(n);
  });
  for(const [from,to] of map)c=c.replace(new RegExp('\\b'+from+'\\b','g'),to);
  return c;
}
function junk(){const a=id(4),b=id(4),n=R(100,9000);return `do local ${a}=${n} local ${b}=${a}-${a} if ${b}~=0 then return end end`;}
function wrap(code){const n=id(7);return `local function ${n}(...)\n${code}\nend\nreturn ${n}(...)`;}
function controlFlow(code){const k=R(1000,9999);return `do local __cf=${k}\nif __cf==${k} then\n${code}\nelse while true do end end\nend`;}
function obfuscate(source,opts={}){
  const withAnti=opts.antiTamper!==false;
  let code=String(source||'');
  if(!code.trim())throw new Error('Empty code');
  if(code.length>800000)throw new Error('Too large');
  if(withAnti)code=antiTamper()+'\n'+code;
  try{code=encryptStrings(code);}catch{}
  try{code=numbersToExpr(code);}catch{}
  try{code=renameLocals(code);}catch{}
  code=junk()+'\n'+controlFlow(wrap(code))+'\n'+junk();
  return '-- Protect by QyrexObf\n'+code;
}
module.exports={obfuscate};
