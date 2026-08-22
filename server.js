const express=require('express');
const cors=require('cors');
const path=require('path');
const {obfuscate}=require('./obfuscate');
const app=express();
const PORT=process.env.PORT||10000;
app.use(cors({origin:true}));
app.use(express.json({limit:'2mb'}));
app.get('/api/health',(q,s)=>s.json({ok:true,service:'QyrexObf'}));
app.post('/api/obfuscate',(req,res)=>{
  try{
    const code=(req.body&&(req.body.code||req.body.source))||'';
    const antiTamper=!(req.body&&req.body.antiTamper===false);
    if(!String(code).trim())return res.status(400).json({success:false,error:'code required'});
    const out=obfuscate(code,{antiTamper});
    res.json({success:true,code:out,brand:'QyrexObf'});
  }catch(e){res.status(500).json({success:false,error:e.message});}
});
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(q,s)=>s.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,'0.0.0.0',()=>console.log('QyrexObf',PORT));
