import { NovaModel, BPETokenizer } from "../supabase/functions/_shared/engine.js";

export const config = { maxDuration: 300 };

const SBURL="https://jtstdajaaasucialvsfs.supabase.co";
const SBKEY="sb_publishable_1O9wO2dY_ZFFfdPFGaLeMA_3oaW2Hs-";
const TRAINING_URL=SBURL+"/functions/v1/server-training";
const headers=(jwt)=>({"apikey":SBKEY,"Authorization":"Bearer "+jwt,"Content-Type":"application/json"});
const j=(res,s=200)=>res.status(s).json(res.body);

async function edge(jwt,body){
  const r=await fetch(TRAINING_URL,{method:"POST",headers:headers(jwt),body:JSON.stringify(body)});
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data.error||"Server Training request failed.");
  return data;
}
async function downloadInput(jwt,path){
  const safe=path.split("/").map(encodeURIComponent).join("/");
  const r=await fetch(SBURL+"/storage/v1/object/authenticated/nova-deploy-models/"+safe,{headers:{"apikey":SBKEY,"Authorization":"Bearer "+jwt}});
  if(!r.ok) throw new Error("Training data could not be read.");
  return await r.text();
}
function batches(tokens,ctx,batchSize){
  const maxStart=Math.max(1,tokens.length-ctx-1);
  const out=[];
  for(let b=0;b<batchSize;b++){
    const start=Math.floor(Math.random()*maxStart);
    out.push({input:tokens.slice(start,start+ctx),target:tokens.slice(start+1,start+ctx+1)});
  }
  return out;
}
async function train(text,onProgress){
  const clean=text.replace(/\u0000/g,"");
  const tokenizer=new BPETokenizer();
  tokenizer.train(clean,256,2);
  const ids=tokenizer.encode(clean,true,true);
  if(ids.length<66) throw new Error("Training data is too small after tokenization.");
  const cfg={dModel:32,nHeads:2,nLayers:1,dFF:64,ctxLen:64};
  const model=new NovaModel(tokenizer.size,cfg);
  model.eosId=tokenizer.vocab["<EOS>"];
  const steps=Math.min(64,Math.max(8,Math.floor(ids.length/256)));
  let last=0;
  for(let step=0;step<steps;step++){
    const bs=batches(ids,cfg.ctxLen,2);
    const loss=model.trainStep(bs.map(x=>x.input),bs.map(x=>x.target),0.002);
    if(step===0||step+1===steps||step-last>=4){
      last=step;
      await onProgress(step+1,steps,loss);
      await new Promise(r=>setTimeout(r,0));
    }
  }
  return {
    format:"nova-model",
    version:1,
    config:cfg,
    vocabSize:tokenizer.size,
    weights:model.serializeWeights(),
    tokenizer:tokenizer.toJSON(),
    stepCount:model.stepCount,
    epochsDone:1,
    paramCount:model.paramCount(),
    createdAt:new Date().toISOString()
  };
}
export default async function handler(req,res){
  if(req.method!=="POST") return res.status(405).json({error:"Method not allowed."});
  const auth=String(req.headers.authorization||"");
  if(!auth.startsWith("Bearer ")) return res.status(401).json({error:"Sign in first."});
  const jwt=auth.slice(7);
  let jobId;
  try{
    const body=typeof req.body==="object"&&req.body?req.body:JSON.parse(req.body||"{}");
    jobId=String(body.jobId||"");
    if(!jobId) return res.status(400).json({error:"Missing training job."});
    const status=await edge(jwt,{action:"status",jobId});
    const job=status.job;
    if(!job) return res.status(404).json({error:"Training job not found."});
    if(job.status==="completed") return res.status(200).json({ok:true,job});
    const path=String(job.metadata?.input_path||"");
    if(!path) throw new Error("Training input is missing.");
    const text=await downloadInput(jwt,path);
    const model=await train(text,async(done,total,loss)=>{
      await edge(jwt,{action:"progress",jobId,steps_done:done});
    });
    const raw=JSON.stringify(model);
    const bytes=Buffer.from(raw,"utf8");
    const b64=bytes.toString("base64");
    const completed=await edge(jwt,{action:"complete",jobId,data:b64,name:"nova-model.json"});
    const final=await edge(jwt,{action:"status",jobId});
    return res.status(200).json({ok:true,model_id:job.model_id,steps:model.stepCount,parameters:model.paramCount,loss:0,job:final.job});
  }catch(e){
    try{if(jobId) await edge(jwt,{action:"fail",jobId,error:e?.message||"Training failed."});}catch{}
    return res.status(500).json({error:e?.message||"Server Training failed."});
  }
}