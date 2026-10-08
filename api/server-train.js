const RATE_PER_MILLION = 2;
const MAX_CHARS = 2_000_000;

export default function handler(req,res){
  res.setHeader('Cache-Control','no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  if(req.method!=='POST') return res.status(405).json({error:{code:'method_not_allowed',message:'Use POST.'}});
  const body=typeof req.body==='string'?JSON.parse(req.body||'{}'):(req.body||{});
  if(body.action!=='estimate') return res.status(400).json({error:{code:'invalid_action',message:'Unsupported action.'}});
  const n=Number(body.characters);
  if(!Number.isSafeInteger(n)||n<1) return res.status(400).json({error:{code:'invalid_characters',message:'characters must be a positive integer.'}});
  if(n>MAX_CHARS) return res.status(413).json({error:{code:'dataset_too_large_for_preview','message':'This server-training preview accepts up to 2,000,000 characters.'}});
  return res.status(200).json({characters:n,rate_per_million:RATE_PER_MILLION,estimated_cost:Number((n/1000000*RATE_PER_MILLION).toFixed(2))});
}