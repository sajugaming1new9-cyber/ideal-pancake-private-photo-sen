const encoder = new TextEncoder();
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {
  status, headers: {"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}
});
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const random = (n=32) => crypto.getRandomValues(new Uint8Array(n));
const hex = (buf) => [...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,"0")).join("");
async function sha(s){return hex(await crypto.subtle.digest("SHA-256",encoder.encode(s)));}
async function pbkdf(password,salt){
  const key=await crypto.subtle.importKey("raw",encoder.encode(password),"PBKDF2",false,["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:encoder.encode(salt),iterations:210000,hash:"SHA-256"},key,256));
}
async function hmac(text,secret){
  const k=await crypto.subtle.importKey("raw",encoder.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  return b64url(await crypto.subtle.sign("HMAC",k,encoder.encode(text)));
}
function cookie(req,name){
  const c=req.headers.get("Cookie")||"";
  return c.split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="))?.slice(name.length+1)||"";
}
async function admin(req,env){
  const val=cookie(req,"vault_session"); if(!val) return false;
  const [exp,sig]=val.split("."); if(!exp||!sig||Number(exp)<Date.now())return false;
  return (await hmac(exp,env.SESSION_SECRET))===sig;
}
function headersNoCache(){return {"cache-control":"no-store, no-cache, must-revalidate","pragma":"no-cache","x-content-type-options":"nosniff","referrer-policy":"no-referrer"}}
function corsHeaders(){return {}}
async function route(req,env){
  const url=new URL(req.url), path=url.pathname, method=req.method;
  if(method==="GET"&&path==="/api/status") return json({ok:true});
  if(method==="POST"&&path==="/api/login"){
    const body=await req.json().catch(()=>({}));
    if(typeof body.password!=="string"||body.password.length>256)return json({error:"Invalid password"},400);
    // Set MASTER_PASSWORD as a Worker secret; never put it in source control.
    if(body.password!==env.MASTER_PASSWORD)return json({error:"Wrong password"},401);
    const exp=String(Date.now()+8*60*60*1000), sig=await hmac(exp,env.SESSION_SECRET);
    return json({ok:true},200,{"set-cookie":`vault_session=${exp}.${sig}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`});
  }
  if(method==="POST"&&path==="/api/logout")return json({ok:true},200,{"set-cookie":"vault_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"});
  if(method==="GET"&&path==="/api/me")return json({authenticated:await admin(req,env)});
  if(path.startsWith("/api/admin/") && !(await admin(req,env)))return json({error:"Unauthorized"},401);
  if(method==="POST"&&path==="/api/admin/photo"){
    const ct=req.headers.get("content-type")||"";
    if(!ct.startsWith("image/"))return json({error:"Choose an image"},415);
    const allowed=["image/jpeg","image/png","image/webp","image/gif"];
    if(!allowed.includes(ct.split(";")[0]))return json({error:"Allowed: JPEG, PNG, WEBP, GIF"},415);
    const bytes=await req.arrayBuffer();
    if(bytes.byteLength<1||bytes.byteLength>4*1024*1024)return json({error:"Image must be 1 byte to 4 MB"},413);
    await env.DB.prepare("INSERT INTO photo(id,mime,bytes,updated_at) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET mime=excluded.mime,bytes=excluded.bytes,updated_at=excluded.updated_at")
      .bind(ct.split(";")[0],bytes,Date.now()).run();
    return json({ok:true});
  }
  if(method==="GET"&&path==="/api/admin/photo"){
    const p=await env.DB.prepare("SELECT mime,bytes FROM photo WHERE id=1").first();
    if(!p)return json({error:"Upload a photo first"},404);
    return new Response(p.bytes,{headers:{"content-type":p.mime,"cache-control":"no-store","x-content-type-options":"nosniff"}});
  }
  if(method==="POST"&&path==="/api/admin/links"){
    const p=await env.DB.prepare("SELECT id FROM photo WHERE id=1").first();
    if(!p)return json({error:"Upload your photo first"},400);
    const token=b64url(random(32)), otp=String(crypto.getRandomValues(new Uint32Array(1))[0]%900000+100000);
    const salt=b64url(random(16)), id=b64url(random(12)), now=Date.now(), expires=now+24*60*60*1000;
    await env.DB.prepare("INSERT INTO links(id,token_hash,otp_salt,otp_hash,created_at,expires_at,used_at,failed_attempts,locked_until) VALUES(?,?,?,?,?,?,NULL,0,NULL)")
      .bind(id,await sha(token),salt,await pbkdf(otp,salt),now,expires).run();
    return json({ok:true,url:new URL("/view/"+token,url.origin).href,password:otp,expiresAt:expires});
  }
  const view=path.match(/^\/api\/view\/([A-Za-z0-9_-]+)$/);
  if(method==="POST"&&view){
    const body=await req.json().catch(()=>({}));
    if(typeof body.password!=="string"||!/^\d{6}$/.test(body.password))return json({error:"Enter the 6-digit password"},400);
    const th=await sha(view[1]);
    const link=await env.DB.prepare("SELECT id,otp_salt,otp_hash,expires_at,used_at,failed_attempts,locked_until FROM links WHERE token_hash=?").bind(th).first();
    if(!link||link.used_at||link.expires_at<Date.now())return json({error:"This link is invalid, expired, or already used"},410);
    if(link.locked_until && link.locked_until>Date.now())return json({error:"Too many attempts. This link is temporarily locked."},429);
    if((await pbkdf(body.password,link.otp_salt))!==link.otp_hash){
      const updated=await env.DB.prepare("UPDATE links SET failed_attempts=failed_attempts+1, locked_until=CASE WHEN failed_attempts+1>=6 THEN ? ELSE locked_until END WHERE id=? AND used_at IS NULL AND expires_at>? RETURNING failed_attempts")
        .bind(Date.now()+15*60*1000,link.id,Date.now()).first();
      const tries=updated?.failed_attempts??6;
      return json({error:tries>=6?"Too many incorrect attempts. Link locked for 15 minutes.":"Incorrect password. Attempts remaining: "+(6-tries)},tries>=6?429:401);
    }
    // Conditional update is the single-use gate. Only one request can win.
    const won=await env.DB.prepare("UPDATE links SET used_at=? WHERE id=? AND used_at IS NULL AND expires_at>? RETURNING id")
      .bind(Date.now(),link.id,Date.now()).first();
    if(!won)return json({error:"This link was already used"},410);
    const photo=await env.DB.prepare("SELECT mime,bytes FROM photo WHERE id=1").first();
    if(!photo)return json({error:"Photo is no longer available"},404);
    return new Response(photo.bytes,{headers:{"content-type":photo.mime,"cache-control":"no-store, no-cache, must-revalidate","x-content-type-options":"nosniff","content-disposition":"inline","referrer-policy":"no-referrer"}});
  }
  return env.ASSETS.fetch(req);
}
export default {fetch:route};
