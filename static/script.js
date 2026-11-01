const $ = id => document.getElementById(id);
async function call(url, options={}) {
  const r=await fetch(url,options), d=await r.json().catch(()=>({}));
  if(!r.ok || d.success===false) throw new Error(d.error||"Request failed");
  return d;
}
function post(url,obj){return call(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(obj)});}
function result(id,msg,type="notice"){const e=$(id);e.className="notice "+type;e.textContent=msg;}
function escapeHTML(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
document.querySelectorAll("[data-copy]").forEach(b=>b.onclick=()=>{const v=$(b.dataset.copy).value||$(b.dataset.copy).textContent;if(!v)return alert("Nothing to copy");navigator.clipboard.writeText(v).then(()=>alert("Copied"));});
$("generate").onclick=async()=>{const b=$("generate");b.disabled=true;try{const d=await post("/api/keys",{key_size:Number($("keySize").value),passphrase:$("keyPass").value});$("publicKey").value=d.public_key;$("fingerprint").textContent=d.fingerprint;$("sizeValue").textContent=d.key_size+" bits";result("keyStatus","RSA key pair generated. Private key is encrypted on disk.","success");await refresh();}catch(e){result("keyStatus",e.message,"failure");}finally{b.disabled=false;}};
$("sign").onclick=async()=>{try{const d=await post("/api/sign",{message:$("messageText").value,passphrase:$("signPass").value});$("hash").value=d.hash;$("signature").value=d.signature;$("modified").value=$("messageText").value;result("verifyResult","Signature generated. Now verify the original message.","success");await refresh();}catch(e){result("verifyResult",e.message,"failure");}};
async function verify(message,target){try{const d=await post("/api/verify",{message,signature:$("signature").value,public_key:$("publicKey").value});result(target,d.message,d.valid?"success":"failure");await refresh();}catch(e){result(target,e.message,"failure");}}
$("verify").onclick=()=>verify($("messageText").value,"verifyResult");
$("tamperVerify").onclick=()=>verify($("modified").value,"tamperResult");
$("clear").onclick=()=>{["messageText","hash","signature","modified"].forEach(x=>$(x).value="");result("verifyResult","Fields cleared.");result("tamperResult","Tampering test not run.");};
$("signFile").onclick=async()=>{const f=$("fileSign").files[0];if(!f)return result("fileResult","Choose a file first.","failure");const form=new FormData();form.append("file",f);form.append("passphrase",$("filePass").value);try{const d=await call("/api/file/sign",{method:"POST",body:form});$("fileHash").value=d.hash;$("fileSig").value=d.signature;$("fileSigVerify").value=d.signature;result("fileResult","File signed: "+d.filename,"success");await refresh();}catch(e){result("fileResult",e.message,"failure");}};
$("downloadSig").onclick=()=>{if(!$("fileSig").value)return alert("Sign a file first");const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([$("fileSig").value]));a.download="digital_signature.sig";a.click();URL.revokeObjectURL(a.href);};
$("verifyFile").onclick=async()=>{const f=$("fileVerify").files[0];if(!f)return result("fileResult","Choose a file to verify.","failure");const form=new FormData();form.append("file",f);form.append("signature",$("fileSigVerify").value);form.append("public_key",$("filePublic").value);try{const d=await call("/api/file/verify",{method:"POST",body:form});result("fileResult",d.message+" SHA-256: "+d.hash,d.valid?"success":"failure");await refresh();}catch(e){result("fileResult",e.message,"failure");}};
$("loadCert").onclick=async()=>{try{const d=await call("/api/certificate");$("certInfo").innerHTML=["subject","issuer","serial","valid_from","valid_until","fingerprint"].map(k=>`<p><b>${k.replace("_"," ")}:</b> ${escapeHTML(d[k])}</p>`).join("");}catch(e){result("certInfo",e.message,"failure");}};
$("refresh").onclick=refresh;
async function refresh(){try{const d=await call("/api/audit");$("total").textContent=d.stats.total;$("signed").textContent=d.stats.signed;$("valid").textContent=d.stats.valid;$("invalid").textContent=d.stats.invalid;$("logs").innerHTML=d.logs.length?d.logs.map(x=>`<tr><td>${escapeHTML(new Date(x.created_at).toLocaleString())}</td><td>${escapeHTML(x.event)}</td><td>${escapeHTML(x.status)}</td><td>${escapeHTML(x.details||"")}</td></tr>`).join(""):'<tr><td colspan="4">No events yet.</td></tr>';}catch(e){console.error(e);}}
refresh();
