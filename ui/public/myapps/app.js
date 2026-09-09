const TOKEN_KEY="marketsphere.myapps.tokens";
const PKCE_KEY="marketsphere.myapps.pkce";
const RECENT_KEY="marketsphere.myapps.applicationSettings";
const RECENT_LIMIT=3;
const API_BASE="http://localhost:4000";
let config,tokens,apps=[],currentIdentity="user",profileInfo=null;
const $=id=>document.getElementById(id);

function b64(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function rnd(n=32){const b=new Uint8Array(n);crypto.getRandomValues(b);return b64(b)}
async function sha(v){return crypto.subtle.digest("SHA-256",new TextEncoder().encode(v))}
function jwt(t){const p=t.split(".")[1].replace(/-/g,"+").replace(/_/g,"/");return JSON.parse(decodeURIComponent(escape(atob(p))))}
function client(){const c=config?.clients?.appPortal;if(!c?.clientId)throw new Error("Application Portal OIDC client is missing from runtime configuration.");return c}
function loadTokens(){try{return JSON.parse(sessionStorage.getItem(TOKEN_KEY)||"null")}catch{return null}}
function expired(t){if(!t?.id_token)return true;try{return jwt(t.id_token).exp<=Math.floor(Date.now()/1000)+10}catch{return true}}
async function loadConfig(){const r=await fetch(`${API_BASE}/api/config`,{cache:"no-store"});if(!r.ok)throw new Error(`Runtime configuration unavailable (${r.status}).`);return r.json()}

async function begin(){
  const c=client(),verifier=rnd(48),state=rnd(20),nonce=rnd(20),challenge=b64(await sha(verifier));
  sessionStorage.setItem(PKCE_KEY,JSON.stringify({verifier,state,nonce}));
  const p=new URLSearchParams({response_type:"code",client_id:c.clientId,redirect_uri:c.redirectUri,scope:c.scopes||"openid profile email internal_login",state,nonce,code_challenge:challenge,code_challenge_method:"S256"});
  location.assign(`${config.authorizationEndpoint}?${p}`);
}

async function finish(){
  const p=new URLSearchParams(location.search);
  if(p.get("error"))throw new Error(p.get("error_description")||p.get("error"));
  const code=p.get("code");if(!code)return null;
  const saved=JSON.parse(sessionStorage.getItem(PKCE_KEY)||"{}");
  if(!saved.verifier||saved.state!==p.get("state"))throw new Error("OIDC state/PKCE validation failed.");
  const c=client(),body=new URLSearchParams({grant_type:"authorization_code",client_id:c.clientId,redirect_uri:c.redirectUri,code,code_verifier:saved.verifier});
  const r=await fetch(config.tokenEndpoint,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});
  const value=await r.json();if(!r.ok)throw new Error(value.error_description||value.error||"Authorization code exchange failed.");
  const cl=jwt(value.id_token),aud=Array.isArray(cl.aud)?cl.aud:[cl.aud];
  if(cl.iss!==config.issuer)throw new Error("OIDC issuer validation failed.");
  if(!aud.includes(c.clientId))throw new Error("OIDC audience validation failed.");
  if(cl.nonce!==saved.nonce)throw new Error("OIDC nonce validation failed.");
  sessionStorage.removeItem(PKCE_KEY);sessionStorage.setItem(TOKEN_KEY,JSON.stringify(value));history.replaceState({},"","/myapps/");return value;
}

function normalize(payload){
  const list=Array.isArray(payload)?payload:payload.applications||payload.items||payload.Resources||payload.results||[];
  return list.map((a,i)=>({id:String(a.id||a.applicationId||a.clientId||a.name||i),name:a.name||a.displayName||a.applicationName||"Application",description:a.description||a.applicationDescription||"",accessUrl:a.accessUrl||a.accessURL||a.url||a.homepageUrl||"",imageUrl:a.imageUrl||a.image||a.logoUrl||a.logo||""}))
    .filter(a=>a.accessUrl);
}
async function catalog(){
  const r=await fetch(`${API_BASE}/api/discoverable-applications`,{headers:{Authorization:`Bearer ${tokens.access_token}`},cache:"no-store"});
  const body=await r.text();
  if(!r.ok)throw new Error(`WSO2 discoverable applications returned ${r.status}: ${body.slice(0,180)}`);
  return normalize(JSON.parse(body));
}

async function loadProfile(){
  const r=await fetch(`${API_BASE}/api/my-profile`,{
    headers:{Authorization:`Bearer ${tokens.access_token}`},
    cache:"no-store"
  });
  const body=await r.text();
  if(!r.ok)throw new Error(`WSO2 profile returned ${r.status}: ${body.slice(0,180)}`);
  return JSON.parse(body);
}

function resolveProfileUsername(profile){
  if(profile?.name?.givenName)return profile.name.givenName;
  if(profile?.name?.familyName)return profile.name.familyName;
  if(profile?.userName){
    const parts=String(profile.userName).split("/");
    return parts.length>1?parts[parts.length-1]:profile.userName;
  }
  return "";
}

function resolveProfileEmail(profile){
  const username=resolveProfileUsername(profile);
  const emails=Array.isArray(profile?.emails)?profile.emails:[];

  const primary=emails.find(email=>email&&typeof email==="object"&&email.primary===true);
  if(primary?.value&&primary.value!==username)return primary.value;

  for(const email of emails){
    if(typeof email==="string"&&email&&email!==username)return email;
  }

  for(const email of emails){
    if(email?.value&&email.value!==username)return email.value;
  }

  return "";
}

function setUserAvatar(element,profile,username){
  element.replaceChildren();

  if(profile?.profileUrl){
    const image=document.createElement("img");
    image.src=profile.profileUrl;
    image.alt="";
    image.referrerPolicy="no-referrer";
    image.onerror=()=>element.replaceChildren(document.createTextNode(initials(username)));
    element.appendChild(image);
    return;
  }

  element.textContent=initials(username);
}

function initials(n){return(n||"U").split(/\s+/).filter(Boolean).slice(0,2).map(x=>x[0]).join("").toUpperCase()}
function letter(n){return(n||"A").trim().charAt(0).toUpperCase()}
function avatar(app,small=false){
  const el=document.createElement("div");el.className=`app-avatar${small?" small":""}`;
  if(app.imageUrl){const img=document.createElement("img");img.src=app.imageUrl;img.alt="";img.onerror=()=>el.replaceChildren(document.createTextNode(letter(app.name)));el.appendChild(img)}
  else el.textContent=letter(app.name);
  return el;
}
function settings(){try{return JSON.parse(localStorage.getItem(RECENT_KEY)||"{}")}catch{return{}}}
function recentIds(){const s=settings();return Array.isArray(s?.[currentIdentity]?.recentApplications)?s[currentIdentity].recentApplications:[]}
function recordRecent(id){const s=settings();if(!s[currentIdentity])s[currentIdentity]={recentApplications:[]};const old=Array.isArray(s[currentIdentity].recentApplications)?s[currentIdentity].recentApplications:[];s[currentIdentity].recentApplications=[id,...old.filter(x=>x!==id)].slice(0,RECENT_LIMIT);localStorage.setItem(RECENT_KEY,JSON.stringify(s))}
function openApp(app){recordRecent(app.id);const a=document.createElement("a");a.href=app.accessUrl;a.target="_blank";a.rel="noopener";a.click();render()}

function recentCard(app){
  const card=document.createElement("div");card.className="recent-card";card.tabIndex=0;card.setAttribute("role","link");
  const image=document.createElement("div");image.className="recent-card-image";image.appendChild(avatar(app));
  const content=document.createElement("div");content.className="recent-card-content";
  const name=document.createElement("div");name.className="recent-card-name";name.textContent=app.name;
  const desc=document.createElement("div");desc.className="recent-card-description";desc.textContent=app.description||"Enterprise application";
  content.append(name,desc);card.append(image,content);
  const open=()=>openApp(app);card.addEventListener("click",open);card.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();open()}});
  return card;
}
function listItem(app){
  const item=document.createElement("div");item.className="application-list-item";item.tabIndex=0;item.setAttribute("role","link");
  item.appendChild(avatar(app,true));
  const content=document.createElement("div");content.className="application-list-content";
  const name=document.createElement("div");name.className="application-list-name";name.textContent=app.name;
  const desc=document.createElement("div");desc.className="application-list-description";desc.textContent=app.description||"Enterprise application";
  content.append(name,desc);
  const icon=document.createElementNS("http://www.w3.org/2000/svg","svg");icon.setAttribute("class","application-open-icon");icon.setAttribute("width","18");icon.setAttribute("height","18");icon.setAttribute("viewBox","0 0 24 24");icon.innerHTML='<path d="M14 5h5v5M19 5l-8 8M18 13v6H5V6h6" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>';
  item.append(content,icon);
  const open=()=>openApp(app);item.addEventListener("click",open);item.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();open()}});
  return item;
}

function render(){
  const raw=$("search").value.trim(),q=raw.toLowerCase();
  const filtered=apps.filter(a=>!q||`${a.name} ${a.description}`.toLowerCase().includes(q)).sort((a,b)=>a.name.localeCompare(b.name));
  $("apps").replaceChildren(...filtered.map(listItem));
  $("searchIndicator").textContent=q?`${filtered.length} result${filtered.length===1?"":"s"} for "${raw}"`:"";
  const recent=recentIds().map(id=>apps.find(a=>a.id===id)).filter(Boolean);
  const showRecent=!q&&recent.length>0;
  $("recentApps").replaceChildren(...recent.map(recentCard));
  $("recentSection").classList.toggle("hidden",!showRecent);
  $("allHeading").classList.toggle("hidden",showRecent);
  $("empty").classList.toggle("hidden",filtered.length!==0);
  $("apps").classList.toggle("hidden",filtered.length===0);
}

function showUser(){
  const username=resolveProfileUsername(profileInfo)||"User";
  const email=resolveProfileEmail(profileInfo);

  currentIdentity=profileInfo?.userName||username;

  setUserAvatar($("avatar"),profileInfo,username);
  setUserAvatar($("menuAvatar"),profileInfo,username);

  $("headerUserName").textContent=username;
  $("userName").textContent=username;
  $("userEmail").textContent=email;
}
async function logout(){
  const idToken=tokens?.id_token;
  const oidc=client();

  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(PKCE_KEY);

  if(!idToken){
    location.assign("/myapps/");
    return;
  }

  const params=new URLSearchParams({
    id_token_hint:idToken,
    post_logout_redirect_uri:oidc.postLogoutRedirectUri||"http://localhost:3000/myapps/"
  });

  location.assign(`${config.logoutEndpoint}?${params}`);
}
function closeMenu(){$("userMenu").classList.add("hidden");$("avatarButton").setAttribute("aria-expanded","false")}
function toggleNav(){const n=$("sideNav"),o=$("mobileOverlay"),opening=!n.classList.contains("open");n.classList.toggle("open",opening);o.classList.toggle("hidden",!opening)}
function fail(e){console.error(e);$("loading").classList.add("hidden");$("shell").classList.add("hidden");$("error").classList.remove("hidden");$("errorMessage").textContent=e?.message||String(e)}

async function main(){
  try{
    config=await loadConfig();tokens=await finish()||loadTokens();
    if(!tokens||expired(tokens)){sessionStorage.removeItem(TOKEN_KEY);await begin();return}
    apps=await catalog();profileInfo=await loadProfile();showUser();render();
    $("search").addEventListener("input",render);
    $("clearSearch").addEventListener("click",()=>{$("search").value="";$("search").focus();render()});
    $("avatarButton").addEventListener("click",e=>{e.stopPropagation();const m=$("userMenu"),opening=m.classList.contains("hidden");m.classList.toggle("hidden",!opening);$("avatarButton").setAttribute("aria-expanded",String(opening))});
    $("signOut").addEventListener("click",logout);$("mobileNavToggle").addEventListener("click",toggleNav);$("mobileOverlay").addEventListener("click",toggleNav);
    document.addEventListener("click",e=>{if(!$("userMenu").contains(e.target)&&!$("avatarButton").contains(e.target))closeMenu()});
    $("loading").classList.add("hidden");$("shell").classList.remove("hidden");
  }catch(e){fail(e)}
}
main();
