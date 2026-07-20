/**
 * Server-rendered HTML for the sign-in and consent steps of the OIDC flow.
 *
 * Kept as a self-contained, build-step-free module: no CDN and no external asset, so the
 * pages work offline/low-bandwidth and can be served by the app itself. A deployment is
 * expected to restyle these, but they are production-shaped, not a stub: responsive,
 * accessible, light/dark, and -- critically -- every interpolated value is HTML-escaped.
 *
 * Why the escaping matters: `client_id`, `scope`, and any error string originate in the
 * OIDC authorize request, which is attacker-controllable. Interpolating them raw (as the
 * earlier reference page did) is a reflected-XSS vector on the very page where a citizen
 * authenticates. Everything user-influenced goes through escapeHtml()/jsString() here.
 *
 * The CSS and JS are inline but NOT inlined blindly: every <style> and <script> carries a
 * per-response nonce, and there is not a single `onclick=`/`onsubmit=` attribute, because
 * event-handler attributes cannot be nonced and are therefore unconditionally blocked by
 * any CSP without `unsafe-inline`. That is what lets the controller serve these under
 * `script-src 'nonce-...'` with no `unsafe-inline` anywhere -- escaping is the first line
 * of defence against injection here, and the CSP is the second. Keep it that way: binding
 * handlers in the nonced script block is the house rule, not a style preference.
 */

/**
 * The Content-Security-Policy these pages are designed against.
 *
 * It lives here, next to the markup it constrains, so the policy and the pages cannot drift
 * apart -- and so a test can assert against the exact string the controller sends rather
 * than a copy of it. `default-src 'none'` denies by default; the absence of `unsafe-inline`
 * is what gives the nonce any meaning.
 */
export function cspHeader(nonce: string): string {
  return [
    "default-src 'none'",
    `style-src 'nonce-${nonce}'`,
    `script-src 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; ');
}

/** Escape a value for interpolation into HTML text or a double-quoted attribute. */
export function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string,
  );
}

/** Embed a string safely inside an inline <script>, closing-tag breakout included. */
function jsString(value: string): string {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

/** Human-readable descriptions for the scopes a citizen is asked to release. */
const SCOPE_LABELS: Record<string, string> = {
  profile: 'Your name, date of birth and gender',
  residency: 'Your residency status — state/area and assurance level',
  offline_access: 'Keep you signed in to this service',
  health: 'Access to Health services',
  tax: 'Access to Tax services',
  permits: 'Access to Permits services',
  subsidy: 'Access to Subsidy services',
};

/** Turn a raw scope string into the human-readable claims a citizen is consenting to. */
export function describeScopes(scope: string): string[] {
  const items = scope
    .split(/\s+/)
    .filter((s) => s && s !== 'openid')
    .map((s) => SCOPE_LABELS[s] ?? `Access to ${titleCase(s)} services`);
  // De-duplicate while preserving order.
  return [...new Set(items.length ? items : ['Your basic profile'])];
}

function titleCase(s: string): string {
  return s.replace(/[-_]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

const STYLES = `
:root{
  --bg:#f4f6f8; --card:#ffffff; --fg:#1a1f24; --muted:#5b6670; --border:#dbe1e6;
  --primary:#0b6b3a; --primary-fg:#ffffff; --primary-weak:#e6f2ec;
  --danger:#9a1c1c; --danger-weak:#fbeaea; --ring:#0b6b3a55; --radius:14px;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0f1417; --card:#171d22; --fg:#eef2f5; --muted:#9aa6b0; --border:#2a333a;
    --primary:#3fbf7f; --primary-fg:#05130c; --primary-weak:#12291d;
    --danger:#ff8f8f; --danger-weak:#2a1618; --ring:#3fbf7f55;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
  background:var(--bg); color:var(--fg);
  font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  padding:20px;
}
.card{
  width:100%; max-width:440px; background:var(--card); border:1px solid var(--border);
  border-radius:var(--radius); box-shadow:0 1px 3px rgba(0,0,0,.06),0 8px 24px rgba(0,0,0,.06);
  padding:28px 24px; animation:rise .25s ease both;
}
@media (prefers-reduced-motion:reduce){.card{animation:none}}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:18px}
.brand svg{flex:none}
.brand-name{font-weight:650;font-size:15px;letter-spacing:.2px}
h1{font-size:20px;margin:0 0 6px}
.sub{color:var(--muted);margin:0 0 18px;font-size:14px}
.sub b{color:var(--fg)}
.alert{
  background:var(--danger-weak); color:var(--danger); border:1px solid transparent;
  border-radius:10px; padding:10px 12px; font-size:14px; margin:0 0 16px;
}
.tabs{display:flex;gap:6px;background:var(--bg);padding:4px;border-radius:10px;margin:0 0 16px}
.tab{
  flex:1; appearance:none; border:0; background:transparent; color:var(--muted);
  font:inherit; font-weight:600; font-size:14px; padding:9px 8px; border-radius:8px; cursor:pointer;
}
.tab[aria-selected="true"]{background:var(--card);color:var(--fg);box-shadow:0 1px 2px rgba(0,0,0,.08)}
.tab:focus-visible{outline:2px solid var(--primary);outline-offset:1px}
.qr{
  display:grid;place-items:center; background:#fff; border:1px solid var(--border);
  border-radius:12px; padding:14px; margin:6px auto 10px; max-width:260px; aspect-ratio:1;
}
.qr svg{width:100%;height:auto;display:block}
.status{color:var(--muted);font-size:13px;text-align:center;margin:6px 0 0;min-height:1.2em}
.status.err{color:var(--danger)}
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--border);
  border-top-color:var(--primary);border-radius:50%;vertical-align:-2px;margin-right:6px;
  animation:sp .8s linear infinite}
@media (prefers-reduced-motion:reduce){.spin{animation:none}}
@keyframes sp{to{transform:rotate(360deg)}}
label{display:block;font-size:14px;font-weight:600;margin:0 0 6px}
input{
  width:100%; font:inherit; font-size:16px; padding:12px 12px; color:var(--fg);
  background:var(--card); border:1px solid var(--border); border-radius:10px;
}
input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 4px var(--ring)}
.hint{color:var(--muted);font-size:13px;margin:6px 0 0}
.btn{
  appearance:none; width:100%; margin-top:14px; font:inherit; font-weight:650; font-size:16px;
  padding:13px 16px; border-radius:10px; border:1px solid transparent; cursor:pointer;
  background:var(--primary); color:var(--primary-fg);
}
.btn:disabled{opacity:.6;cursor:progress}
.btn:focus-visible{outline:2px solid var(--fg);outline-offset:2px}
.btn.secondary{background:transparent;color:var(--fg);border-color:var(--border)}
.linkbtn{background:none;border:0;color:var(--primary);font:inherit;cursor:pointer;padding:6px 0;text-decoration:underline}
.claims{list-style:none;margin:8px 0 18px;padding:0;border:1px solid var(--border);border-radius:12px;overflow:hidden}
.claims li{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;font-size:14px}
.claims li+li{border-top:1px solid var(--border)}
.claims svg{flex:none;margin-top:2px;color:var(--primary)}
.privacy{display:flex;gap:8px;background:var(--primary-weak);border-radius:10px;padding:10px 12px;font-size:13px;color:var(--fg);margin:0 0 18px}
.privacy svg{flex:none;margin-top:1px;color:var(--primary)}
.actions{display:flex;gap:10px;align-items:center}
.actions .btn{margin-top:0;flex:1}
.deny{color:var(--muted);text-decoration:none;font-weight:600;font-size:14px;padding:12px}
.deny:hover{color:var(--fg)}
.foot{color:var(--muted);font-size:12px;text-align:center;margin:18px 0 0}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);border:0}
`;

const SHIELD = `<svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2l7 3v6c0 4.5-3 8-7 11-4-3-7-6.5-7-11V5l7-3z" fill="var(--primary-weak)" stroke="var(--primary)" stroke-width="1.6"/><path d="M8.5 12l2.3 2.3L15.5 9.7" stroke="var(--primary)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const CHECK = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const LOCK = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="4" y="10" width="16" height="10" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M8 10V7a4 4 0 118 0v3" stroke="currentColor" stroke-width="1.7"/></svg>`;

function layout(title: string, brand: string, body: string, nonce: string): string {
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${escapeHtml(title)}</title>
<style nonce="${escapeHtml(nonce)}">${STYLES}</style></head>
<body><main class="card" role="main">
<div class="brand">${SHIELD}<span class="brand-name">${escapeHtml(brand)}</span></div>
${body}
</main></body></html>`;
}

export interface LoginView {
  uid: string;
  brand: string;
  /** Friendly name of the requesting relying party, if known. */
  clientName?: string;
  error?: string;
  /** Per-response CSP nonce. Must match the `script-src`/`style-src` nonce on the header. */
  nonce: string;
}

export function loginPage(v: LoginView): string {
  const uid = escapeHtml(v.uid);
  const requester = v.clientName
    ? `<p class="sub"><b>${escapeHtml(v.clientName)}</b> wants to verify your residency to sign you in.</p>`
    : '';
  const alert = v.error ? `<div class="alert" role="alert">${escapeHtml(v.error)}</div>` : '';

  const body = `
<h1>Sign in with your Residency</h1>
${requester}
${alert}
<div class="tabs" role="tablist" aria-label="Sign-in method">
  <button class="tab" id="tab-vp" type="button" role="tab" aria-controls="pane-vp" aria-selected="true">Scan with wallet</button>
  <button class="tab" id="tab-otp" type="button" role="tab" aria-controls="pane-otp" aria-selected="false" tabindex="-1">Use a one-time code</button>
</div>

<section id="pane-vp" role="tabpanel" aria-labelledby="tab-vp">
  <p class="sub">Scan this code with your wallet app to present your residency credential.</p>
  <div class="qr" id="qr" aria-label="Sign-in QR code"><span class="status"><span class="spin"></span>Loading…</span></div>
  <p class="status" id="vp-status" role="status" aria-live="polite"><span class="spin"></span>Waiting for your wallet…</p>
</section>

<section id="pane-otp" role="tabpanel" aria-labelledby="tab-otp" hidden>
  <form id="otp-start">
    <label for="rid">Residency ID</label>
    <input id="rid" name="residentId" autocomplete="off" autocapitalize="characters"
           spellcheck="false" placeholder="KT-XXXX-XXXX-X" aria-describedby="rid-hint">
    <p class="hint" id="rid-hint">We'll send a one-time code to the contact registered for this ID.</p>
    <button class="btn" type="submit" id="send-btn">Send me a code</button>
  </form>
  <form id="otp-verify" method="post" action="/interaction/${uid}/otp/verify" hidden>
    <input type="hidden" id="rid2" name="residentId">
    <label for="code">Enter the code we sent</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
           pattern="[0-9]*" maxlength="8" placeholder="123456">
    <button class="btn" type="submit">Sign in</button>
    <button class="linkbtn" type="button" id="resend-btn">Send a new code</button>
    <p class="hint" id="resend-status" role="status" aria-live="polite"></p>
  </form>
</section>

<p class="foot">Your national ID number is never shared with the service you are signing in to.</p>

<script nonce="${escapeHtml(v.nonce)}">
const uid=${jsString(v.uid)};
const base='/interaction/'+encodeURIComponent(uid);
const $=(id)=>document.getElementById(id);

// ---- tabs ----------------------------------------------------------------
function show(which){
  const vp=which==='vp';
  $('tab-vp').setAttribute('aria-selected',vp); $('tab-otp').setAttribute('aria-selected',!vp);
  // Roving tabindex: only the selected tab is in the tab order, per the ARIA tabs pattern.
  $('tab-vp').tabIndex=vp?0:-1; $('tab-otp').tabIndex=vp?-1:0;
  $('pane-vp').hidden=!vp; $('pane-otp').hidden=vp;
  if(vp)startVp(); else setTimeout(()=>$('rid').focus(),0);
}
$('tab-vp').addEventListener('click',()=>show('vp'));
$('tab-otp').addEventListener('click',()=>show('otp'));
// Arrow keys move between tabs, which is the interaction a screen-reader user expects
// once role="tablist" is announced.
for(const id of ['tab-vp','tab-otp']){
  $(id).addEventListener('keydown',(e)=>{
    if(e.key!=='ArrowLeft'&&e.key!=='ArrowRight')return;
    e.preventDefault();
    const next=id==='tab-vp'?'otp':'vp';
    show(next); $('tab-'+next).focus();
  });
}

// ---- primary factor: wallet presentation ---------------------------------
let polling=false,tries=0,netFails=0;
async function startVp(){
  if(polling)return; polling=true;
  const status=$('vp-status');
  try{
    const r=await fetch(base+'/vp/start');
    if(!r.ok)throw new Error('start failed');
    const {requestId,qrSvg}=await r.json();
    $('qr').innerHTML=qrSvg;
    const tick=async()=>{
      try{
        const res=await fetch(base+'/vp/poll?requestId='+encodeURIComponent(requestId));
        // A 4xx/5xx is the server telling us this poll will never succeed -- an expired or
        // unknown interaction, most often. Retrying it for the full five minutes strands
        // the citizen on a spinner, so only genuine network failures are retried, and only
        // a few times.
        if(!res.ok){
          if(res.status>=400&&res.status<500){fail('This sign-in has expired. Refresh to try again.');return;}
          throw new Error('poll '+res.status);
        }
        netFails=0;
        const p=await res.json();
        if(p.status==='authenticated'){status.textContent='Signing you in…';window.location=base+'/vp/complete?requestId='+encodeURIComponent(requestId);return;}
        if(p.status==='failed'){fail('That presentation was not accepted. Refresh to try again.');return;}
      }catch(e){
        if(++netFails>5){fail('Lost connection. Refresh to try again.');return;}
      }
      if(++tries<150)setTimeout(tick,2000); else fail('Timed out. Refresh to try again.');
    };
    setTimeout(tick,2000);
  }catch(e){
    fail('Could not start sign-in. Refresh to try again.');
  }
  function fail(msg){ status.classList.add('err'); status.textContent=msg; }
}

// ---- fallback factor: one-time code --------------------------------------
async function requestCode(rid){
  try{
    await fetch(base+'/otp/start',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({residentId:rid})});
  }catch(e){/* delivery outcome is intentionally opaque; never surface it */}
}
$('otp-start').addEventListener('submit',async(e)=>{
  e.preventDefault();
  const rid=$('rid').value.trim(); if(!rid)return;
  const btn=$('send-btn'); btn.disabled=true; btn.textContent='Sending…';
  await requestCode(rid);
  $('rid2').value=rid; $('otp-start').hidden=true; $('otp-verify').hidden=false;
  btn.disabled=false; btn.textContent='Send me a code';
  setTimeout(()=>$('code').focus(),0);
});
// Actually send a new code, rather than bouncing the citizen back to re-type an ID they
// have already given us.
$('resend-btn').addEventListener('click',async()=>{
  const rid=$('rid2').value; if(!rid)return;
  const btn=$('resend-btn'); btn.disabled=true;
  await requestCode(rid);
  btn.disabled=false;
  $('resend-status').textContent='If that ID is registered, a new code is on its way.';
  $('code').focus();
});

show('vp');
</script>`;
  return layout('Sign in', v.brand, body, v.nonce);
}

export interface ConsentView {
  uid: string;
  brand: string;
  clientName?: string;
  scope: string;
  /** Per-response CSP nonce. Must match the `style-src` nonce on the header. */
  nonce: string;
}

export function consentPage(v: ConsentView): string {
  const uid = escapeHtml(v.uid);
  // No name means the client is registered with the OIDC provider but absent from country
  // config, so we have nothing vouched-for to show. Say that plainly rather than echoing a
  // raw client_id, which reads to a citizen as the name of the service asking.
  const who = escapeHtml(v.clientName ?? 'An unrecognised service');
  const claims = describeScopes(v.scope)
    .map((c) => `<li>${CHECK}<span>${escapeHtml(c)}</span></li>`)
    .join('');

  const body = `
<h1>Share your residency?</h1>
<p class="sub"><b>${who}</b> is asking to access:</p>
<ul class="claims">${claims}</ul>
<div class="privacy">${LOCK}<span>Your national ID number is never shared — only the residency details listed above, and only while you allow it.</span></div>
<form method="post" action="/interaction/${uid}/confirm" class="actions">
  <button class="btn" type="submit">Allow</button>
  <a class="deny" href="/interaction/${uid}/abort">Deny</a>
</form>`;
  return layout('Consent', v.brand, body, v.nonce);
}