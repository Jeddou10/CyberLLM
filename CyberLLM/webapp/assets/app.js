
const $ = s => document.querySelector(s);
const EXT = {py:".py",c:".c",cpp:".cpp",rust:".rs",java:".java",js:".js",go:".go"};
const SEV = ["critical","high","medium","low","info"];
const sevClass = s => SEV.includes((s||"").toLowerCase()) ? (s||"").toLowerCase() : "info";
const cap = s => (s||"").charAt(0).toUpperCase()+(s||"").slice(1);
const esc = s => (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let HEALTH=null;

async function loadHealth(){
  try{ const h=await (await fetch("/api/health")).json(); HEALTH=h;
    const real=h.llm_real;
    $("#provPill").innerHTML=`<span class="d ${real?'green':'amber'}"></span>LLM <b>${esc(h.llm_impl)}</b> · ${esc(h.llm_model)} <span style="color:var(--dim)">(${real?'live':'offline stub'})</span>`;
    refreshModeNote(); refreshBenchModeNote(); refreshAtkModeNote();
  }catch(e){ $("#provPill").innerHTML=`<span class="d gray"></span>provider unknown`; }
}
function tools(){ const t=HEALTH&&HEALTH.tools||{}; return Object.keys(t).filter(k=>t[k]); }
function refreshModeNote(){
  const deep=$("#deep").checked, real=HEALTH&&HEALTH.llm_real, av=tools();
  $("#modeNote").textContent = (deep&&real)?"Deep mode → live LLM refinement + auto-remediation of findings."
    :(deep&&!real)?"Deep requested but no live LLM — running deterministic regex"+(av.length?" + "+av.join("/"):"")+" only."
    :"Fast mode → deterministic regex"+(av.length?" + "+av.join("/"):"")+" (offline, instant). Fixed output needs Deep.";
}
function populateLoader(sel,data){ sel._data=[];
  const addGroup=(label,items)=>{ if(!items||!items.length)return; const og=document.createElement("optgroup"); og.label=label;
    items.forEach(ex=>{ const i=sel._data.length; sel._data[i]=ex; const o=document.createElement("option"); o.value=i; o.textContent=ex.name; og.appendChild(o); }); sel.appendChild(og); };
  addGroup("Examples",data.examples); addGroup("Benchmark corpus (automotive)",data.benchmark);
}
async function loadExamples(){ try{ const r=await (await fetch("/api/examples")).json();
  populateLoader($("#examples"),r); populateLoader($("#atkExamples"),r); }catch(e){} }
$("#atkExamples").addEventListener("change",e=>{ const d=e.target._data&&e.target._data[e.target.value]; if(!d)return;
  $("#atkCode").value=d.code; $("#atkFname").value=d.filename; });
$("#examples").addEventListener("change",e=>{ const d=e.target._data&&e.target._data[e.target.value]; if(!d)return;
  $("#code").value=d.code; $("#fname").value=d.filename;
  const ext=(d.filename.match(/\.(\w+)$/)||[])[1]; for(const k in EXT){ if(EXT[k]==="."+ext){ $("#lang").value=k; } }
  if(d.clean){ $("#loadHint").innerHTML="🧪 <b>Clean control</b> — a correct scan finds nothing here."; }
  else { $("#loadHint").textContent=""; }
});
$("#lang").addEventListener("change",e=>{ const f=$("#fname"); const base=(f.value.replace(/\.\w+$/,"")||"input"); f.value=base+(EXT[e.target.value]||".txt"); });
$("#deep").addEventListener("change",()=>{ refreshModeNote(); refreshBenchModeNote(); refreshAtkModeNote(); });

// ── shared viz ──────────────────────────────────────────────────────────────
function kpi(n,l,cls){ return `<div class="kpi ${cls||''}"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`; }
function flow(nodes){ return `<div class="flow">`+nodes.map((n,i)=>(i?'<span class="farrow">→</span>':'')+
  `<div class="fnode s-${n.s}${n.target?' clickable':''}"${n.target?` data-target="${n.target}"`:''}><span class="fdot"></span><div><div class="ft">${esc(n.t)}</div><div class="fv">${esc(n.v)}</div></div></div>`).join("")+`</div>`; }
function wireFlow(sel){ $(sel).querySelectorAll(".fnode[data-target]").forEach(n=>n.addEventListener("click",()=>{
  const t=$(n.dataset.target); if(!t)return; t.scrollIntoView({behavior:"smooth",block:"start"});
  t.classList.remove("cardflash"); void t.offsetWidth; t.classList.add("cardflash"); })); }
function sevDistribution(counts){ const total=SEV.reduce((s,k)=>s+(counts[k]||0),0); if(!total) return '';
  const segs=SEV.filter(s=>counts[s]).map(s=>`<div class="seg sev-${s}" style="flex:${counts[s]}" title="${counts[s]} ${s}"></div>`).join("");
  const legend=SEV.filter(s=>s!=="info"||counts.info).map(s=>`<button class="legend on" data-sev="${s}"><span class="sw"></span>${cap(s)} <b>${counts[s]||0}</b></button>`).join("");
  return `<div class="sevbar">${segs}</div><div class="legendrow">${legend}</div>`; }
function donut(pct,label){ const r=52,c=2*Math.PI*r,col=covColor(pct),off=c*(1-pct/100);
  return `<svg width="128" height="128" viewBox="0 0 128 128" role="img" aria-label="${label} ${pct}%">
    <circle cx="64" cy="64" r="${r}" fill="none" stroke="var(--panel3)" stroke-width="14"/>
    <circle cx="64" cy="64" r="${r}" fill="none" stroke="${col}" stroke-width="14" stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 64 64)"/>
    <text x="64" y="60" text-anchor="middle" fill="var(--txt)" font-size="26" font-weight="800" class="tnum">${pct}%</text>
    <text x="64" y="80" text-anchor="middle" fill="var(--dim)" font-size="10.5" letter-spacing=".5">${esc(label)}</text></svg>`; }

// ── scan ────────────────────────────────────────────────────────────────────
$("#scanBtn").addEventListener("click", runScan);
async function runScan(){
  const code=$("#code").value; if(!code.trim()){ showErr("Please paste some code first."); return; }
  const btn=$("#scanBtn"); btn.disabled=true; btn.innerHTML='<span class="spin"></span> Scanning…'; $("#err").style.display="none";
  try{ const res=await fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({code,filename:$("#fname").value||"input.py",log:$("#logtxt").value,deployment:$("#deptxt").value,deep:$("#deep").checked})});
    const data=await res.json(); if(!data.ok){ showErr(data.error||"scan failed"); return; } render(data);
  }catch(e){ showErr(String(e)); } finally{ btn.disabled=false; btn.textContent="Scan"; }
}
function showErr(m){ const e=$("#err"); e.textContent="⚠ "+m; e.style.display="block"; }

let REC=null, EXP={findings:[],code:"",sel:null,filter:new Set()}, REMEDY=null, REMEDY_STATE=null, LAST_SCAN=null;
function render(data){
  $("#placeholder").style.display="none"; $("#results").style.display="block";
  const rec=data.record||{}; REC=rec;
  const findings=(rec.findings||[]).slice().sort((a,b)=>SEV.indexOf(sevClass(a.severity))-SEV.indexOf(sevClass(b.severity)));
  EXP={findings,code:data.code||"",sel:null,filter:new Set()}; REMEDY=null; REMEDY_STATE=null;

  const tier=rec.decision&&rec.decision.recommended_tier||"—", gv=rec.guard_verdict||{}, allowed=gv.allowed;
  const conf=rec.decision?Math.round((rec.decision.confidence||0)*100):0;
  const counts={critical:0,high:0,medium:0,low:0,info:0}; findings.forEach(f=>counts[sevClass(f.severity)]++);
  $("#ovSub").textContent=esc(data.filename||"");
  $("#banner").innerHTML=`<span class="badge mode">${data.deep?'DEEP · AI':'FAST · static'}</span>`+
    `<span class="badge tier">tier: ${esc(tier)}</span>`+
    `<span class="badge ${allowed?'pass':'refused'}">guard: ${allowed?'PASS':'REFUSED'}</span>`+
    (rec.replanning?`<span class="pill">replan <b>${rec.replanning.rounds}</b> · ${rec.replanning.resolved?'resolved':'unresolved'}</span>`:"");
  const canRemedy=findings.length>0 && !!data.deep && !!(data.provider&&data.provider.llm_real);
  $("#kpis").innerHTML=kpi(findings.length,"findings","accent")+kpi(counts.critical,"critical","crit")+
    kpi(counts.high,"high","high")+kpi(counts.medium,"medium","med")+kpi(counts.low,"low","low")+
    kpi(conf+"%","confidence",conf>=70?"ok":(conf>=40?"med":""))+
    (canRemedy?`<div class="kpi ok"><div class="n" id="kpiResolvedN">…</div><div class="l">resolved</div></div>`:"");
  $("#sevWrap").innerHTML=findings.length?sevDistribution(counts):"";
  $("#sevWrap").querySelectorAll(".legend").forEach(el=>el.addEventListener("click",()=>{
    const s=el.getAttribute("data-sev"); if(EXP.filter.has(s)) EXP.filter.delete(s); else EXP.filter.add(s);
    $("#sevWrap").querySelectorAll(".legend").forEach(x=>{ const on=EXP.filter.size===0||EXP.filter.has(x.getAttribute("data-sev"));
      x.classList.toggle("on",on); x.classList.toggle("off",!on); }); renderExpList();
  }));
  $("#decisionSummary").textContent=rec.decision&&rec.decision.summary||"";
  $("#stages").innerHTML=scanStages(rec,data.deep); wireFlow("#stages");
  renderReasoning(rec); $("#rawjson").textContent=JSON.stringify(rec,null,2);

  // explorer
  $("#expCode").innerHTML=`<div class="exphint">Select a finding to view its code.</div>`;
  $("#expOutput").innerHTML=`<div class="exphint">—</div>`;
  renderExpList();
  $("#expSel").className="expsel"; $("#expSel").innerHTML="";

  // remediation / output panel
  LAST_SCAN=canRemedy?{code:data.code||"",filename:data.filename||"input.py",findings:findings}:null;
  $("#remedyCard").style.display=canRemedy?"":"none";
  const firstVisible=findings.findIndex(f=>EXP.filter.size===0||EXP.filter.has(sevClass(f.severity)));
  if(canRemedy){
    REMEDY_STATE="pending";
    $("#remedy").innerHTML=`<p class="note"><span class="spin" style="border-top-color:var(--accent)"></span> Auto-remediation running — rewriting the code and re-scanning to verify…</p>`;
    if(findings.length) selectFinding(firstVisible<0?0:firstVisible);
    autoRemediate();
  } else {
    REMEDY_STATE=null;
    if(findings.length) selectFinding(firstVisible<0?0:firstVisible);
    else { $("#expOutput").innerHTML=`<div class="exphint">No findings.</div>`; }
  }
  window.scrollTo({top:0,behavior:"smooth"});
}
function scanStages(rec,deep){ const findings=(rec.findings||[]),d=rec.decision||{},gv=rec.guard_verdict||{},a=rec.action||{};
  const tier=d.recommended_tier||'none', tierS={none:'ok',soft:'low',moderate:'med',hard:'crit'}[tier]||'accent';
  return flow([
    {t:"Detect",v:`${findings.length} finding${findings.length===1?'':'s'}`,s:findings.length?'accent':'ok',target:"#card-explorer"},
    {t:"Decide",v:`tier ${tier} · ${Math.round((d.confidence||0)*100)}%`,s:tierS,target:"#card-reasoning"},
    {t:"Act",v:`${a.kind||'—'} · dry-run`,s:'accent',target:"#card-reasoning"},
    {t:"Guard",v:gv.allowed?'PASS':'REFUSED',s:gv.allowed?'ok':'bad',target:"#card-reasoning"},
  ]); }
function renderExpList(){
  const {findings,filter,sel}=EXP;
  const show=findings.map((f,i)=>({f,i})).filter(o=>filter.size===0||filter.has(sevClass(o.f.severity)));
  $("#expCount").textContent=filter.size?`${show.length}/${findings.length}`:`${findings.length}`;
  if(!findings.length){ $("#expList").innerHTML=`<div class="exphint">✓ No issues detected.</div>`; return; }
  if(!show.length){ $("#expList").innerHTML=`<div class="exphint">None match the filter.</div>`; return; }
  $("#expList").innerHTML=show.map(({f,i})=>`<div class="expitem sev-${sevClass(f.severity)}${i===sel?' sel':''}" data-i="${i}">
    <span class="edot"></span><div><div>${esc(f.title)}</div><div class="erid">${esc(f.rule_id)}${f.line?(' · L'+f.line):''}</div></div></div>`).join("");
  $("#expList").querySelectorAll(".expitem").forEach(el=>el.addEventListener("click",()=>selectFinding(+el.dataset.i)));
}
function selectFinding(idx){
  EXP.sel=idx; const f=EXP.findings[idx]; if(!f) return;
  $("#expList").querySelectorAll(".expitem").forEach(el=>el.classList.toggle("sel",+el.dataset.i===idx));
  $("#expSel").className="expsel show sev-"+sevClass(f.severity);
  $("#expSel").innerHTML=expSelBanner(f);
  $("#expCode").innerHTML = f.line
    ? `<div class="code bare">${snippet(EXP.code, f.line, 6, EXP.findings, {sel:f.line})}</div>`
    : `<div class="exphint">Not tied to a specific source line (${esc(f.location||'—')}).</div>`;
  refreshOutput(f);
}
function step(n,label,val,state){ return `<div class="expstep ${state||''}"><div class="sn">${n}</div><div><div class="sl">${esc(label)}</div><div class="sv">${val}</div></div></div>`; }
function expSelBanner(f){
  const sc=sevClass(f.severity), via=f.source_agent||"";
  const layer=/bandit|semgrep/.test(via)?"AST analyser ("+via+")":(via==="source_code_scanner"?"regex / LLM":via);
  let out=null;
  if(REMEDY_STATE==="pending") out="output: generating…";
  else if(REMEDY){ const p=planFor(f); out = (p&&p.outcome==="blocked") ? "output: ✗ refused by guard" : (isFixed(f)?"output: ✓ fixed":"output: ✗ still present"); }
  const meta=[layer&&`detected via ${esc(layer)}`, f.asset_category&&`asset: ${esc(f.asset_category)}`, out]
    .filter(Boolean).map(m=>`<span class="chip">${m}</span>`).join("");
  return `<div class="top"><span class="sevtag sev-${sc}">${esc(f.severity)}</span><span class="rid">${esc(f.rule_id)}</span>`+
    `<span style="font-weight:650">${esc(f.title)}</span>`+
    `<span class="mono" style="margin-left:auto;color:var(--dim);font-size:12px">${esc(f.location||'')}${f.line?(' : line '+f.line):''}</span></div>`+
    `<div class="detail">${esc(f.detail||'')}</div>`+(meta?`<div class="meta">${meta}</div>`:"");
}
function planFor(f){ return (REMEDY&&(REMEDY.plan||[]).find(p=>p.rule_id===f.rule_id && p.line===f.line))||null; }
function isFixed(f){ const p=planFor(f); if(p) return p.outcome==="fixed";
  return !!(REMEDY && !(REMEDY.after||[]).some(x=>x.rule_id===f.rule_id && x.line===f.line)); }
function refreshOutput(f){
  const out=$("#expOutput");
  if(REMEDY_STATE==="pending"){ out.innerHTML=`<div class="exphint"><span class="spin" style="border-top-color:var(--accent)"></span><br>Generating fixed code…</div>`; $("#expOutHead").textContent=""; return; }
  if(!REMEDY){ out.innerHTML=`<div class="exphint">Fixed output is produced by the auto-remediation pass — it runs on a <b>Deep</b> scan with a live LLM.</div>`; $("#expOutHead").textContent=""; return; }
  const p=planFor(f), line=f.line||1;
  $("#expOutHead").textContent=REMEDY.verified_safe?"verified safe":"partial";
  // refused by the guard → code intentionally left as-is (still vulnerable)
  if(p && p.outcome==="blocked"){
    out.innerHTML=`<div class="outstat bad">✗ not corrected — the fix step was refused by the guard: ${esc(p.guard_reason||'')}</div>`+
      `<div class="code bare">${snippet(REMEDY.fixed_code, line, 6, REMEDY.after, {sel:line})}</div>`;
    return;
  }
  // attempted but the issue is still detected on re-scan
  if(!(p?p.outcome==="fixed":isFixed(f))){
    out.innerHTML=`<div class="outstat bad">⚠ fix was attempted but the issue is still detected on re-scan</div>`+
      `<div class="code bare">${snippet(REMEDY.fixed_code, line, 6, REMEDY.after, {sel:line})}</div>`;
    return;
  }
  // fixed → show the corrected slice
  const changed=changedLines(REMEDY.original_code,REMEDY.fixed_code);
  if(!changed.size){ out.innerHTML=`<div class="outstat ok">✓ fixed</div><div class="exphint">No code lines changed.</div>`; return; }
  const blocks=changedBlocks(changed), bi=bestBlockIndex(f,blocks), bl=blocks[bi]||blocks[0];
  const center=Math.round((bl.start+bl.end)/2), ctx=Math.max(5,(bl.end-bl.start)+3);
  out.innerHTML=`<div class="outstat ok">✓ fixed &amp; re-scanned clean</div><div class="code bare safe">${snippet(REMEDY.fixed_code, center, ctx, REMEDY.after, {changed})}</div>`;
}
async function autoRemediate(){ if(!LAST_SCAN) return; runRemediate(true); }
function argsHtml(params){
  if(!params||typeof params!=="object"||Array.isArray(params)||!Object.keys(params).length)
    return '<div class="args"><span class="arg"><span class="av" style="color:var(--dim)">(no arguments)</span></span></div>';
  return `<div class="args">`+Object.keys(params).map(k=>{
    let v=params[k]; if(v&&typeof v==="object") v=JSON.stringify(v);
    return `<div class="arg"><span class="ak">${esc(k)}</span><span class="av">${esc(String(v))}</span></div>`;
  }).join("")+`</div>`;
}
function statusClass(st){ st=(st||"").toLowerCase();
  if(/completed|ok|would/.test(st)) return "st-ok";
  if(/fail|refus|verification/.test(st)) return "st-bad";
  if(/skip|pending|not_started/.test(st)) return "st-dim";
  return "st-accent"; }
function statusCol(cls){ return cls==="st-ok"?"var(--ok)":cls==="st-bad"?"var(--bad)":cls==="st-dim"?"var(--dim)":"#8fbaf2"; }
function renderReasoning(rec){
  const d=rec.decision||{}, a=rec.action||{}, gv=rec.guard_verdict||{}, rp=rec.replanning||{};
  const rep=rec.action_report||{}, plan=rep.plan||{}, steps=plan.steps||[], tal=rep.tallies||{}, audit=rec.mcp_audit||[];
  const traj=rec.trajectory_verdict||null;
  const assets=(d.asset_categories_touched||[]).map(x=>`<span class="chip">${esc(x)}</span>`).join(" ")||'<span class="chip">none</span>';
  const lab=t=>`<div style="font-size:10.5px;color:var(--dim);text-transform:uppercase;letter-spacing:.4px">${t}</div>`;

  // ── Decision ──
  let html=`<div class="dsec"><div class="dh dh-dec">🧭 Decision <span class="sub">central agent · tiered response</span></div><div class="db">`+
    `<div class="row" style="gap:26px;align-items:flex-start"><div>${lab('Tier')}<div class="tierbig">${esc(d.recommended_tier||'—')}</div></div>`+
    `<div>${lab('Confidence')}<div class="tierbig">${Math.round((d.confidence||0)*100)}%</div></div></div>`+
    `<div class="kv" style="margin-top:14px"><div class="k">Assets touched</div><div class="v">${assets}</div>`+
    `<div class="k">Justification</div><div class="v">${esc(d.justification||'—')}</div></div></div></div>`;

  // ── Action plan ──
  html+=`<div class="dsec"><div class="dh dh-act">⚙️ Action plan <span class="sub">${esc(a.kind||'—')} → ${esc(a.target||'—')} · dry-run</span></div><div class="db">`+
    `<div class="pchips"><span class="pchip">status: <b>${esc(rep.status||'—')}</b></span>`+
    (plan.blast_radius?`<span class="pchip">blast: ${esc(plan.blast_radius)}</span>`:"")+
    (tal.total?`<span class="pchip">${tal.completed||0}/${tal.total} completed</span>`:"")+
    (tal.refused?`<span class="pchip badp">${tal.refused} refused</span>`:"")+
    (tal.failed?`<span class="pchip badp">${tal.failed} failed</span>`:"")+
    (tal.skipped?`<span class="pchip">${tal.skipped} skipped</span>`:"")+`</div>`+
    (rep.summary?`<p class="note" style="margin-top:2px">${esc(rep.summary)}</p>`:"");
  if(steps.length){
    html+=`<div class="psteps">`+steps.map((s,i)=>{ const cls=statusClass(s.status),col=statusCol(cls);
      return `<div class="pstep ${cls}"><div class="pt"><span class="kb">${i+1} · ${esc(s.kind||'')}</span><span class="tool">${esc(s.tool||'')}</span>`+
        (s.side_effect?`<span class="chip">${esc(s.side_effect)}</span>`:"")+(s.requires_authorization?`<span class="chip">requires auth</span>`:"")+
        `<span class="pstat" style="color:${col}">${esc(s.status||'')}</span></div>`+
        (s.description?`<div class="pdesc">${esc(s.description)}</div>`:"")+argsHtml(s.params)+
        (s.error?`<div class="pdesc" style="color:var(--bad)">error: ${esc(s.error)}</div>`:"")+
        (s.refusal_reason?`<div class="pdesc" style="color:var(--bad)">refused: ${esc(s.refusal_reason)}</div>`:"")+`</div>`;
    }).join("")+`</div>`;
  } else { html+=`<p class="note">No remediation steps were generated (nothing to act on, or an alert-only response).</p>`; }
  if(audit.length){
    html+=`<div class="subhead" style="padding-top:14px">MCP tool calls <span class="sub">${audit.length}</span></div><div class="psteps">`;
    audit.forEach(x=>{ const cls=statusClass(x.status),col=statusCol(cls),mode=x.real_invoked?"real":"dry-run";
      html+=`<div class="pstep ${cls}"><div class="pt"><span class="tool">${esc(x.tool||'tool')}</span>`+
        (x.side_effect?`<span class="chip">${esc(x.side_effect)}</span>`:"")+`<span class="chip">${mode}</span>`+
        (x.elapsed_ms!=null?`<span class="chip">${Math.round(x.elapsed_ms)} ms</span>`:"")+
        `<span class="pstat" style="color:${col}">${esc(x.status||'')}</span></div>`+argsHtml(x.params)+
        (x.error?`<div class="pdesc" style="color:var(--bad)">error: ${esc(x.error)}</div>`:"")+`</div>`; });
    html+=`</div>`;
  }
  html+=`</div></div>`;

  // ── Security guard ──
  const pc=(label,ok)=>`<span class="pchip ${ok?'okp':'badp'}">${label} ${ok?'✓':'✕'}</span>`;
  html+=`<div class="dsec"><div class="dh dh-guard ${gv.allowed?'gok':'gbad'}">🛡️ Security guard — ${gv.allowed?'PASS':'REFUSED'} <span class="sub">paper 1 · four properties</span></div><div class="db">`+
    `<div class="pchips">`+pc('task-alignment',gv.task_alignment)+pc('action-alignment',gv.action_alignment)+pc('source-auth',gv.source_authorization)+pc('data-isolation',gv.data_isolation)+`</div>`+
    `<p class="note" style="margin-top:4px">${esc(gv.reason||'')}</p>`+
    (traj?`<div class="pchips">`+pc('compositional',traj.compositional_ok)+pc('temporal',traj.temporal_ok)+(traj.violations&&traj.violations.length?`<span class="pchip badp">${traj.violations.length} violation(s)</span>`:"")+`</div>`:"")+
    `<div class="kv" style="margin-top:10px"><div class="k">Re-planning</div><div class="v">${rp.rounds||0} round(s) · ${rp.resolved?'<span class="ok">resolved</span>':'<span style="color:var(--med)">unresolved</span>'}</div></div>`+
    `</div></div>`;
  $("#reasoning").innerHTML=html;
}

// ── remediation (auto-runs during a Deep scan) ───────────────────────────────
async function runRemediate(auto){
  if(!LAST_SCAN) return;
  REMEDY_STATE="pending"; if(EXP.sel!=null) refreshOutput(EXP.findings[EXP.sel]);
  $("#remedy").innerHTML=`<p class="note"><span class="spin" style="border-top-color:var(--accent)"></span> Auto-remediation running — rewriting the code and re-scanning to verify…</p>`;
  try{ const res=await fetch("/api/remediate",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({code:LAST_SCAN.code,filename:LAST_SCAN.filename,deep:true,findings:LAST_SCAN.findings})});
    const data=await res.json();
    if(!data.ok){ REMEDY_STATE=null; $("#remedy").innerHTML=`<div class="err">⚠ ${esc(data.error||"remediation failed")}</div>`; if(EXP.sel!=null) refreshOutput(EXP.findings[EXP.sel]); return; }
    REMEDY=data; REMEDY_STATE="done"; renderRemediation(data);
    if(EXP.sel!=null){ selectFinding(EXP.sel); }   // refresh banner + output snippet
  }catch(e){ REMEDY_STATE=null; $("#remedy").innerHTML=`<div class="err">⚠ ${esc(String(e))}</div>`; if(EXP.sel!=null) refreshOutput(EXP.findings[EXP.sel]); }
}
function codeTable(code,findings,safe,changed,tagByLine,withLn){
  const byLine={}; (findings||[]).forEach(f=>{ if(f.line){ (byLine[f.line]=byLine[f.line]||[]).push(f); }});
  const lines=(code||"").replace(/\n$/,"").split("\n");
  return `<table>`+lines.map((ln,i)=>{ const n=i+1,fs=byLine[n]; let cls="",tag="";
    if(fs){ const worst=fs.map(f=>sevClass(f.severity)).sort((a,b)=>SEV.indexOf(a)-SEV.indexOf(b))[0]; cls=`hl-${worst}`; tag=`<span class="tag">${fs.map(f=>esc(f.rule_id)).join(", ")}</span>`; }
    else if(changed&&changed.has(n)){ cls="hl-changed"; tag=(tagByLine&&tagByLine[n])||""; }
    else if(safe){ cls="hl-safe"; }
    return `<tr ${withLn?`data-ln="${n}"`:''} class="${cls}"><td class="ln">${n}</td><td class="src">${esc(ln)||" "}${tag}</td></tr>`;
  }).join("")+`</table>`;
}
// Render only the slice of `code` around `center` (±ctx lines), with data-ln,
// finding/changed highlights, a rowsel on opts.sel, and "… N lines" markers.
function snippet(code,center,ctx,findings,opts){
  opts=opts||{}; const lines=(code||"").replace(/\n$/,"").split("\n");
  if(!center||center<1) center=1; center=Math.min(center,lines.length||1);
  const lo=Math.max(1,center-ctx), hi=Math.min(lines.length,center+ctx);
  const byLine={}; (findings||[]).forEach(f=>{ if(f.line){ (byLine[f.line]=byLine[f.line]||[]).push(f); } });
  const changed=opts.changed; let rows="";
  if(lo>1) rows+=`<tr class="gaprow"><td class="ln">⋯</td><td class="src">${lo-1} line(s) above</td></tr>`;
  for(let n=lo;n<=hi;n++){ const fs=byLine[n]; let cls="",tag="";
    if(fs){ const worst=fs.map(f=>sevClass(f.severity)).sort((a,b)=>SEV.indexOf(a)-SEV.indexOf(b))[0]; cls="hl-"+worst; tag=`<span class="tag">${fs.map(f=>esc(f.rule_id)).join(", ")}</span>`; }
    else if(changed&&changed.has(n)){ cls="hl-changed"; }
    if(opts.sel===n) cls=(cls+" rowsel").trim();
    rows+=`<tr data-ln="${n}" class="${cls}"><td class="ln">${n}</td><td class="src">${esc(lines[n-1])||" "}${tag}</td></tr>`; }
  if(hi<lines.length) rows+=`<tr class="gaprow"><td class="ln">⋯</td><td class="src">${lines.length-hi} line(s) below</td></tr>`;
  return `<table>${rows}</table>`;
}
// Which changed block best corresponds to a finding (token overlap).
function bestBlockIndex(f,blocks){
  if(!f||!blocks.length) return 0;
  const afterL=(REMEDY.fixed_code||"").replace(/\n$/,"").split("\n");
  const origL=(REMEDY.original_code||"").replace(/\n$/,"").split("\n");
  const toks=tokenize(((f.line&&origL[f.line-1])||"")+" "+(f.title||"")+" "+(f.rule_id||""));
  let best=0,bestScore=-1;
  blocks.forEach((bl,bi)=>{ let t=""; for(let k=bl.start;k<=bl.end;k++) t+=" "+(afterL[k-1]||""); const bt=tokenize(t);
    let sc=0; toks.forEach(x=>{ if(bt.has(x)) sc++; }); if(sc>bestScore){ bestScore=sc; best=bi; } });
  return best;
}
function changedLines(before,after){ const A=(before||"").replace(/\n$/,"").split("\n"),B=(after||"").replace(/\n$/,"").split("\n");
  const n=A.length,m=B.length,out=new Set(); if(!m) return out; if(n*m>400000){ for(let k=1;k<=m;k++) out.add(k); return out; }
  const dp=Array.from({length:n+1},()=>new Int32Array(m+1));
  for(let i=n-1;i>=0;i--) for(let j=m-1;j>=0;j--) dp[i][j]=A[i]===B[j]?dp[i+1][j+1]+1:Math.max(dp[i+1][j],dp[i][j+1]);
  const same=new Set(); let i=0,j=0; while(i<n&&j<m){ if(A[i]===B[j]){ same.add(j); i++; j++; } else if(dp[i+1][j]>=dp[i][j+1]){ i++; } else { j++; } }
  for(let k=0;k<m;k++) if(!same.has(k)) out.add(k+1); return out; }
function changedBlocks(changed){ const nums=[...changed].sort((a,b)=>a-b),blocks=[]; let cur=null;
  nums.forEach(n=>{ if(cur&&n===cur.end+1){ cur.end=n; } else { cur={start:n,end:n}; blocks.push(cur); } }); return blocks; }
function tokenize(s){ return new Set((s||"").toLowerCase().match(/[a-z_][a-z0-9_]{2,}/g)||[]); }
function blockTags(data,changed){ const blocks=changedBlocks(changed); if(!blocks.length) return {};
  const afterL=(data.fixed_code||"").replace(/\n$/,"").split("\n"),origL=(data.original_code||"").replace(/\n$/,"").split("\n");
  const fixedF=(data.before||[]).filter(f=>!(data.after||[]).some(x=>x.rule_id===f.rule_id&&x.line===f.line));
  const blockText=blocks.map(bl=>{ let t=""; for(let k=bl.start;k<=bl.end;k++) t+=" "+(afterL[k-1]||""); return tokenize(t); });
  const assigned=blocks.map(()=>[]);
  fixedF.forEach(f=>{ const toks=tokenize(((f.line&&origL[f.line-1])||"")+" "+(f.title||"")); let best=0,bestScore=-1;
    blockText.forEach((bt,bi)=>{ let sc=0; toks.forEach(t=>{ if(bt.has(t)) sc++; }); if(sc>bestScore){ bestScore=sc; best=bi; } }); assigned[best].push(f); });
  const map={}; blocks.forEach((bl,bi)=>{ const fs=assigned[bi]; map[bl.start]=fs.length?fs.map(f=>`<span class="tag chg" title="${esc(f.title||'')}">✓ ${esc(f.rule_id)} fixed</span>`).join(""):`<span class="tag chg">✓ fixed</span>`; }); return map; }
function renderRemediation(data){
  const safe=!!data.verified_safe,b=data.before_count||0,a=data.after_count||0;
  const aSev=data.after_sev||{critical:0,high:0,medium:0,low:0}; const exploitable=(aSev.critical||0)+(aSev.high||0);
  const advisory=data.advisory_after||((aSev.medium||0)+(aSev.low||0)+(aSev.info||0));
  const fixedCount=(data.before||[]).filter(f=>!(data.after||[]).some(x=>x.rule_id===f.rule_id&&x.line===f.line)).length;
  const blockedN=data.blocked_count||0, allowedN=data.allowed_count||0, allowedFixed=data.allowed_fixed||0;
  const model=data.provider&&data.provider.llm_model||"";
  const changed=changedLines(data.original_code,data.fixed_code);
  const tagByLine=blockTags(data,changed);
  const clean=safe&&!blockedN;
  const badge = blockedN
    ? `<span class="badge refused">${blockedN} fix(es) refused by guard — left vulnerable</span>`
    : (safe?`<span class="badge pass">✓ Verified safe — no exploitable issues remain</span>`
          :`<span class="badge refused">${exploitable} exploitable finding(s) remain</span>`);
  const resolved=data.allowed_fixed||0;
  const kr=$("#kpiResolvedN"); if(kr) kr.textContent=String(resolved);
  $("#remedy").innerHTML=`<div class="banner" style="margin:0 0 14px">`+
    `<span class="badge ${resolved>=b&&!blockedN?'pass':'tier'}">${resolved} of ${b} finding(s) resolved</span>`+
    `${badge}`+
    `<span class="pill">re-scan <b>${b} → ${a}</b></span>`+
    (blockedN?`<span class="pill">${blockedN} refused → left as-is</span>`:"")+
    (advisory?`<span class="pill">${advisory} advisory</span>`:"")+
    (model?`<span class="pill">by <b>${esc(model)}</b></span>`:"")+`</div>`+
    `<div class="subhead" style="padding-top:0">Input vs corrected output <span class="sub">findings highlighted in both</span></div>`+
    `<div class="remedgrid">`+
      `<div><div class="rhead bad2">Input · ${b} finding(s) highlighted</div>`+
        `<div class="code">${codeTable(data.original_code,data.before,false,null,null,true)}</div></div>`+
      `<div><div class="rhead ${clean?'ok2':'warn2'}">Output · rewritten lines${clean?' ✓':''} &amp; any remaining findings highlighted</div>`+
        `<div class="code ${clean?'safe':''}">${codeTable(data.fixed_code,data.after,clean,changed,tagByLine,true)}</div></div>`+
    `</div>`;
}

// ── tabs ────────────────────────────────────────────────────────────────────
let benchLoaded=false;
document.querySelectorAll(".tab").forEach(t=>t.addEventListener("click",()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active")); t.classList.add("active");
  const tab=t.getAttribute("data-tab");
  $("#view-scan").style.display=tab==="scan"?"block":"none";
  $("#view-bench").style.display=tab==="bench"?"block":"none";
  $("#view-attack").style.display=tab==="attack"?"block":"none";
  $("#scanBtn").style.display=tab==="scan"?"":"none";
  if(tab==="bench"&&!benchLoaded){ benchLoaded=true; loadBenchManifest(); }
}));

// ── benchmark ────────────────────────────────────────────────────────────────
function refreshBenchModeNote(){ if(!$("#benchModeNote"))return;
  const deep=$("#deep").checked,real=HEALTH&&HEALTH.llm_real,model=(HEALTH&&HEALTH.llm_model)||"the LLM";
  $("#benchModeNote").textContent=(deep&&real)?`Deep: one live ${model} call per ingested file (slower, costs tokens).`
    :(deep&&!real)?"Deep requested but no live LLM — running the deterministic layers.":"Fast: deterministic layers only (offline, instant)."; }
async function loadBenchManifest(){ try{ const m=await (await fetch("/api/benchmark")).json(); if(!m.ok)return;
    const langs=[...new Set(m.files.map(f=>f.language))].join(" · "),clean=m.files.filter(f=>f.clean).length,skip=m.files.filter(f=>!f.ingested&&!f.clean).length;
    $("#benchSub").innerHTML=`${m.files.length} files (${langs}) · <b>${m.total_vulns}</b> labelled vulnerabilities · ${clean} clean control(s)`+(skip?` · <span style="color:var(--med)">${skip} not ingested</span>`:"");
    refreshBenchModeNote();
  }catch(e){ $("#benchSub").textContent="could not load corpus"; } }
$("#benchBtn").addEventListener("click",runBench);
async function runBench(){ const btn=$("#benchBtn"); btn.disabled=true; btn.innerHTML='<span class="spin"></span> Running…'; $("#benchErr").style.display="none";
  try{ const win=parseInt($("#benchWindow").value)||3;
    const res=await fetch("/api/benchmark",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({deep:$("#deep").checked,window:win,remediate:$("#benchRemediate").checked})});
    const data=await res.json(); if(!data.ok){ $("#benchErr").textContent="⚠ "+(data.error||"failed"); $("#benchErr").style.display="block"; return; } renderBench(data);
  }catch(e){ $("#benchErr").textContent="⚠ "+String(e); $("#benchErr").style.display="block"; } finally{ btn.disabled=false; btn.textContent="Run benchmark"; } }
function covColor(pct){ if(pct>=75)return "var(--ok)"; if(pct>=40)return "var(--med)"; if(pct>=15)return "var(--high)"; return "var(--bad)"; }
function bar(label,covered,total){ const pct=total?Math.round(covered/total*100):0;
  return `<div class="brow"><div class="lab">${esc(label)}</div><div class="track2"><div class="fill2" style="width:${pct}%;background:${covColor(pct)}"></div></div><div class="val tnum">${covered}/${total} · ${pct}%</div></div>`; }
function barGroup(obj){ return Object.keys(obj).sort((a,b)=>obj[b].total-obj[a].total).map(k=>bar(k,obj[k].covered,obj[k].total)).join("")||'<div class="note">—</div>'; }
function renderBench(data){ $("#benchResults").style.display="block"; const m=data.metrics;
  $("#benchScoreSub").textContent=(data.deep?'Deep · '+((data.provider&&data.provider.llm_model)||'LLM'):'Fast · static')+` · window ±${data.window}`;
  $("#benchDonut").innerHTML=donut(m.coverage_pct,"coverage");
  const cards=[{n:`${m.covered}/${m.total_vulns}`,l:"detected",c:"accent"},{n:m.missed,l:"missed",c:m.missed?"warn":"good"},
    {n:m.recall,l:"recall",c:"accent"},{n:m.precision,l:"precision",c:"accent"},{n:m.f1,l:"F1 score",c:"accent"},
    {n:m.false_positives,l:"false positives",c:m.false_positives?"bad":"good"},{n:m.extra_findings,l:"extra (unlabeled)",c:""}];
  if(m.remediated){
    cards.push({n:`${m.resolved}/${m.covered}`,l:"resolved",c:m.resolved?"good":"warn"});
    cards.push({n:Math.round((m.resolution_rate||0)*100)+"%",l:"resolution rate",c:"good"});
  }
  $("#benchMetrics").innerHTML=cards.map(c=>`<div class="metric ${c.c}"><div class="n tnum">${esc(c.n)}</div><div class="l">${c.l}</div></div>`).join("");
  $("#benchBySev").innerHTML=barGroup(m.by_severity); $("#benchByCat").innerHTML=barGroup(m.by_category); $("#benchByLang").innerHTML=barGroup(m.by_language);
  $("#benchFiles").innerHTML=data.files.map(f=>{ const cov=f.clean?`<span class="cov">${f.false_positives?'<span class="bad">'+f.false_positives+' FP</span>':'<span class="ok">0 FP</span>'}</span>`:`<span class="cov" style="color:${covColor(f.n_vulns?Math.round(f.covered/f.n_vulns*100):100)}">${f.covered}/${f.n_vulns}${f.remediated?` · <span class="ok">${f.resolved} resolved</span>`:''}</span>`;
    const skipBadge=(!f.ingested&&!f.clean)?'<span class="pill skip">not ingested (.'+f.path.split(".").pop()+')</span>':''; let body="";
    if(f.clean){ body=f.extra.length?f.extra.map(x=>`<div class="vrow"><span class="mark bad">⚠</span><span class="vt">false positive: <span class="tag2">${esc(x.rule_id)}</span> ${esc(x.title||'')} <span class="vmeta">line ${x.line||'?'}</span></span></div>`).join(""):'<div class="vrow" style="border:0"><span class="mark ok">✓</span><span class="vt">no findings — clean control behaved correctly</span></div>'; }
    else { body=(f.vulns||[]).map(v=>{ const mk=v.detected?'<span class="mark ok">✓</span>':'<span class="mark bad">✗</span>'; const matched=v.detected&&v.matched?` <span class="vmeta">→ matched <span class="tag2">${esc(v.matched.rule_id)}</span> @ line ${v.matched.line}</span>`:'';
      const res=(v.resolved===true)?' <span class="ok vmeta">· ✓ resolved</span>':(v.resolved===false?' <span class="vmeta" style="color:var(--med)">· not resolved</span>':'');
      return `<div class="vrow">${mk}<span class="vt"><span class="tag2">${esc(v.cwe)}</span> <b>${esc(v.title)}</b> <span class="vmeta">${esc(v.severity)} · line ${v.line} · ${esc(v.category)}</span>${matched}${res}</span></div>`; }).join("");
      if(f.extra&&f.extra.length){ body+=`<div class="vrow"><span class="mark">·</span><span class="vt vmeta">${f.extra.length} extra finding(s) not matching a label (not scored): `+f.extra.map(x=>`<span class="tag2">${esc(x.rule_id)}@${x.line||'?'}</span>`).join(" ")+`</span></div>`; } }
    return `<details class="bfile"><summary><span class="langtag">${esc(f.language)}</span><span class="fname">${esc(f.path)}</span><span class="note" style="color:var(--dim)">${esc(f.subsystem)}</span>${skipBadge}${cov}</summary><div class="inner">${body}</div></details>`;
  }).join("");
  $("#benchRaw").textContent=JSON.stringify(data,null,2);
}

// ── attack ────────────────────────────────────────────────────────────────────
let ATK={findings:[],chosen:new Set(),scriptByRule:{},sel:null,inst:{}};
function refreshAtkModeNote(){ if(!$("#atkModeNote"))return;
  const deep=$("#deep").checked,real=HEALTH&&HEALTH.llm_real,model=(HEALTH&&HEALTH.llm_model)||"the LLM";
  $("#atkModeNote").textContent=(deep&&real)?`Deep: live ${model} plans the chain and authors the PoC scripts.`
    :(deep&&!real)?"Deep requested but no live LLM — deterministic demo plan/scripts.":"Fast: deterministic plan from the static findings + template scripts (offline)."; }
$("#atkBtn").addEventListener("click",runAttack);
async function runAttack(){ const code=$("#atkCode").value; if(!code.trim()){ $("#atkErr").textContent="⚠ Please paste target code first."; $("#atkErr").style.display="block"; return; }
  const btn=$("#atkBtn"); btn.disabled=true; btn.innerHTML='<span class="spin"></span> Analysing…'; $("#atkErr").style.display="none";
  try{ const res=await fetch("/api/attack",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({code,filename:$("#atkFname").value||"input.py",scenario:$("#atkScenario").value,deployment:$("#atkDep").value,deep:$("#deep").checked})});
    const data=await res.json(); if(!data.ok){ $("#atkErr").textContent="⚠ "+(data.error||"failed"); $("#atkErr").style.display="block"; return; } renderAttack(data);
  }catch(e){ $("#atkErr").textContent="⚠ "+String(e); $("#atkErr").style.display="block"; } finally{ btn.disabled=false; btn.textContent="Run red-team analysis"; } }
function pathFlow(arr){ if(!arr||!arr.length) return '<span class="note">—</span>';
  return `<div class="pathflow">`+arr.map((s,i)=>(i?'<span class="patharr">→</span>':'')+`<span class="pathstep">${esc(s)}</span>`).join("")+`</div>`; }
function renderAttack(data){
  $("#atkPlaceholder").style.display="none"; $("#atkResults").style.display="block";
  const rec=data.record||{},plan=rec.plan||{},ev=rec.ethics_verdict||{},inst=rec.system_instance||{};
  const allowed=ev.allowed,scripts=rec.scripts||[],redacted=rec.redacted||[];
  const findings=(rec.findings||[]).slice().sort((a,b)=>SEV.indexOf(sevClass(a.severity))-SEV.indexOf(sevClass(b.severity)));
  const chosen=new Set(plan.chosen_rule_ids||[]); const scriptByRule={}; scripts.forEach(s=>{ if(!(s.rule_id in scriptByRule)) scriptByRule[s.rule_id]=s; });
  ATK={findings,chosen,scriptByRule,sel:null,inst,
       code:data.code||"", filename:data.filename||"input.py",
       scenario:(rec.scenario||$("#atkScenario").value||""), sims:{}};

  $("#atkBanner").innerHTML=`<span class="badge mode">${data.deep?'DEEP · AI':'FAST · static'}</span>`+
    `<span class="badge ${allowed?'pass':'refused'}">ethics: ${allowed?'PASS':'REFUSED'}</span><span class="pill">${esc(data.filename)}</span>`;
  $("#atkKpis").innerHTML=kpi(findings.length,"exploits","accent")+kpi((plan.chosen_rule_ids||[]).length,"in chain","med")+
    kpi(Math.round((plan.confidence||0)*100)+"%","confidence",(plan.confidence||0)>=0.6?"ok":"med")+kpi(scripts.length,"scripts","accent")+kpi(redacted.length,"redacted",redacted.length?"bad":"ok");
  $("#atkSummary").textContent="🎯 Target asset: "+(plan.target_asset||'—')+(plan.summary?" — "+plan.summary:"");

  $("#atkChain").innerHTML=flow([
    {t:"Recon",v:`${(inst.external_actors||[]).length} external actor(s)`,s:'accent',target:"#card-atkexplorer"},
    {t:"Exploit",v:`${findings.length} found`,s:findings.length?'crit':'ok',target:"#card-atkexplorer"},
    {t:"Chain",v:`${(plan.chosen_rule_ids||[]).length} chosen`,s:'med',target:"#card-atkplan"},
    {t:"Ethics",v:allowed?'PASS':'REFUSED',s:allowed?'ok':'bad',target:"#card-atkethics"},
    {t:"Scripts",v:`${scripts.length} PoC`,s:scripts.length?'accent':'ok',target:"#card-atkscripts"},
  ]); wireFlow("#atkChain");

  renderAtkList();
  $("#atkDetail").innerHTML=`<div class="exphint">Select an exploit on the left to trace it.</div>`;
  if(findings.length) selectAtkFinding(0);

  $("#atkPlan").innerHTML=`<div class="kv"><div class="k">Target asset</div><div class="v"><b>${esc(plan.target_asset||'—')}</b></div>`+
    `<div class="k">Chosen exploits</div><div class="v">${(plan.chosen_rule_ids||[]).map(r=>`<span class="tag2">${esc(r)}</span>`).join(" ")||'—'}</div>`+
    `<div class="k">Poison path</div><div class="v">${pathFlow(plan.poison_path)}</div>`+
    `<div class="k">Trigger path</div><div class="v">${pathFlow(plan.trigger_path)}</div>`+
    `<div class="k">Justification</div><div class="v">${esc(plan.justification||'—')}</div></div>`;
  $("#atkEthics").innerHTML=`<div class="banner"><span class="badge ${allowed?'pass':'refused'}">${allowed?'✓ ALLOWED':'✕ REFUSED'}</span>`+
    `<span class="pill">scope ${ev.scope_ok?'✓':'✕'}</span><span class="pill">target ${ev.target_ok?'✓':'✕'}</span><span class="pill">non-destructive ${ev.non_destructive?'✓':'✕'}</span></div>`+
    `<p class="note" style="margin-top:0">${esc(ev.reason||'')}</p>`;

  $("#atkScriptCount").textContent=`${scripts.length} generated`+(redacted.length?` · ${redacted.length} redacted`:"")+" · never executed";
  if(!allowed){ $("#atkScripts").innerHTML=`<div class="empty"><div class="big">🛡️</div>Ethics guard refused this scenario/target — no scripts generated.</div>`; }
  else if(!scripts.length){ $("#atkScripts").innerHTML=`<div class="empty">No scripts produced for the chosen plan.</div>`; }
  else { $("#atkScripts").innerHTML=scripts.map(s=>scriptCard(s)).join(""); }
  $("#atkRaw").textContent=JSON.stringify(rec,null,2);
  window.scrollTo({top:0,behavior:"smooth"});
}
function scriptCard(s){ const red=(s.expected_effect==="REDACTED")||/^\[REDACTED\]/.test(s.title||"");
  return `<div class="scriptcard${red?' redacted':''}"><div class="sh"><span class="tag2">${esc(s.rule_id)}</span><span class="langtag">${esc(s.language)}</span><span class="st">${esc(s.title)}</span>`+
    (s.target_hint?`<span class="vmeta" style="color:var(--dim);font-size:11.5px">target: ${esc(s.target_hint)}</span>`:"")+
    (s.expected_effect&&!red?`<span class="eff">effect: ${esc(s.expected_effect)}</span>`:"")+`</div><pre>${esc(s.body||"")}</pre></div>`; }
function renderAtkList(){
  const {findings,chosen,scriptByRule,sel}=ATK;
  $("#atkExpCount").textContent=`${findings.length}`;
  if(!findings.length){ $("#atkList").innerHTML=`<div class="exphint">No exploitable findings surfaced.</div>`; return; }
  $("#atkList").innerHTML=findings.map((f,i)=>`<div class="expitem sev-${sevClass(f.severity)}${i===sel?' sel':''}" data-i="${i}">
    <span class="edot"></span><div><div>${esc(f.title)} ${chosen.has(f.rule_id)?'<span class="chosen">chain</span>':''} ${scriptByRule[f.rule_id]?'<span class="chip">PoC</span>':''}</div>
    <div class="erid">${esc(f.rule_id)}${f.line?(' · L'+f.line):''}</div></div></div>`).join("");
  $("#atkList").querySelectorAll(".expitem").forEach(el=>el.addEventListener("click",()=>selectAtkFinding(+el.dataset.i)));
}
function selectAtkFinding(idx){
  ATK.sel=idx; const f=ATK.findings[idx]; if(!f) return;
  $("#atkList").querySelectorAll(".expitem").forEach(el=>el.classList.toggle("sel",+el.dataset.i===idx));
  const via=f.source_agent||"—", inChain=ATK.chosen.has(f.rule_id), sx=ATK.scriptByRule[f.rule_id];
  let html=`<div style="padding:11px 12px 4px"><span class="sevtag sev-${sevClass(f.severity)}">${esc(f.severity)}</span> <span class="rid">${esc(f.rule_id)}</span> ${inChain?'<span class="chosen">in chain</span>':''}</div>`+
    `<p class="note" style="padding:0 12px;margin:6px 0 2px;color:var(--muted);font-size:12.5px">${esc(f.detail||f.title)}</p>`+
    step("1","Detected by",`${esc(via)}${f.evidence?`<span class="ev">${esc((f.evidence||'').slice(0,160))}</span>`:''}`)+
    step("2","Classified",`severity <b>${esc(f.severity)}</b>${f.asset_category?` · asset: ${esc(f.asset_category)}`:''} · <span class="mono">${esc(f.location||'—')}${f.line?(' :'+f.line):''}</span>`)+
    step("3","Exploit chain",inChain?'<span class="ok">selected</span> — part of the poison/trigger chain':'not selected — shown for completeness',inChain?'done':'')+
    step("4","Proof-of-concept",sx?`${esc(sx.language)} · never executed${sx.expected_effect&&sx.expected_effect!=="REDACTED"?`<span class="ev">effect: ${esc(sx.expected_effect)}</span>`:''}`:'no PoC generated for this finding',sx?'done':'');
  if(sx){ const red=(sx.expected_effect==="REDACTED")||/^\[REDACTED\]/.test(sx.title||"");
    html+=`<div style="padding:10px 12px 6px"><div class="scriptcard${red?' redacted':''}" style="margin:0"><pre>${esc(sx.body||"")}</pre></div></div>`+
      `<div style="padding:0 12px 12px"><button class="btn sm" id="atkSimBtn" style="border-color:color-mix(in srgb,var(--accent2) 45%,var(--line))">▶ Simulate running this PoC on the target</button><div id="atkSim"></div></div>`; }
  $("#atkDetail").innerHTML=html;
  if(sx){ const b=$("#atkSimBtn"); if(b) b.addEventListener("click",()=>simulateAtk(idx));
    if(ATK.sims[f.rule_id]) renderSim($("#atkSim"), ATK.sims[f.rule_id]); }
}
async function simulateAtk(idx){
  const f=ATK.findings[idx], sx=ATK.scriptByRule[f.rule_id]; if(!sx) return;
  const box=$("#atkSim"), btn=$("#atkSimBtn");
  if(btn){ btn.disabled=true; btn.innerHTML='<span class="spin"></span> Simulating…'; }
  box.innerHTML=`<p class="note"><span class="spin" style="border-top-color:var(--accent2)"></span> Simulating the PoC against the target code (LLM reasoning — nothing is executed)…</p>`;
  try{
    const res=await fetch("/api/attack_sim",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({code:ATK.code, filename:ATK.filename, scenario:ATK.scenario, script:sx})});
    const d=await res.json();
    if(!d.ok){ box.innerHTML=`<div class="err">⚠ ${esc(d.error||'simulation failed')}</div>`; return; }
    ATK.sims[f.rule_id]=d; renderSim(box, d);
  }catch(e){ box.innerHTML=`<div class="err">⚠ ${esc(String(e))}</div>`; }
  finally{ if(btn){ btn.disabled=false; btn.innerHTML="▶ Re-simulate"; } }
}
function renderSim(box, d){
  const s=d.simulation||{};
  const yn=v=> v===true?'<span class="pchip okp">yes</span>':(v===false?'<span class="pchip badp">no</span>':'<span class="pchip">n/a</span>');
  box.innerHTML=`<div class="subhead" style="padding:12px 0 6px">Simulated outcome `+
    (d.live?'':'<span class="sub">(offline heuristic — enable Deep for a reasoned simulation)</span>')+`</div>`+
    `<div class="pchips">reachable ${yn(s.reachable)} <span style="color:var(--dim)">·</span> exploit succeeds ${yn(s.success)}`+
    ((s.confidence!=null&&d.live)?` <span class="pchip">confidence ${Math.round((s.confidence||0)*100)}%</span>`:'')+`</div>`+
    `<div class="kv" style="margin-top:10px">`+
      `<div class="k">What happens</div><div class="v">${esc(s.outcome||'—')}</div>`+
      (s.impact?`<div class="k">Impact</div><div class="v">${esc(s.impact)}</div>`:'')+
      (s.observable&&s.observable!=='—'?`<div class="k">Observable</div><div class="v">${esc(s.observable)}</div>`:'')+
      ((s.preconditions&&s.preconditions.length)?`<div class="k">Preconditions</div><div class="v">${s.preconditions.map(esc).join('; ')}</div>`:'')+
    `</div>`;
}

loadHealth(); loadExamples();
