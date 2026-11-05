const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { fileURLToPath } = require('node:url');
const { configuration: aiConfiguration, explainCase, proxyAI, isLoopback } = require('./ai-provider');

const ROOT = path.resolve(__dirname, '..');
const DATA = path.join(ROOT, 'dataset');
const OUTPUT = path.join(ROOT, 'output.csv');
let PORT = Number(process.env.PORT || 8000);

function csv(text) {
  const rows = []; let row = [], field = '', quote = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote && c === '"' && text[i + 1] === '"') { field += '"'; i++; }
    else if (c === '"') quote = !quote;
    else if (c === ',' && !quote) { row.push(field); field = ''; }
    else if ((c === '\n' || c === '\r') && !quote) { if (c === '\r' && text[i + 1] === '\n') i++; row.push(field); if (row.some(x => x !== '')) rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  const headers = rows.shift() || [];
  return rows.map(values => Object.fromEntries(headers.map((h, i) => [h, values[i] ?? ''])));
}
function load(name) { return csv(fs.readFileSync(path.join(DATA, name), 'utf8').replace(/^\uFEFF/, '')); }
function iso(s) { const n = Date.parse(s || ''); return Number.isFinite(n) ? n : 0; }
function esc(s) { return `"${String(s).replaceAll('"', '""')}"`; }
function norm(s) { return String(s ?? '').trim().toLocaleLowerCase('en-US'); }
function flatValues(obj, out = []) {
  if (obj && typeof obj === 'object') for (const [k, v] of Object.entries(obj)) {
    if (v && typeof v === 'object') flatValues(v, out); else if (v != null) out.push([k.toLowerCase(), String(v)]);
  }
  return out;
}
function readEvidence() {
  const manifest = load('evidence_files.csv');
  return manifest.map(item => {
    const filename = path.resolve(DATA, 'evidence', item.file_path.replace(/^evidence[\\/]/, ''));
    const relative = path.relative(path.join(DATA, 'evidence'), filename);
    if (relative.startsWith('..') || path.isAbsolute(relative)) return { ...item, error: 'Unsafe manifest path' };
    try {
      const raw = fs.readFileSync(filename);
      const ext = path.extname(filename).toLowerCase();
      let text = raw.toString('utf8'); let parsed;
      if (ext === '.json') { try { parsed = JSON.parse(text); } catch {} }
      return { ...item, text, parsed, error: null };
    } catch (e) { return { ...item, error: e.message }; }
  });
}
function deletionIntent(text) {
  const t = norm(text);
  const positive = /\b(delet\w*|eras\w*|remov\w*|clos\w*|purge\w*|wip\w*|eliminat\w*)\b|\b(account|profile|data|personal details)\b.{0,36}\b(gone|removed|deleted|closed|erased)\b|\b(suppression|supprimer|effac\w*|löschen|loeschen|borrar|elimin\w*|apagar|削除|消去|抹消)\b|(?:アカウント|データ).{0,8}(?:削除|消去)|계정.{0,8}삭제/i.test(t);
  const negative = /\b(do not delete|don't delete|not delete|without deleting|instead of deleting|not a deletion|no deletion)\b/i.test(t);
  const alternative = /\b(access|export|correct|update|rectify|marketing opt.?out|unsubscribe|change my|reset my password)\b/i.test(t) && !positive;
  return positive && !negative && !alternative;
}
function parseSqlValues(line){
  const m=line.match(/^\s*INSERT\s+INTO\s+["`\w]+\s+VALUES\s*\((.*)\);\s*$/i);if(!m)return null;
  const out=[];let v='',q=false;
  for(let i=0;i<m[1].length;i++){const c=m[1][i];if(c==="'"&&q&&m[1][i+1]==="'"){v+="'";i++;}else if(c==="'")q=!q;else if(c===','&&!q){out.push(v);v='';}else v+=c;}out.push(v);return out;
}
function parseSqlSchema(text){
  const schemas=new Map();const re=/CREATE\s+TABLE\s+["`]?([\w]+)["`]?\s*\(([\s\S]*?)\);/gi;let m;
  while((m=re.exec(text))){const columns=[];for(const row of m[2].split(',')){const x=row.trim().match(/^["`]?([A-Za-z_]\w*)["`]?\s+(?:TEXT|INTEGER|REAL|BLOB|NUMERIC|BOOLEAN)/i);if(x)columns.push(x[1]);}schemas.set(m[1],columns);}
  return schemas;
}
function identityIndex() {
  const users = load('user_identities.csv'); const audits = load('user_audit_log.csv');
  const byId = new Map(users.map(u => [u.user_id, { ...u, identifiers: new Set([u.email, u.email_hash, u.phone, u.name].filter(Boolean).map(norm)), history: [] }]));
  for (const a of audits) {
    const p = byId.get(a.user_id); if (!p) continue;
    p.history.push(a);
    for (const value of [a.old_value, a.new_value]) if (value) p.identifiers.add(norm(value));
  }
  return byId;
}
function identifiersAt(profile, cutoff) {
  const values = new Set(profile.user_id ? [norm(profile.user_id)] : []);
  const snapshot = iso(profile.updated_at);
  if (!cutoff || (snapshot && snapshot <= cutoff)) {
    for (const key of ['email','email_hash','phone','name']) if (profile[key]) values.add(norm(profile[key]));
  }
  for (const event of profile.history) {
    const time = iso(event.event_time);
    if (cutoff && (!time || time > cutoff)) continue;
    if (!['email','email_hash','phone','name'].includes(norm(event.field_name))) continue;
    for (const key of ['old_value','new_value']) if (event[key]) values.add(norm(event[key]));
  }
  return values;
}
function evidenceMatches(profile, evidence) {
  const ids = profile.identifiers;
  const terms = evidence.parsed ? flatValues(evidence.parsed) : evidence.text.split(/\r?\n/).map(x => ['', x]);
  const matches = [];
  for (const [key, value] of terms) {
    const n = norm(value);
    if (ids.has(n)) matches.push({ kind: key, value });
  }
  return matches;
}
function observations(profile, evidence) {
  const wanted=profile.identifiers; const out=[];
  const scan=value=>{
    if(Array.isArray(value)){for(const x of value)scan(x);return;}
    if(!value||typeof value!=='object')return;
    const fields=flatValues(value); const hits=fields.filter(([,v])=>wanted.has(norm(v)));
    if(hits.length){
      const resource=value.resource_id||value.file_id||value.activity_id||value.audit_id;
      if(resource) out.push({resource:String(resource), object:value, hits});
    }
    for(const v of Object.values(value)) if(v&&typeof v==='object')scan(v);
  };
  if(evidence.parsed) scan(evidence.parsed);
  else for(const line of evidence.text.split(/\r?\n/)){
    const terms=[...wanted].filter(x=>x&&line.toLocaleLowerCase('en-US').includes(x));
    if(!terms.length)continue;
    const ids=line.match(/\b(?:account|search|support|analytics|telemetry|export|backup|audit_record|message|attachment|cache|replica|archive|job|data_flow)_[0-9][A-Za-z0-9_-]*\b/g)||[];
    for(const resource of new Set(ids))out.push({resource,object:{line},hits:terms.map(value=>['identifier',value])});
  }
  return out;
}
const operationRank = new Map(['REPORT_REMAINING_RECORD','REPORT_EXPOSED_PII','REPORT_ACTIVE_DATA_FLOW','REPORT_RESTORE_RISK','DISABLE_DATA_FLOW','BLOCK_RESTORE','DELETE_RECORD','REDACT_RECORD','ANONYMIZE_RECORD','VERIFY_RECORD_ABSENT','VERIFY_RECORD_PRESENT','VERIFY_RECORD_REDACTED','VERIFY_RECORD_ANONYMIZED','VERIFY_DATA_FLOW_DISABLED','VERIFY_RESTORE_BLOCKED'].map((x,i)=>[x,i]));
function sortSteps(steps) {
  const phase = { FINDING: 0, REMEDIATION: 1, VERIFICATION: 2 };
  return steps.sort((a,b) => phase[a.phase]-phase[b.phase] || operationRank.get(a.operation)-operationRank.get(b.operation) || a.system_id.localeCompare(b.system_id) || a.resource_id.localeCompare(b.resource_id));
}
function makeStep(phase, system, resource, operation, state, evidence) { return { step_no: 0, phase, system_id: system || 'unknown', resource_id: resource || 'unknown', operation, state, evidence_id: evidence || '' }; }
const RESOURCE_ID_RE=/^(?:account|search|support|analytics|telemetry|export|backup|audit_record|data_flow|archive|cache|replica|attachment|message|job|marketing|tombstone)_[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*$/i;
function isResourceId(value){return typeof value==='string'&&RESOURCE_ID_RE.test(value);}
function lineageState(record) {
  const direct=[record?.record_state,record?.state,record?.status,record?.deletion_state,record?.operation_result,record?.result].filter(x=>typeof x==='string').join(' ').toUpperCase();
  const line=typeof record?.line==='string'?record.line.toUpperCase():'';const text=`${direct} ${line}`;
  for(const state of ['ANONYMIZED','ANONYMISED','REDACTED','NOT_FOUND','ABSENT','DELETED','IDENTIFIABLE','PRESENT','FOUND','ACTIVE','ENABLED','RUNNING','RESTORABLE','AVAILABLE','BLOCKED','DISABLED']) if(new RegExp(`\\b${state}\\b`).test(text)) return state==='NOT_FOUND'||state==='DELETED'?'ABSENT':state;
  return 'UNKNOWN';
}
function relationCandidates(record,evidenceId,out=[]) {
  if(Array.isArray(record)){for(const value of record)relationCandidates(value,evidenceId,out);return out;}
  if(!record||typeof record!=='object')return out;
  const source=record.source_resource_id||record.from_resource_id||record.parent_resource_id;
  const target=record.target_resource_id||record.to_resource_id||record.child_resource_id;
  const type=record.relationship_type||record.relation_type||record.relationship||record.transfer_type||record.event_type;
  if(isResourceId(source)&&isResourceId(target)&&typeof type==='string'&&type.trim())out.push({source_resource_id:source,target_resource_id:target,type:type.trim().slice(0,80),evidence_id:evidenceId,source_system_id:record.source_system_id||record.source_system||'',target_system_id:record.target_system_id||record.target_system||'',allow_self:record.allow_self_relationship===true});
  for(const value of Object.values(record))if(value&&typeof value==='object')relationCandidates(value,evidenceId,out);
  return out;
}
function buildLineageGraph(caseResult,request,observations,evidenceFiles) {
  const caseId=caseResult.case_id,cutoff=request?.audit_at||'', evidenceById=new Map(evidenceFiles.map(x=>[x.file_id,x]));
  const nodeMap=new Map(),related=[];const key=(system,resource)=>`${system}::${resource}`;
  const findingIndex=new Map();for(const f of caseResult.findings||[]){const resource=f.resource||f.resource_id,system=f.system||f.system_id;if(isResourceId(resource))findingIndex.set(key(system||'unknown',resource),f);}
  const stepIndex=new Map();for(const s of caseResult.steps||[]){if(!isResourceId(s.resource_id))continue;const k=key(s.system_id||'unknown',s.resource_id);if(!stepIndex.has(k))stepIndex.set(k,[]);stepIndex.get(k).push(s);}
  const add=(system,resource,record,evidenceId,category,observedAt)=>{
    system=String(system||'unknown');resource=String(resource||'');if(!isResourceId(resource))return;
    const id=key(system,resource),f=findingIndex.get(id),steps=stepIndex.get(id)||[];let node=nodeMap.get(id);
    if(!node){
      category=category||f?.category||f?.data_category||'';
      const name=record?.resource_name||record?.resource_label||category||'Observed resource';
      node={id,system_id:system,resource_id:resource,resource_name:String(name).slice(0,120),resource_type:String(category||record?.record_type||'Not available').slice(0,80),presence_status:'UNKNOWN',verification_status:'UNKNOWN',verification_operation:'',evidence_ids:[],evidence:[],last_observed_at:'',audit_status:caseResult.deletion_status,audit_cutoff:cutoff,reason:f?.reason||''};nodeMap.set(id,node);
    }
    const state=lineageState(record);if(state!=='UNKNOWN')node.presence_status=state;
    if(f?.state)node.presence_status=f.state;
    if(evidenceId&&!node.evidence_ids.includes(evidenceId)){
      node.evidence_ids.push(evidenceId);const file=evidenceById.get(evidenceId);
      if(file){const label=[file.origin,path.basename(file.file_path||'')].filter(Boolean).join(' · ');node.evidence.push({evidence_id:evidenceId,description:label||'Evidence metadata unavailable',file_path:file.file_path||'',observed_at:file.captured_at||''});}
    }
    const timestamp=String(observedAt||'');if(timestamp&&(!node.last_observed_at||iso(timestamp)>iso(node.last_observed_at)))node.last_observed_at=timestamp;
    const verify=steps.find(s=>s.phase==='VERIFICATION'&&s.evidence_id&&/^VERIFY_/.test(s.operation));
    const pending=steps.some(s=>s.phase==='REMEDIATION')||Boolean(f);
    if(verify){node.verification_status='VERIFIED';node.verification_operation=verify.operation;if(['ABSENT','REDACTED','ANONYMIZED','PRESENT','DISABLED','BLOCKED'].includes(verify.state))node.presence_status=verify.state;}
    else if(pending)node.verification_status='PENDING';
    else if(!node.evidence_ids.length)node.verification_status='EVIDENCE_UNAVAILABLE';
    if(record&&typeof record==='object'&&evidenceId)related.push(...relationCandidates(record,evidenceId));
  };
  for(const observation of observations){
    const {evidence,resource,object}=observation;const resourceId=String(object?.resource_id||resource||'');
    if(!isResourceId(resourceId))continue;
    const system=observation.system_id||object?.system_id||object?.system||object?.origin_system||object?.source_system||'unknown';
    const category=object?.data_category||object?.category||object?.record_type||'';
    const time=object?.observed_at||object?.recorded_at||object?.event_time||object?.timestamp||object?.updated_at||evidence?.captured_at||'';
    add(system,resourceId,object,evidence?.file_id,category,time);
  }
  for(const step of caseResult.steps||[])if(step.evidence_id)add(step.system_id,step.resource_id,null,step.evidence_id,'',evidenceById.get(step.evidence_id)?.captured_at||'');
  const byResource=new Map();for(const n of nodeMap.values()){if(!byResource.has(n.resource_id))byResource.set(n.resource_id,[]);byResource.get(n.resource_id).push(n);}
  const resolve=(resource,system)=>{if(system){const n=nodeMap.get(key(system,resource));if(n)return n.id;}const options=byResource.get(resource)||[];return options.length===1?options[0].id:null;};
  const edgeMap=new Map();for(const rel of related){const source=resolve(rel.source_resource_id,rel.source_system_id),target=resolve(rel.target_resource_id,rel.target_system_id);if(!source||!target||(source===target&&!rel.allow_self))continue;const id=[source,target,rel.type,rel.evidence_id].join('|');edgeMap.set(id,{id,source,target,type:rel.type,evidence_id:rel.evidence_id,description:evidenceById.get(rel.evidence_id)?.file_path||'Evidence metadata unavailable'});}
  const nodes=[...nodeMap.values()].sort((a,b)=>a.system_id.localeCompare(b.system_id)||a.resource_id.localeCompare(b.resource_id));
  for(const node of nodes){if(node.evidence.length){const first=node.evidence[0];node.evidence_id=first.evidence_id;node.evidence_description=first.description;}else{node.evidence_id='';node.evidence_description='Not available';}node.last_observed_at=node.last_observed_at||node.evidence[0]?.observed_at||'';}
  const edges=[...edgeMap.values()].sort((a,b)=>a.source.localeCompare(b.source)||a.target.localeCompare(b.target)||a.type.localeCompare(b.type));
  return {case_id:caseId,audit_status:caseResult.deletion_status,audit_cutoff:cutoff,nodes,edges,relationship_status:edges.length?'Evidence-supported relationships found':'No verified resource-to-resource relationships were found for this case.'};
}
function explainFinding(finding, policyAction = '') {
  const treatment=policyAction||({REPORT_REMAINING_RECORD:'DELETE',REPORT_EXPOSED_PII:'REDACT'}[finding.op]||'REVIEW');
  const action=({REPORT_ACTIVE_DATA_FLOW:'DISABLE_DATA_FLOW',REPORT_RESTORE_RISK:'BLOCK_RESTORE'}[finding.op]||treatment);
  const reasons={
    REPORT_REMAINING_RECORD:`A matching record is still present in ${finding.system}. The ${finding.category||'identified'} treatment rule requires ${action.toLowerCase()} before this deletion can be complete.`,
    REPORT_EXPOSED_PII:`A retained or transformable record in ${finding.system} still contains a direct identifier linked to this subject. Policy requires ${action.toLowerCase()} so the record is no longer identifiable.`,
    REPORT_ACTIVE_DATA_FLOW:`The process resource ${finding.resource} is active in ${finding.system} and may copy or recreate the subject's data. Disable the flow before verifying downstream records.`,
    REPORT_RESTORE_RISK:`The resource ${finding.resource} in ${finding.system} has an active restore path that may bring deleted data back. Although policy treatment is ${treatment.toLowerCase()}, this restore path must be blocked and verified before deletion can be considered complete.`
  };
  const actions={DELETE:'Remove the whole record, then verify it is absent.',REDACT:'Keep only the policy-permitted content and remove direct identifiers, then verify redaction.',ANONYMIZE:'Irreversibly unlink the record from the subject, then verify anonymisation.',DISABLE_DATA_FLOW:'Disable the process, then verify that it cannot copy data.',BLOCK_RESTORE:'Block the restore path, then verify restoration is prevented.'};
  return {reason:reasons[finding.op]||'The available evidence shows a policy-related issue that needs review.',policy_action:treatment,recommended_action:actions[action]||'Review the applicable policy and collect verification evidence.'};
}

class Ghostprints {
  constructor() {
    this.requests = load('deletion_requests.csv'); this.sample = load('sample_deletion_requests.csv');
    this.identities = identityIndex(); this.evidence = readEvidence(); this.rules = load('deletion_rules.csv');
    this.activity = load('system_activity.csv'); this.results = new Map(); this.datasets = [];
    this.manifest = this.evidence.map(e => ({ file_id:e.file_id, file_path:e.file_path, origin:e.origin, captured_at:e.captured_at, readable:!e.error, error:e.error || null }));
    this.observationIndex=this.buildObservationIndex();
  }
  buildObservationIndex() {
    const terms=new Map();
    for(const profile of this.identities.values()) for(const value of profile.identifiers){
      if(!terms.has(value))terms.set(value,[]); terms.get(value).push(profile.user_id);
    }
    const index=new Map([...this.identities.keys()].map(id=>[id,[]]));
    const add=(e,resource,object,values)=>{
      const hitUsers=new Set();const hits=[];
      for(const value of values){const n=norm(value);const ids=terms.get(n);if(ids)for(const id of ids){hitUsers.add(id);hits.push([String(value),id]);}}
      for(const id of hitUsers)index.get(id).push({evidence:e,resource,object,hits:hits.filter(x=>x[1]===id)});
    };
    for(const e of this.evidence){if(e.error)continue;
      if(e.parsed){
        const scan=value=>{if(Array.isArray(value)){for(const x of value)scan(x);return;}if(!value||typeof value!=='object')return;
          const values=flatValues(value).map(x=>x[1]);const resource=value.resource_id||value.file_id||value.activity_id||value.audit_id;
          if(resource)add(e,String(resource),value,values);
          for(const child of Object.values(value))if(child&&typeof child==='object')scan(child);
        };scan(e.parsed);
      }else{
        const schemas=path.extname(e.file_path).toLowerCase()==='.sql'?parseSqlSchema(e.text):new Map();
        for(const line of e.text.split(/\r?\n/)){
          if(path.extname(e.file_path).toLowerCase()==='.sql'){
            const values=parseSqlValues(line);if(values?.length>=4){
              const tableMatch=line.match(/INSERT\s+INTO\s+["`]?([\w]+)["`]?\s+VALUES/i);const table=tableMatch?.[1]||'';
              let record;try{record=JSON.parse(values[3]);}catch{}
              if(record&&typeof record==='object')record={...record,origin_system:values[1],collection_name:values[2]};
              else {const columns=schemas.get(table)||[];record=Object.fromEntries(columns.map((key,i)=>[key,values[i]]));record.collection_name=table;}
              const resource=String(record.resource_id||values[0]);if(resource)add(e,resource,record,flatValues(record).map(x=>x[1]));
            }
            continue;
          }
          const candidates=[...(line.match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g)||[]),...(line.match(/\buser_\d+\b/gi)||[]),...(line.match(/\b[a-f0-9]{64}\b/gi)||[]),...(line.match(/\+?[\d][\d ()-]{7,}\d/g)||[])];
          if(!candidates.length)continue;
          const resources=line.match(/\b(?:account|search|support|analytics|telemetry|export|backup|audit_record|message|attachment|cache|replica|archive|job|data_flow)_[0-9][A-Za-z0-9_-]*\b/g)||[];
          for(const resource of new Set(resources))add(e,resource,{line},candidates);
        }
      }
    }
    return index;
  }
  analyze(req) {
    if (!deletionIntent(req.request_text)) return { case_id:req.case_id, deletion_status:'NOT_APPLICABLE', steps:[], findings:[], explanation:'Request text does not clearly authorize deletion, so no deletion audit was run.' };
    const cutoff = iso(req.audit_at);
    const matches = [...this.identities.values()].filter(p => identifiersAt(p,cutoff).has(norm(req.email)));
    if (matches.length !== 1) return { case_id:req.case_id, deletion_status:'INCOMPLETE', steps:[], findings:[], explanation:matches.length ? 'The audit is incomplete because more than one identity matches the request. Records were not merged; resolve the identity ambiguity before deciding deletion status.' : 'The audit is incomplete because the request email could not be linked to one identity profile. Resolve the identity before drawing a deletion conclusion.' , identity_ambiguous: matches.length > 1 };
    const profile = matches[0]; const caseIdentifiers=identifiersAt(profile,cutoff); const found=[],safeChecks=[]; let unresolvedEvidence=false;
    for (const observation of this.observationIndex.get(profile.user_id)||[]) {
      const e=observation.evidence;if(iso(e.captured_at)>cutoff)continue;
      if(!observation.hits.some(([value])=>caseIdentifiers.has(norm(value))))continue;
      {
        const {resource,object}=observation; const encoded=JSON.stringify(object); const system=this.systemFor(resource,encoded);
        const absent=/NOT_FOUND|"deleted"\s*:\s*true|"(?:state|status|record_state)"\s*:\s*"(?:ABSENT|NOT_FOUND|DELETED)"/i.test(encoded);
        const category=String(object.data_category||object.category||'').toUpperCase();
        const collection=String(object.collection_name||'').toLowerCase();
        const kind=category||(/tombstone/.test(collection+' '+resource)?'ACCOUNT_TOMBSTONE':/customer_profiles/.test(collection)||/account_/.test(resource)?'USER_PROFILE':/secondary_identifier/.test(collection+' '+resource)?'SECONDARY_IDENTIFIER':/search/.test(collection)||/search_/.test(resource)?'SEARCH_INDEX_ENTRY':/analytics|telemetry/.test(collection)||/analytics_|telemetry_/.test(resource)?'ANALYTICS_PROFILE':/support.*attachment|attachment/.test(collection)?'SUPPORT_ATTACHMENT':/support/.test(collection)||/support_/.test(resource)?'SUPPORT_MESSAGE':/export/.test(collection)||/export_/.test(resource)?'USER_EXPORT':/backup|archive/.test(collection)||/backup_|archive_/.test(resource)?'BACKUP_ARCHIVE':/marketing/.test(collection+' '+resource)?'MARKETING_PROFILE':/email_delivery/.test(collection+' '+resource)?'EMAIL_DELIVERY_LOG':/security_audit|audit_record_/.test(collection+' '+resource)?'SECURITY_AUDIT_LOG':'');
        const policy=this.policyAction(kind);
        const hasPII=observation.hits.some(([value])=>norm(value)!==norm(profile.user_id)) || /"(?:email|phone|full_name|name|email_hash)"\s*:\s*"[^"\s]+/i.test(encoded);
        const active=/ACTIVE|ENABLED|RUNNING|RESTORABLE|AVAILABLE|"enabled"\s*:\s*true|"restore_allowed"\s*:\s*true/i.test(encoded);
        if(/data_flow|sync|import/i.test(resource)) {
          if(active)found.push({resource,system,op:'REPORT_ACTIVE_DATA_FLOW',state:'ACTIVE',evidence:e.file_id,category:kind||'DATA_FLOW'});
          else if(/DISABLED|"enabled"\s*:\s*false|"scheduler_registered"\s*:\s*false/i.test(encoded))safeChecks.push(makeStep('VERIFICATION',system,resource,'VERIFY_DATA_FLOW_DISABLED','DISABLED',e.file_id));
          else unresolvedEvidence=true;
        } else if(/backup|archive/i.test(resource)) {
          if(active)found.push({resource,system,op:'REPORT_RESTORE_RISK',state:'ACTIVE',evidence:e.file_id,category:kind||'BACKUP_ARCHIVE'});
          else if(/BLOCKED|"restore_allowed"\s*:\s*false|"deletion_block"\s*:\s*true/i.test(encoded)) {
            safeChecks.push(makeStep('VERIFICATION',system,resource,'VERIFY_RESTORE_BLOCKED','BLOCKED',e.file_id));
            if(policy==='RETAIN')safeChecks.push(makeStep('VERIFICATION',system,resource,'VERIFY_RECORD_PRESENT','PRESENT',e.file_id));
          } else unresolvedEvidence=true;
        }
        else if(!kind||!policy) unresolvedEvidence=true;
        else if(policy==='RETAIN') {
          if(!absent)safeChecks.push(makeStep('VERIFICATION',system,resource,'VERIFY_RECORD_PRESENT','PRESENT',e.file_id));
          else unresolvedEvidence=true;
        } else if(policy==='DELETE') {
          if(!absent&&/(?:ACTIVE|IDENTIFIABLE|FOUND|PRESENT|SUCCESS|"deleted"\s*:\s*false)/i.test(encoded))found.push({resource,system,op:'REPORT_REMAINING_RECORD',state:'PRESENT',evidence:e.file_id,category:kind});
          else if(absent)safeChecks.push(makeStep('VERIFICATION',system,resource,'VERIFY_RECORD_ABSENT','ABSENT',e.file_id));
          else unresolvedEvidence=true;
        } else if(policy==='REDACT'||policy==='ANONYMIZE') {
          if(hasPII)found.push({resource,system,op:'REPORT_EXPOSED_PII',state:'PRESENT',evidence:e.file_id,category:kind});
          else if(!absent)safeChecks.push(makeStep('VERIFICATION',system,resource,policy==='REDACT'?'VERIFY_RECORD_REDACTED':'VERIFY_RECORD_ANONYMIZED',policy==='REDACT'?'REDACTED':'ANONYMIZED',e.file_id));
          else unresolvedEvidence=true;
        } else unresolvedEvidence=true;
      }
    }
    // Activity is contextual only: require a related, independently matched evidence item.
    const steps = [];
    for (const f of dedupe(found)) steps.push(makeStep('FINDING',f.system,f.resource,f.op,f.state,f.evidence));
    const matchedByCutoff=(this.observationIndex.get(profile.user_id)||[]).filter(o=>iso(o.evidence.captured_at)<=cutoff&&o.hits.some(([value])=>caseIdentifiers.has(norm(value))));
    const incomplete = steps.length > 0 || unresolvedEvidence || matchedByCutoff.length===0;
    if(incomplete && !found.length) return { case_id:req.case_id,deletion_status:'INCOMPLETE',steps:[],findings:[],explanation:`The audit is incomplete because no matching evidence proves the required final state by ${req.audit_at}. This is an evidence gap, not proof of deletion or a confirmed remaining copy.`,missing_evidence:true };
    if (incomplete) {
      for (const f of dedupe(found)) {
        const treatment=this.policyAction(f.category);
        const op = f.op==='REPORT_ACTIVE_DATA_FLOW'?'DISABLE_DATA_FLOW':f.op==='REPORT_RESTORE_RISK'?'BLOCK_RESTORE':({DELETE:'DELETE_RECORD',REDACT:'REDACT_RECORD',ANONYMIZE:'ANONYMIZE_RECORD'}[treatment]||'DELETE_RECORD');
        const state = op === 'REDACT_RECORD' ? 'REDACTED' : op==='ANONYMIZE_RECORD'?'ANONYMIZED':'ABSENT';
        const remediationState=op==='DISABLE_DATA_FLOW'?'DISABLED':op==='BLOCK_RESTORE'?'BLOCKED':state;
        steps.push(makeStep('REMEDIATION',f.system,f.resource,op,remediationState,''));
        const verify = op==='DISABLE_DATA_FLOW'?'VERIFY_DATA_FLOW_DISABLED':op==='BLOCK_RESTORE'?'VERIFY_RESTORE_BLOCKED':op === 'REDACT_RECORD' ? 'VERIFY_RECORD_REDACTED' : op==='ANONYMIZE_RECORD'?'VERIFY_RECORD_ANONYMIZED':'VERIFY_RECORD_ABSENT';
        steps.push(makeStep('VERIFICATION',f.system,f.resource,verify,remediationState,''));
      }
    } else if (!incomplete) {
      if(!safeChecks.some(s=>s.operation!=='VERIFY_RECORD_PRESENT')) return { case_id:req.case_id, deletion_status:'INCOMPLETE', steps:[], findings:[], explanation:`The audit is incomplete because evidence of retained records alone does not prove the required deletion treatment by ${req.audit_at}.`, missing_evidence:true };
      steps.push(...safeChecks);
    } else {
      return { case_id:req.case_id, deletion_status:'INCOMPLETE', steps:[], findings:[], explanation:`The audit is incomplete because matching evidence is missing or unreadable at the ${req.audit_at} cutoff. This is an evidence gap, not confirmation that data remains or was deleted.`, missing_evidence:true };
    }
    sortSteps(steps); steps.forEach((s,i)=>s.step_no=i+1);
    const findingDetails=dedupe(found).map(f=>({...f,...explainFinding(f,this.policyAction(f.category))}));
    const affected=[...new Set(findingDetails.map(f=>f.system))];
    const explanation=incomplete?`The audit is incomplete: ${findingDetails.length} evidence-backed issue(s) were found in ${affected.join(', ')||'the supplied records'}. Open “Why this audit is incomplete” to see each resource, policy treatment, and evidence reference.`:'No policy violation was found in the matched evidence before the audit cutoff; see the verification steps for the evidence references supporting this status.';
    return { case_id:req.case_id, deletion_status:incomplete?'INCOMPLETE':'COMPLETE', steps, findings:findingDetails, explanation };
  }
  systemFor(resource, context='') {
    const map = [['account','account_service'],['search','search_service'],['support','support_platform'],['analytics','analytics_platform'],['telemetry','analytics_platform'],['export','export_service'],['backup','backup_service'],['audit_record','security_service'],['data_flow','integration_service'],['cache','cache_service'],['archive','archive_service']];
    return (map.find(([p])=>resource.startsWith(p))||[])[1] || (context.match(/(?:account_service|search_service|support_platform|analytics_platform|security_service|backup_service|export_service|integration_service|identity_service)/)||[])[0] || 'unknown';
  }
  policyAction(category) { return this.rules.find(r=>r.data_category.toUpperCase()===String(category).toUpperCase())?.required_action.toUpperCase()||''; }
  lineage(caseResult,request) {
    const cutoff=iso(request?.audit_at),profiles=[...this.identities.values()].filter(p=>identifiersAt(p,cutoff).has(norm(request?.email)));
    if(profiles.length!==1)return {case_id:caseResult.case_id,audit_status:caseResult.deletion_status,audit_cutoff:request?.audit_at||'',nodes:[],edges:[],relationship_status:profiles.length?'Identity is ambiguous; resource observations were not combined.':'Identity could not be resolved; no case resources can be safely attributed.'};
    const identifiers=identifiersAt(profiles[0],cutoff);
    const observations=(this.observationIndex.get(profiles[0].user_id)||[]).filter(o=>iso(o.evidence.captured_at)<=cutoff&&o.hits.some(([value])=>identifiers.has(norm(value)))).map(o=>({...o,system_id:this.systemFor(o.resource,JSON.stringify(o.object||{}))}));
    return buildLineageGraph(caseResult,request,observations,this.manifest);
  }
  all() { return this.requests.map(r=>{if(!this.results.has(r.case_id))this.results.set(r.case_id,this.analyze(r));return this.results.get(r.case_id);}); }
  run() { for (const r of this.requests) this.results.set(r.case_id,this.analyze(r)); return this.all(); }
  dashboard() {
    const cases=this.all(); const counts={COMPLETE:0,INCOMPLETE:0,NOT_APPLICABLE:0}; cases.forEach(c=>counts[c.deletion_status]++);
    const findings=cases.flatMap(c=>c.steps.filter(s=>s.phase==='FINDING'));
    const riskOf=c=>{const f=c.steps.filter(s=>s.phase==='FINDING');if(f.some(s=>s.operation==='REPORT_RESTORE_RISK'||s.operation==='REPORT_ACTIVE_DATA_FLOW')&&f.length>2)return'CRITICAL';if(f.some(s=>s.operation==='REPORT_RESTORE_RISK'||s.operation==='REPORT_ACTIVE_DATA_FLOW')||f.length>2)return'HIGH';if(f.length)return'MEDIUM';return c.deletion_status==='COMPLETE'?'LOW':'UNKNOWN';};
    const riskCounts={LOW:0,MEDIUM:0,HIGH:0,CRITICAL:0};cases.forEach(c=>{const r=riskOf(c);if(riskCounts[r]!==undefined)riskCounts[r]++;});
    return { total_requests:cases.length, completed:counts.COMPLETE, incomplete:counts.INCOMPLETE, not_applicable:counts.NOT_APPLICABLE, remaining_records:findings.length, active_flows:findings.filter(x=>x.operation==='REPORT_ACTIVE_DATA_FLOW').length, restore_risks:findings.filter(x=>x.operation==='REPORT_RESTORE_RISK').length, high_risk_cases:cases.filter(c=>['HIGH','CRITICAL'].includes(riskOf(c))).length, risk_distribution:riskCounts, by_system:Object.fromEntries([...new Set(findings.map(f=>f.system_id))].map(s=>[s,findings.filter(f=>f.system_id===s).length])), recent:cases.slice(-10) };
  }
  export() {
    const rows=this.all().slice().sort((a,b)=>a.case_id.localeCompare(b.case_id));
    return 'case_id,deletion_status,steps_json\n'+rows.map(c=>[c.case_id,c.deletion_status,esc(JSON.stringify(c.steps))].join(',')).join('\n')+'\n';
  }
}
function dedupe(items) { const seen=new Set(); return items.filter(x=>{const k=[x.resource,x.system,x.op,x.evidence].join('|'); if(seen.has(k)) return false; seen.add(k); return true;}); }
const app = new Ghostprints();
const MIME = { '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml' };

function readJSONBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) { reject(new Error('Request body exceeds the local AI request limit.')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { reject(new Error('Request body must be valid JSON.')); }
    });
    req.on('error', () => reject(new Error('Request body could not be read.')));
  });
}

function sendAI(res, route, payload, method = 'POST') {
  if (['ai/analyze-evidence','ai/explain-case','ai/investigate'].includes(route) && payload?.case_id) {
    const request = app.requests.find(item => item.case_id === payload.case_id);
    if (request) payload = { ...payload, deterministic_case: app.analyze(request) };
  }
  proxyAI(route, payload, method).then(result => {
    res.writeHead(result.status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store' });
    res.end(JSON.stringify(result.body));
  }).catch(error => {
    res.writeHead(503, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store' });
    res.end(JSON.stringify({ error: String(error?.message || 'Local AI service is unavailable.').slice(0, 180) }));
  });
}

const server = http.createServer((req,res)=>{
  const origin = req.headers.origin;
  if (origin) {
    try { if (isLoopback(new URL(origin).hostname)) res.setHeader('Access-Control-Allow-Origin', origin); }
    catch { /* Invalid origins receive no CORS permission. */ }
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers','Content-Type'); res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  if(req.method==='OPTIONS'){res.writeHead(204);return res.end();}
  const url=new URL(req.url,'http://localhost'); const parts=url.pathname.split('/').filter(Boolean);
  const json=(code,value)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value));};
  if(url.pathname==='/api/health') { const ai=aiConfiguration(); return json(200,{status:'ok',product:'GHOSTGUARD',requests:app.requests.length,evidence_files:app.manifest.length,ai_configured:ai.enabled,ai_provider:ai.provider,ai_model:ai.model||null}); }
  if(url.pathname.startsWith('/api/ai/') || (parts[0]==='api'&&parts[1]==='investigations'&&parts[3]==='ai-explanation')) {
    if(origin) {
      try { if(!isLoopback(new URL(origin).hostname)) return json(403,{error:'Local AI endpoints accept only loopback browser origins.'}); }
      catch { return json(403,{error:'Local AI endpoints accept only loopback browser origins.'}); }
    }
  }
  if(url.pathname==='/api/ai/health'&&req.method==='GET') return sendAI(res,'ai/health',undefined,'GET');
  if(url.pathname.startsWith('/api/ai/')&&req.method==='POST') {
    const route=url.pathname.slice('/api/'.length);
    if(!['ai/retrieve-evidence','ai/analyze-evidence','ai/explain-case','ai/investigate'].includes(route)) return json(404,{error:'AI endpoint not found.'});
    return readJSONBody(req).then(body=>sendAI(res,route,body)).catch(error=>json(400,{error:error.message}));
  }
  if(url.pathname==='/api/dashboard/summary') return json(200,app.dashboard());
  if(url.pathname==='/api/forensics/aggregate') {
    const cases=app.all();
    return json(200,{total:cases.length,items:cases.map(c=>{const request=app.requests.find(r=>r.case_id===c.case_id)||{};return {case_id:c.case_id,deletion_status:c.deletion_status,risk_level:c.risk_level||'UNKNOWN',request:{requested_at:request.requested_at||'',audit_at:request.audit_at||''},steps:(c.steps||[]).map(s=>({step_no:s.step_no,phase:s.phase,system_id:s.system_id,resource_id:s.resource_id,operation:s.operation,state:s.state,evidence_id:s.evidence_id||''}))}})});
  }
  if(url.pathname==='/api/datasets') return json(200,[{dataset_id:'official-challenge',request_count:app.requests.length,evidence_count:app.manifest.length,files:app.manifest}]);
  if(url.pathname==='/api/datasets/official-challenge') return json(200,{dataset_id:'official-challenge',request_count:app.requests.length,evidence_count:app.manifest.length,manifest:app.manifest,missing:app.manifest.filter(f=>!f.readable)});
  if(url.pathname==='/api/investigations/run' && req.method==='POST') return json(200,{processed:app.requests.length,results:app.run().length});
  if(url.pathname==='/api/investigations') {
    const q=norm(url.searchParams.get('q')||''); const status=url.searchParams.get('status');
    const out=app.all().filter(c=>{const r=app.requests.find(x=>x.case_id===c.case_id); return (!status||c.deletion_status===status)&&(!q||norm([c.case_id,r?.email,r?.request_text].join(' ')).includes(q));});
    const offset=Math.max(0,Number(url.searchParams.get('offset')||0)); const limit=Math.min(1000,Math.max(1,Number(url.searchParams.get('limit')||25)));
    return json(200,{total:out.length,items:out.slice(offset,offset+limit).map(c=>({...c,request:app.requests.find(r=>r.case_id===c.case_id)}))});
  }
  if(parts[0]==='api'&&parts[1]==='investigations'&&parts[2]) {
    const c=app.all().find(x=>x.case_id===parts[2]); if(!c) return json(404,{error:'Case not found'});
    const request=app.requests.find(x=>x.case_id===c.case_id);
    const identity=[...app.identities.values()].find(p=>identifiersAt(p,iso(request?.audit_at)).has(norm(request?.email)));
    const evidenceIds=[...new Set((c.steps||[]).map(s=>s.evidence_id).filter(Boolean))];
    if(parts[3]==='ai-explanation'&&req.method==='POST') { explainCase(c,request).then(result=>json(200,result)).catch(error=>json(503,{error:String(error?.message||'Local AI explanation is unavailable.').slice(0,180)})); return; }
    if(parts[3]==='identity') {
      const cutoff=iso(request?.audit_at), history=(identity?.history||[]).filter(a=>!cutoff||!iso(a.event_time)||iso(a.event_time)<=cutoff), emailEvents=history.filter(a=>norm(a.field_name)==='email').sort((a,b)=>iso(a.event_time)-iso(b.event_time));
      const snapshotInScope=Boolean(identity&&(!cutoff||!iso(identity.updated_at)||iso(identity.updated_at)<=cutoff));
      const currentEmail=emailEvents.at(-1)?.new_value||(snapshotInScope?identity.email:request?.email)||'';
      const historicalEmails=[...new Set(emailEvents.flatMap(a=>[a.old_value,a.new_value]).filter(Boolean).filter(v=>norm(v)!==norm(currentEmail)))];
      const historicalIdentifiers={},knownIdentifiers=new Set(identity?.user_id?[identity.user_id]:[]);
      if(snapshotInScope)for(const field of ['email','name','phone','email_hash'])if(identity?.[field])knownIdentifiers.add(identity[field]);
      for(const event of history){const field=norm(event.field_name);if(!['email','name','phone','email_hash'].includes(field))continue;if(!historicalIdentifiers[field])historicalIdentifiers[field]=new Set();for(const key of ['old_value','new_value'])if(event[key]){historicalIdentifiers[field].add(event[key]);knownIdentifiers.add(event[key]);}}
      if(currentEmail&&historicalIdentifiers.email)historicalIdentifiers.email.delete(currentEmail);
      return json(200,{user_id:identity?.user_id||'',current_email:currentEmail,historical_emails:historicalEmails,historical_identifiers:Object.fromEntries(Object.entries(historicalIdentifiers).map(([key,values])=>[key,[...values]]).filter(([,values])=>values.length)),known_identifiers:[...knownIdentifiers],resolution_status:identity?'RESOLVED':'UNRESOLVED',evidence_ids:evidenceIds});
    }
    if(parts[3]==='findings') return json(200,(c.findings||[]).map(s=>{
      const resourceId=s.resource||s.resource_id;const systemId=s.system||s.system_id;const operation=s.op||s.operation;const evidenceId=s.evidence||s.evidence_id;
      const source=app.evidence.find(e=>e.file_id===evidenceId);let excerpt='';
      if(source?.text){const at=source.text.toLocaleLowerCase('en-US').indexOf(String(resourceId||'').toLocaleLowerCase('en-US'));if(at>=0)excerpt=source.text.slice(Math.max(0,at-100),Math.min(source.text.length,at+420)).replace(/\s+/g,' ').trim();}
      const step=c.steps.find(x=>x.phase==='FINDING'&&x.resource_id===resourceId&&x.operation===operation);
      return {...step,system_id:systemId,resource_id:resourceId,operation,state:s.state,evidence_id:evidenceId,data_category:s.category||s.data_category||'Unclassified',reason:s.reason||'',policy_action:s.policy_action||'',recommended_action:s.recommended_action||'',evidence_excerpt:excerpt};
    }));
    if(parts[3]==='verification') return json(200,c.steps.filter(s=>s.phase==='VERIFICATION'));
    if(parts[3]==='certificate') return json(200,{case_id:c.case_id,eligible:c.deletion_status==='COMPLETE',evidence_ids:evidenceIds,hash_scope:'recorded evidence references and step metadata'});
    if(parts[3]==='evidence') return json(200,{case_id:c.case_id,items:c.steps.map(s=>s.evidence_id).filter(Boolean).map(id=>app.manifest.find(f=>f.file_id===id)).filter(Boolean)});
    if(parts[3]==='timeline') return json(200,{case_id:c.case_id,request:app.requests.find(x=>x.case_id===c.case_id),steps:c.steps});
    if(parts[3]==='graph'&&req.method==='GET') return json(200,app.lineage(c,request));
    if(parts[3]==='risks') return json(200,c.steps.filter(s=>s.phase==='FINDING'));
    if(parts[3]==='remediation') return json(200,c.steps.filter(s=>s.phase!=='FINDING'));
    return json(200,{...c,request:app.requests.find(x=>x.case_id===c.case_id)});
  }
  if(url.pathname==='/api/risk-analysis') {
    const findings=app.all().flatMap(c=>c.steps.filter(s=>s.phase==='FINDING').map(s=>({...s,case_id:c.case_id})));
    return json(200,{findings,active_flows:findings.filter(s=>s.operation==='REPORT_ACTIVE_DATA_FLOW').length,restore_risks:findings.filter(s=>s.operation==='REPORT_RESTORE_RISK').length});
  }
  if(url.pathname==='/api/reports/export') { const body=app.export(); res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="output.csv"'}); return res.end(body); }
  if(url.pathname==='/api/evidence') return json(200,app.manifest);
  if(req.method==='POST'&&url.pathname==='/api/datasets/upload') return json(400,{error:'Upload is disabled for this challenge build. Evidence ingestion is read-only and uses the participant dataset manifest.'});
  const isDashboardRoute=url.pathname==='/dashboard'||url.pathname==='/dashboard/';
  const filename=url.pathname==='/'?path.join(__dirname,'frontend','landing.html'):isDashboardRoute?path.join(__dirname,'frontend','index.html'):parts.length?path.resolve(__dirname,'frontend',...parts):path.join(__dirname,'frontend','landing.html');
  const rel=path.relative(path.join(__dirname,'frontend'),filename); if(rel.startsWith('..')||path.isAbsolute(rel)) return json(403,{error:'Invalid path'});
  fs.readFile(filename,(err,content)=>{if(err){res.writeHead(404);return res.end('Not found');}res.writeHead(200,{'Content-Type':MIME[path.extname(filename)]||'application/octet-stream'});res.end(content);});
});
if (require.main===module) {
  if(process.argv.includes('--export')){fs.writeFileSync(OUTPUT,app.export(),'utf8');console.log(`Wrote ${app.requests.length} rows to ${OUTPUT}`);}
  else if(process.argv.includes('--evaluate-sample')){
    const expected=load('sample_output.csv');const requests=load('sample_deletion_requests.csv');
    const canonical=x=>JSON.stringify(x,(_k,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
    let statusCorrect=0,sequenceCorrect=0,expectedSteps=0,matchedSteps=0,fieldsCorrect=0,fieldCount=0;
    for(const expectedRow of expected){const request=requests.find(x=>x.case_id===expectedRow.case_id);if(!request)continue;
      const actual=app.analyze(request);const a=actual.steps;const e=JSON.parse(expectedRow.steps_json);
      if(actual.deletion_status===expectedRow.deletion_status)statusCorrect++;
      if(canonical(a)===canonical(e))sequenceCorrect++;
      expectedSteps+=e.length;for(let i=0;i<Math.max(a.length,e.length);i++){
        if(i<a.length&&i<e.length){if(canonical(a[i])===canonical(e[i]))matchedSteps++;for(const key of ['step_no','phase','system_id','resource_id','operation','state','evidence_id']){fieldCount++;if(a[i][key]===e[i][key])fieldsCorrect++;}}
      }
    }
    const result={sample_cases:expected.length,status_accuracy:statusCorrect/expected.length,step_sequence_accuracy:sequenceCorrect/expected.length,exact_step_fraction:expectedSteps?matchedSteps/expectedSteps:0,field_accuracy:fieldCount?fieldsCorrect/fieldCount:0,status_correct:statusCorrect,sequence_correct:sequenceCorrect,expected_step_count:expectedSteps,field_count:fieldCount,fields_correct:fieldsCorrect};
    console.log(JSON.stringify(result,null,2));
  }
  else if(process.argv.includes('--debug-sample')){
    const expected=load('sample_output.csv');const requests=load('sample_deletion_requests.csv');
    for(const e of expected){const r=requests.find(x=>x.case_id===e.case_id);const a=app.analyze(r);if(a.deletion_status!==e.deletion_status||JSON.stringify(a.steps)!==JSON.stringify(JSON.parse(e.steps_json)))console.log(JSON.stringify({case_id:e.case_id,email:r.email,expected_status:e.deletion_status,actual_status:a.deletion_status,expected_steps:JSON.parse(e.steps_json).slice(0,3),actual_steps:a.steps.slice(0,3),note:a.explanation}));}
  }
  else if(process.argv.includes('--debug-one')){
    const id=process.argv[process.argv.indexOf('--debug-one')+1];const request=app.sample.find(x=>x.case_id===id);const profile=[...app.identities.values()].find(p=>p.identifiers.has(norm(request?.email)));
    console.log(JSON.stringify({request,profile:profile&&{user_id:profile.user_id,identifiers:[...profile.identifiers]},observations:profile&&(app.observationIndex.get(profile.user_id)||[]).map(o=>({file_id:o.evidence.file_id,captured_at:o.evidence.captured_at,resource:o.resource,object:o.object})),result:request&&app.analyze(request)},null,2));
  }
  else {
    server.on('error',error=>{
      if(error.code==='EADDRINUSE'&&!process.env.PORT){
        const busy=PORT;PORT+=1;console.warn(`Port ${busy} is occupied; trying ${PORT}. Set PORT to choose another port.`);server.listen(PORT);return;
      }
      console.error(`GHOST PRINT could not listen on port ${PORT}: ${error.message}`);process.exitCode=1;
    });
    server.on('listening',()=>console.log(`GHOST PRINT listening on http://localhost:${server.address().port}`));
    server.listen(PORT);
  }
}
module.exports={Ghostprints,csv,deletionIntent,parseSqlValues,parseSqlSchema,explainFinding,buildLineageGraph,isResourceId};
