export const MAX_FILE = 50 * 1024 * 1024;
export function validateSubmission(s){
 if(!s.author?.trim()||!s.title?.trim())throw Error('请填写称呼和这段记忆的名字。');
 if(s.author.length>80||s.title.length>150||(s.story||'').length>10000)throw Error('文字太长，请缩短后保存。');
 if(!['photo','story','correction','shoot'].includes(s.kind)||!['team','private'].includes(s.privacy))throw Error('提交类型不正确。');
 if((s.x==null)!==(s.y==null)||s.x!=null&&(!Number.isFinite(s.x)||!Number.isFinite(s.y)||s.x<0||s.x>1058||s.y<0||s.y>1186))throw Error('地图位置超出范围。');
 return s;
}
export function checkedReview(s, revision, status, note=''){
 if(s.revision!==revision)throw Error('这条资料已被更新，请刷新后再核对。');
 if(!['approved','needs_info','rejected'].includes(status))throw Error('核对结果不正确。');
 return {...s,status,review_note:note,revision:revision+1,updated_at:new Date().toISOString()};
}
export function validateFiles(files){
 if(files.length>12)throw Error('一次最多提交 12 个文件。');
 for(const f of files){if(f.size>MAX_FILE)throw Error(`${f.name} 超过 50 MB，请保留原片，先提交短片或照片。`);if(!/\.(jpe?g|png|webp|heic|heif|mp4|mov)$/i.test(f.name))throw Error(`${f.name} 格式暂不支持。`);}
}
export function mergeBoxes(trace, state={}){
 const base=[...(trace.otherVisibleRoofs||[]),...(trace.roofSegments||[])];
 const ids=new Set(base.map(b=>b.id));
 return [...base.map(b=>({...b,...state.boxes?.[b.id]})),...(state.addedBoxes||[]).filter(b=>!ids.has(b.id))];
}
export function uniqueFiles(files){const seen=new Set();return files.filter(f=>{if(seen.has(f.sha256))return false;seen.add(f.sha256);return true})}
export function cloudReady(c){return c.mode==='cloud'&&/^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(c.supabaseUrl)&&typeof c.supabasePublishableKey==='string'&&c.supabasePublishableKey.length>20}
export const statusText={pending:'待核对',approved:'已核对',needs_info:'待补充',rejected:'未采用'};
