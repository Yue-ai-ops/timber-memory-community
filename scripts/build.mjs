import fs from 'node:fs';
const source=new URL('../web/',import.meta.url),out=new URL('../dist/',import.meta.url);
fs.mkdirSync(out,{recursive:true});
// Allow-list only: never recursively copy a private local preview into a public build.
for(const name of ['index.html','style.css','app.js','core.js','config.json'])fs.copyFileSync(new URL(name,source),new URL(name,out));
const cfg=JSON.parse(fs.readFileSync(new URL('config.json',out),'utf8'));
if(cfg.mode!=='cloud')throw Error('Public builds must use cloud mode.');
if(fs.existsSync(new URL('private-data',out)))throw Error('Remove private-data from public output before deploying.');
fs.mkdirSync(new URL('vendor/',out),{recursive:true});
fs.copyFileSync(new URL('../node_modules/@google/model-viewer/dist/model-viewer.min.js',import.meta.url),new URL('vendor/model-viewer.min.js',out));
console.log('Public build ready; no photos, source maps, annotations or model data included.');
