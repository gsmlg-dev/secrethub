// Runs a pinned official CLI without placing passwords, session keys or ciphertext in console output.
const {spawnSync} = require('node:child_process');
const fs = require('node:fs'), assert = require('node:assert/strict');
const [fixturePath, cliPath, profile] = process.argv.slice(2);
const fixture = JSON.parse(fs.readFileSync(fixturePath));
fs.mkdirSync(profile, {recursive:true, mode:0o700}); fs.chmodSync(profile, 0o700);
const env = {...process.env, BITWARDENCLI_APPDATA_DIR: profile, HUMAN_CLIENT_PASSWORD: fixture.password};
for (const key of Object.keys(env)) if (/^(https?|all)_proxy$/i.test(key)) delete env[key];
function bw(args, input) {
 const r = spawnSync(process.execPath, [cliPath, ...args, '--nointeraction'], {env, input, encoding:'utf8', timeout:60000, maxBuffer:8*1024*1024});
 fs.mkdirSync(profile, {recursive:true}); fs.writeFileSync(profile+"/last-diagnostic.json", JSON.stringify({command:args[0],status:r.status,stderr:r.stderr}), {mode:0o600});
 if(r.status !== 0) throw new Error(`Official CLI ${args[0]} failed: ${String(r.stderr).slice(0,600)}`);
 return r.stdout.trim();
}
const encode = data => Buffer.from(JSON.stringify(data)).toString('base64');
const report = {client: '@bitwarden/cli', version: bw(['--version']), tests: []};
assert.equal(report.version, '2026.9.1');
function check(name, fn) { fn(); report.tests.push({name, result: 'pass'}); console.log(`PASS ${name}`); }
check('configure self-hosted origin', () => bw(['config','server','https://127.0.0.1:14666']));
check('login and unlock', () => { bw(['login', fixture.email, '--passwordenv','HUMAN_CLIENT_PASSWORD']); env.BW_SESSION = bw(['unlock', '--passwordenv','HUMAN_CLIENT_PASSWORD','--raw']); assert.ok(env.BW_SESSION.length > 20, `login yielded ${env.BW_SESSION.length} characters`); });
check('initial sync', () => bw(['sync']));
let folder, item;
check('create encrypted folder', () => { folder = JSON.parse(bw(['create','folder',encode({name:'Official folder'})])); assert.equal(folder.name,'Official folder'); });
check('create encrypted login item', () => { item = JSON.parse(bw(['create','item',encode({type:1,name:'Official login',folderId:folder.id,login:{username:'fixture-user',password:'fixture-credential',uris:[{uri:'https://example.test',match:null}]}})])); assert.equal(item.login.password,'fixture-credential'); });
check('update and sync login item', () => { item.name='Updated official login'; item.login.password='changed-fixture-credential'; bw(['edit','item',item.id,encode(item)]); bw(['sync']); const got=JSON.parse(bw(['get','item',item.id])); assert.equal(got.name,item.name); assert.equal(got.login.password,item.login.password); });
check('folder update synchronizes', () => { folder.name='Updated folder'; bw(['edit','folder',folder.id,encode(folder)]); bw(['sync']); assert.equal(JSON.parse(bw(['get','folder',folder.id])).name,folder.name); });
check('item deletion synchronizes', () => { bw(['delete','item',item.id]); bw(['sync']); assert.ok(!JSON.parse(bw(['list','items'])).some(x=>x.id===item.id)); });
check('folder deletion synchronizes', () => { bw(['delete','folder',folder.id]); bw(['sync']); assert.ok(!JSON.parse(bw(['list','folders'])).some(x=>x.id===folder.id)); });
check('logout and device relogin', () => { bw(['logout']); delete env.BW_SESSION; bw(['login',fixture.email,'--passwordenv','HUMAN_CLIENT_PASSWORD']); env.BW_SESSION=bw(['unlock','--passwordenv','HUMAN_CLIENT_PASSWORD','--raw']); bw(['sync']); bw(['logout']); delete env.BW_SESSION; });
fs.writeFileSync(profile+'/acceptance-report.json',JSON.stringify(report,null,2));
