// Exercise a real TLS websocket with Microsoft's official SignalR MessagePack decoder.
const fs = require('node:fs'), assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const requireClient = createRequire(process.argv[3]);
const WebSocket = requireClient('ws');
const { MessagePackHubProtocol } = requireClient('@microsoft/signalr-protocol-msgpack');
const fixture = JSON.parse(fs.readFileSync(process.argv[2]));
const other = JSON.parse(fs.readFileSync(process.argv[4]));
const origin = 'https://127.0.0.1:14666';
const protocol = new MessagePackHubProtocol(), logger = {log() {}};
const report = {client: '@microsoft/signalr-protocol-msgpack', tests: []};
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function api(path, body, token, method = body === undefined ? 'GET' : 'POST') {
 const response = await fetch(origin + path, {method, headers: {'Content-Type':'application/json', ...(token ? {Authorization:`Bearer ${token}`} : {})}, body: body === undefined ? undefined : JSON.stringify(body)});
 assert.ok(response.ok, `HTTP ${response.status} for ${path}`); return response.json();
}
async function login(input, device) {
 return (await api('/identity/connect/token', {grant_type:'password', username:input.email, password:input.password_hash, deviceIdentifier:device, deviceName:'Notification acceptance', deviceType:9})).access_token;
}
function claims(token) { return JSON.parse(Buffer.from(token.split('.')[1], 'base64url')); }
function connect(token, handshake = '{"protocol":"messagepack","version":1}\u001e') {
 return new Promise((resolve,reject) => {
  const socket = new WebSocket(origin.replace('https','wss') + '/notifications/hub', {headers:{Authorization:`Bearer ${token}`}, ca:fs.readFileSync(process.env.HUMAN_CLIENT_CERT)});
  const state = {socket,messages:[],close:null};
  const timeout = setTimeout(() => {socket.close();reject(new Error('Websocket handshake timeout'));},10000);
  socket.on('open', () => socket.send(handshake));
  socket.on('error', reject);
  socket.on('close', code => state.close = code);
  socket.on('message', (data,binary) => {
   if (!binary) { assert.equal(data.toString(),'{}\u001e'); clearTimeout(timeout);resolve(state); }
   else state.messages.push(...protocol.parseMessages(data.buffer.slice(data.byteOffset,data.byteOffset+data.byteLength),logger));
  });
 });
}
async function until(check, timeout=5000) { const end=Date.now()+timeout;while(!check()){assert.ok(Date.now()<end,'Timed out waiting for notification');await pause(50);} }
(async () => {
 const token = await login(fixture,'notification-owner'), outsider = await login(other,'notification-outsider');
 const ownerSocket = await connect(token), outsiderSocket = await connect(outsider);
 try {
  ownerSocket.socket.send(Buffer.from(protocol.writeMessage({type:6})));
  await api('/api/folders', {name:fixture.encrypted_key}, token);
  await until(() => ownerSocket.messages.some(m=>m.target==='ReceiveMessage'));
  const notification=ownerSocket.messages.find(m=>m.target==='ReceiveMessage').arguments[0];
  assert.equal(notification.Type,5);assert.equal(notification.Payload.UserId,claims(token).sub);
  await pause(500);assert.ok(!outsiderSocket.messages.some(m=>m.target==='ReceiveMessage'));
  report.tests.push({name:'official decoder parses user-scoped vault invalidation over TLS websocket',result:'pass'});
  await api('/human/sessions/'+claims(token).sid,undefined,token,'DELETE');
  await until(()=>ownerSocket.close===1008,20000);
  assert.equal(outsiderSocket.close,null);
  report.tests.push({name:'revoked session closes on heartbeat while other user remains connected',result:'pass'});
  fs.writeFileSync(process.argv[5],JSON.stringify(report,null,2));
  report.tests.forEach(t=>console.log('PASS '+t.name));
 } finally { ownerSocket.socket.close();outsiderSocket.socket.close(); }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
