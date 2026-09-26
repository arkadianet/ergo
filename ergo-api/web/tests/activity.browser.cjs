// Optional isolated browser regression: node ergo-api/web/tests/activity.browser.cjs
// Requires Playwright and its browser (or BROWSER_CHANNEL=msedge). All APIs are
// fixtures; external requests and non-GET methods are blocked. Screenshots use
// a temporary directory unless ACTIVITY_SCREENSHOT_DIR is supplied.
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const output = process.env.ACTIVITY_SCREENSHOT_DIR || fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'ergo-activity-'));
const now = Date.now();
let session = 'qa-session', fail = 0, delay = 0, badKey = false, requests = 0;
const makeRecord = (seq, extra = {}) => ({seq:String(seq), unixMs:now - (90 - seq)*6000, level:'INFO', target:'ergo_node::node', message:'Node started', fields:{code:'node_started'}, truncated:false, ...extra});
let records = [
  makeRecord(1, {level:'ERROR', target:'ergo_indexer', message:'Index repair requires attention', fields:{code:'index_repair', height:1865720, reason:'An expected entry could not be read'}}),
  ...Array.from({length:12}, (_,i)=>makeRecord(i+2, {level:'WARN', target:'ergo_p2p::delivery', message:'Peer request timed out; retry scheduled', fields:{code:'peer_timeout',peer:'192.0.2.14:9030',latency_ms:4000+i,attempt:i+1}})),
  makeRecord(14, {message:'Chain advanced beyond rejected block', target:'ergo_node::activity',fields:{code:'node_condition',condition:'block_rejection',state:'recovered',evidence:'rejected_height=1865712 applied_height=1865713'}}),
  makeRecord(15, {message:'heartbeat tick'}),
  makeRecord(16, {level:'WARN', message:'Peer disconnected after repeated timeouts',target:'ergo_p2p',fields:{peer:'192.0.2.19:9030'}}),
  ...Array.from({length:45}, (_,i)=>makeRecord(17+i, {message: i%3 ? 'Peer connected' : 'Mining candidate prepared', target:i%3?'ergo_p2p':'ergo_mining', fields:i%3 ? {peer:`192.0.2.${i+20}:9030`} : {height:1865700+i,transactions:i+1}})),
];
let status = {peer_count:14,sync_state:'at_tip', best_full_block_height:1865721,best_header_height:1865721,snapshot_age_ms:30,last_block_apply_error:{height:1865712,block_id:'ab'.repeat(32),reason:'Fixture validation rejection',age_ms:600000}};
let indexer = {status:'halted',indexedHeight:1865720,fullHeight:1865721,haltReason:'Fixture index read failed'};
const server = http.createServer(async (req,res)=>{
  const u = new URL(req.url,'http://127.0.0.1');
  function json(data,code=200){res.writeHead(code,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(data));}
  if(req.method!=='GET') return json({reason:'writes-disabled'},405);
  if(u.pathname==='/api/v1/diagnostics/activity'){
    requests++;
    const snapshot = records.slice(), oldSession=session, requestedKey=req.headers.api_key;
    if(delay) await new Promise(r=>setTimeout(r,delay));
    if(badKey||requestedKey!=='fixture-key') return json({reason:'invalid.api-key'},403);
    if(fail) return json({reason:'fixture-unavailable'},fail);
    const reset = u.searchParams.has('session') && u.searchParams.get('session')!==oldSession;
    const since = reset ? 0n : BigInt(u.searchParams.get('since')||'0');
    const after = snapshot.filter(r=>BigInt(r.seq)>since); const result=after.slice(0,256);
    return json({sessionId:oldSession,oldestSeq:snapshot[0]?.seq||'0',latestSeq:snapshot.at(-1)?.seq||'0',nextSeq:result.at(-1)?.seq||String(since),reset,gap:false,hasMore:after.length>256,capacity:2048,byteCapacity:4194304,retained:snapshot.length,droppedTotal:'0',records:result});
  }
  if(u.pathname==='/api/v1/status') return json(status);
  if(u.pathname==='/api/v1/info') return json({network:'mainnet',version:'0.9.0',started_at_unix_ms:now-500000,target_block_interval_ms:120000});
  if(u.pathname==='/api/v1/indexer/status') return indexer ? json(indexer) : json({},503);
  if(u.pathname==='/wallet/status') return req.headers.api_key==='fixture-key'?json({isInitialized:false,isUnlocked:false}):json({reason:'invalid.api-key'},403);
  if(u.pathname.startsWith('/api/')||u.pathname.startsWith('/wallet/')) return json({},404);
  const file=path.resolve(root,u.pathname==='/'?'index.html':'.'+u.pathname);
  if(!file.startsWith(root+path.sep)||!fs.existsSync(file))return json({},404);
  res.writeHead(200,{'content-type':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.html')?'text/html':'font/woff2'}); fs.createReadStream(file).pipe(res);
});
(async()=>{
  await new Promise(r=>server.listen(0,'127.0.0.1',r)); const origin=`http://127.0.0.1:${server.address().port}`;
  const browser=await chromium.launch({headless:true,...(process.env.BROWSER_CHANNEL ? {channel:process.env.BROWSER_CHANNEL} : {})}); const context=await browser.newContext({viewport:{width:1440,height:1050},acceptDownloads:true});
  await context.route('**/*',route=>route.request().url().startsWith(origin)?route.continue():route.abort());
  const page=await context.newPage(); const errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.addInitScript(()=>sessionStorage.setItem('ergo.apikey','fixture-key'));
  const checks=[]; const check=(name)=>{checks.push(name);process.stdout.write(`PASS ${name}\n`);};
  await page.goto(origin+'/#activity'); await page.locator('[data-live]').filter({hasText:'Live history'}).waitFor();
  assert.equal(await page.locator('.activity-row').count(),4); assert.match(await page.locator('[data-current]').innerText(),/Search indexing is halted/); check('route, current conditions and highlights by default');
  await page.screenshot({path:path.join(output,'activity-desktop.png'),fullPage:true});
  await page.locator('input[name=query]').fill('timed out'); assert.equal(await page.locator('.activity-row').count(),1);assert.equal(await page.locator('.activity-occurrences').innerText(),'×12');check('repeat count and search');
  await page.locator('.activity-row summary').focus();await page.keyboard.press('Enter'); await page.locator('.activity-row[open] .activity-raw').waitFor();
  await page.locator('select[name=minutes]').selectOption('15');
  assert.equal(await page.locator('[data-pause]').getAttribute('aria-pressed'),'true'); const oldText=await page.locator('[data-list]').innerText();
  records.push(makeRecord(70,{level:'WARN',target:'ergo_p2p::delivery',message:'Peer request timed out; retry scheduled',fields:{code:'peer_timeout',peer:'192.0.2.14:9030',latency_ms:8000,attempt:13}}));
  await page.evaluate(()=>import('/js/activity.js').then(m=>m.onSlow()));
  assert.equal(await page.locator('[data-list]').innerText(),oldText); assert.match(await page.locator('[data-pending]').innerText(),/1 new records/);check('keyboard inspection freezes rows while retaining new arrivals');
  await page.evaluate(()=>{window.originalNow=Date.now;const later=Date.now()+3600000;Date.now=()=>later;});await page.evaluate(()=>import('/js/activity.js').then(m=>m.onSlow()));assert.equal(await page.locator('[data-list]').innerText(),oldText);await page.evaluate(()=>{Date.now=window.originalNow;});check('paused time-window filters do not expire inspected records');
  await page.locator('.activity-row summary').click();
  const download=page.waitForEvent('download');await page.locator('.activity-evidence button').filter({hasText:'Download group'}).click(); const d=await download; const contents=fs.readFileSync(await d.path(),'utf8').trim().split('\n').map(JSON.parse); assert.equal(contents[0].recordCount,12);assert.equal(contents.length,13);check('download contains every occurrence and metadata');
  await page.locator('[data-pause]').click(); await page.locator('[data-reset]').click();
  records.push(makeRecord(71,{level:'WARN',message:'<img src=x onerror="window.pwned=true">',fields:{peer:'<script>bad</script>'}}));await page.evaluate(()=>import('/js/activity.js').then(m=>m.onSlow()));
  await page.locator('input[name=query]').fill('<img'); assert.equal(await page.locator('.activity-row').count(),1);assert.equal(await page.locator('.activity-row img').count(),0);assert.equal(await page.evaluate(()=>window.pwned),undefined);check('untrusted message remains inert text');
  await page.locator('[data-reset]').click(); await page.locator('select[name=level]').selectOption('ERROR');assert.equal(await page.locator('.activity-row').count(),1);assert.match(await page.locator('[data-current]').innerText(),/Search indexing is halted/);check('filters do not hide current faults');
  await page.locator('[data-reset]').click();await page.locator('select[name=level]').selectOption('');assert.equal(await page.locator('.activity-row').count(),25);await page.locator('[data-next]').click();assert.equal(await page.locator('[data-pause]').getAttribute('aria-pressed'),'true');assert.match(await page.locator('[data-page]').innerText(),/Page 2/);check('history navigation holds its position');
  await page.locator('[data-pause]').click();fail=503;await page.evaluate(()=>import('/js/activity.js').then(m=>m.onSlow()));assert.match(await page.locator('[data-error]').innerText(),/unavailable/);assert.ok(await page.locator('.activity-row').count()>0);check('transport failures retain evidence without claiming live data');fail=0;
  await page.evaluate(()=>import('/js/activity.js').then(m=>m.onFast({reachable:false,status:null})));assert.match(await page.locator('[data-health-freshness]').innerText(),/unconfirmed/);assert.equal(await page.locator('[data-current]').getByText('Recovered',{exact:true}).count(),0);check('disconnected status never implies fresh recovery');
  const savedIndex=indexer;indexer=null;await page.evaluate(()=>import('/js/activity.js').then(m=>m.onSlow()));assert.match(await page.locator('[data-current]').innerText(),/Search indexing is halted/);assert.equal(await page.locator('[data-issue=index] .activity-badge').innerText(),'Last reported');indexer=savedIndex;check('index read failure preserves the prior fault as unconfirmed');
  await page.evaluate(s=>import('/js/activity.js').then(m=>m.onFast({reachable:true,status:s})),status);
  await page.locator('[data-pause]').click();session='restarted';records=[makeRecord(1,{message:'New process started'})];await page.evaluate(()=>import('/js/activity.js').then(m=>m.onSlow()));assert.match(await page.locator('[data-list]').innerText(),/New process started/);assert.doesNotMatch(await page.locator('[data-list]').innerText(),/timed out/);assert.match(await page.locator('[data-retention]').innerText(),/session changed/);check('restart clears paused evidence and announces new session');
  delay=250; const inFlight=page.evaluate(()=>import('/js/activity.js').then(m=>m.onSlow()));await page.waitForTimeout(50);await page.evaluate(()=>import('/js/auth.js').then(m=>m.setApiKey('')));await inFlight;assert.equal(await page.locator('.activity-row').count(),0);assert.equal(await page.locator('[data-export]').isDisabled(),true);check('clearing authorization scrubs evidence and rejects late responses');delay=0;
  await page.evaluate(()=>import('/js/auth.js').then(m=>m.setApiKey('fixture-key')));await page.evaluate(()=>import('/js/activity.js').then(m=>m.onSlow()));assert.equal(await page.locator('.activity-row').count(),1);check('reauthorization reloads evidence');
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(output,'activity-mobile.png'),fullPage:true});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);check('390px layout has no horizontal overflow');
  await page.evaluate(()=>{document.documentElement.className='theme-light';});await page.screenshot({path:path.join(output,'activity-light.png'),fullPage:true});check('light-theme render');
  assert.deepEqual(errors,[]);check('no browser runtime errors');
  console.log(JSON.stringify({passed:checks.length,requests,checks}));await browser.close();server.close();
})().catch(e=>{console.error(e);server.close();process.exit(1);});
