const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const source=fs.readFileSync(require('node:path').join(__dirname,'../ergo-api/web/js/voting.js'),'utf8').replace(/^import .*;\r?\n/gm,'').replace(/^export /gm,'');
const context=vm.createContext({api:{votes:async()=>context.response},num:String});
vm.runInContext(source+`
let testInputs=[];
root={querySelector:()=>({textContent:''}),querySelectorAll:()=>testInputs};
refreshSummary=()=>{};refreshCells=()=>{};historyLoaded=true;
buildRows=(params,cfg)=>{testInputs=unionRows(params,cfg).map(r=>({dataset:{id:String(r.id)},value:''}));builtKey=rowsKey(params,cfg);};
`,context);
// The browser DOM is stubbed above only for poll/draft lifecycle checks.
// These assertions run the production policy formatter without stubs.
const policy = (p, raw) => { context.p=p; context.raw=raw; return vm.runInContext('desiredPolicy(p,raw)',context); };
const fixed={id:2,current:360,step:10,min:0,max:10000};
assert.match(policy(fixed,'400').text,/increase.*370/);
assert.match(policy(fixed,'350').text,/decrease.*350/);
assert.match(policy(fixed,'360').text,/no vote.*equals/);
assert.match(policy(fixed,'').text,/removes this target/);
assert.match(policy(fixed,'365').text,/alternate/);
assert.equal(policy(fixed,'-1').tone,'warn');
assert.equal(policy(fixed,'1.5').tone,'warn');
assert.match(policy({...fixed,id:3},'400').text,/Step size changes/);
assert.match(policy(null,'400').text,/not currently votable/);
const params=[{id:1,name:'one',current:10,min:0,max:100,step:1},{id:2,name:'two',current:10,min:0,max:100,step:1}];
(async()=>{
context.response={votableParameters:params,configuredVotes:[{parameterId:1,target:20},{parameterId:2,target:30}]};
await vm.runInContext('load()',context);
vm.runInContext("testInputs[0].value='40'",context);
context.response={votableParameters:params.map(p=>({...p,step:2})),configuredVotes:[{parameterId:1,target:20},{parameterId:2,target:50}]};
await vm.runInContext('load()',context);
assert.equal(vm.runInContext('testInputs[0].value',context),'40','dirty draft survives metadata rebuild');
assert.equal(vm.runInContext('testInputs[1].value',context),'50','untouched target follows external saved changes');
vm.runInContext("testInputs[0].value=''",context);
await vm.runInContext('load()',context);
assert.equal(vm.runInContext('testInputs[0].value',context),'','blank draft survives refresh');
assert.equal(vm.runInContext("unionRows([], [{parameterId:9,name:'future',target:1}])[0].id",context),9,'inactive configured targets retained');
console.log('Passed: draft preservation across metadata changes, untouched target refresh, blank drafts, inactive configured targets.');
})().catch(e=>{console.error(e);process.exitCode=1});
