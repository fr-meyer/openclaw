// No auto-run, CLI, provider or authority issuer. The original native owner
// launcher must separately admit the matching source closure/resource window.
import assert from 'node:assert/strict';
import {readFileSync,realpathSync,existsSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {relative,isAbsolute,join} from 'node:path';
import {pathToFileURL} from 'node:url';

const PIN='c074824a27c96d3983043f9eeb33823cd1772d8c';
const CANDIDATE=Object.freeze({
 writer:'31830b33d36b19f691bcfa2dd3a2f2c01c73236ef26c500a0a2fafadd054c379',
 writerKernel:'d52d2a9eac82a5e8d63be366c8dbebd3a37dba3b7ba28ccfb87c3cc7cbaad258',
 writerTypes:'34f084fd722d5dda76229efd3c96a1f864a7bc0b5694b2be0629930d70e02c24',
});
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const within=(root,file)=>{const rel=relative(root,file);return rel===''||(!rel.startsWith('..')&&!isAbsolute(rel))};
const event=(id,action)=>({sourceId:id+':'+action,sourceSequence:action.endsWith('started')?1:2,
 occurredAt:Date.now(),kind:'agent_run',action,status:action.endsWith('started')?'started':'succeeded',
 actorType:'agent',actorId:'synthetic-reviewer',agentId:'synthetic-reviewer',sessionKey:'synthetic-native-audit-session',runId:id});

export async function runOriginalNativeAuditReceiptFixture(admitted) {
 assert.equal(admitted.status,'SOURCE_FIXTURE_EXECUTION_ADMITTED');
 assert.equal(admitted.nativeCommit,PIN);
 for(const field of ['completeRuntimeClosureVerified','moduleSourceArtifactJoinVerified',
  'allPackageExportBindingsVerified','sameRuntimeManifestVerified','isolatedEnvironmentAndWritesVerified',
  'resourceAdmissionFresh','fixtureEnvironmentHasNoCredentials'])assert.equal(admitted[field],true,field);
 for(const field of ['dispatchAllowed','providerCallsAllowed','workerFaultsAllowed'])assert.equal(admitted[field],false,field);
 const sourceRoot=realpathSync(admitted.runtimeRoot),fixtureRoot=realpathSync(admitted.fixtureRoot);
 assert.notEqual(sourceRoot,fixtureRoot);const modules={},pinnedModules={};
 const env=Object.freeze({...admitted.fixtureEnvironment});
 assert.equal(realpathSync(env.OPENCLAW_STATE_DIR),fixtureRoot);
 assert(within(fixtureRoot,env.OPENCLAW_CONFIG_PATH));
 const names=['writer','writerKernel','writerTypes','scheduler','context','database','cache','owner','store','paths','readKernel'];
 // The owner issues a coherent closure manifest before any native module import.
 // Physical path/byte checks cannot replace that preadmission/loaded custody.
 for(const name of names) {
  const item=admitted.modules[name];assert.equal(item.nativeCommit,PIN);
  const file=realpathSync(item.physicalPath);assert(within(sourceRoot,file));
  assert.equal(hash(readFileSync(file)),item.loadedSha256,name);
  pinnedModules[name]=Object.freeze({physicalPath:file,loadedSha256:item.loadedSha256});
 }
 assert.equal(admitted.requiredCandidateManifestVerified,true);
 for(const name of Object.keys(CANDIDATE))assert.equal(pinnedModules[name].loadedSha256,CANDIDATE[name]);
 Object.freeze(pinnedModules);
 // Caller DTO mutation during one import cannot select a different successor.
 for(const name of names.filter(name=>name!=='writerTypes'))modules[name]=await import(pathToFileURL(pinnedModules[name].physicalPath).href);
 const databasePath=modules.paths.resolveOpenClawStateSqlitePath(env);
 assert(within(fixtureRoot,databasePath));
 assert.equal(modules.paths.resolveOpenClawStateSqlitePath(process.env),databasePath);
 assert.equal(existsSync(databasePath),false);
 const scheduler=new modules.scheduler.GatewayScheduler();
 let database,writer,primaryFailure,result;
 let writerClosed=false,schedulerClosed=false,databaseClosed=false;
 const errors=[],checks=[];
 try {
  database=modules.database.openOpenClawStateDatabase({path:databasePath,env,initializationAgentPaths:[]});
  const context=modules.context.captureOpenClawStateWorkerContext({path:databasePath,env,initializationAgentPaths:[]});
  context.admission.assertCurrent();
  const nativeStore=await modules.owner.getOpenClawStateWorkerOwner().open(context,{assertCurrent:()=>context.admission.assertCurrent()});
  context.admission.assertCurrent();const actor=modules.store.getSqliteWorkerActorIdentity(nativeStore);
  assert.equal(actor.databasePath,databasePath);
  writer=modules.writer.createAuditEventWriter({scheduler,stateDir:fixtureRoot,onError:e=>errors.push(e)});
  await writer.ready;context.admission.assertCurrent();assert.deepEqual(errors,[]);
  const id={runId:'synthetic-native-original-receipt',lifecycleGeneration:'synthetic-original-generation'};
  const guard=writer.protectRunTerminal(id,{forbidToolActions:true,requireOriginalEventReceipt:true});
  assert(writer.recordRunEvent(id,event(id.runId,'agent.run.started')));await writer.flush();assert.throws(()=>guard.assertCommitted());
  assert(writer.recordRunEvent(id,event(id.runId,'agent.run.finished')));const flushed=await writer.flush();guard.assertCommitted();guard.assertNoToolActionsObserved();
  const page=modules.readKernel.listAuditEventsInDatabase(database.db,{now:Date.now(),limit:20,filters:{runId:id.runId}});
  assert.equal(page.events.length,2);assert.equal(page.events[0].action,'agent.run.finished');assert.equal(page.events[1].action,'agent.run.started');
  checks.push('original native actor transports matching protected start/terminal acknowledgements');
  const sameStore=await modules.owner.getOpenClawStateWorkerOwner().open(context,{assertCurrent:()=>context.admission.assertCurrent()});
  assert.equal(modules.store.getSqliteWorkerActorIdentity(sameStore),actor);checks.push('original native actor identity remains exact through FIFO/query awaits');
  const ordinaryId={runId:'synthetic-native-ordinary',lifecycleGeneration:id.lifecycleGeneration};
  const ordinary=writer.protectRunTerminal(ordinaryId);assert(writer.recordRunEvent(ordinaryId,event(ordinaryId.runId,'agent.run.finished')));
  await writer.flush();ordinary.assertCommitted();writer.observeRunToolAction(id.runId);
  assert.throws(()=>guard.assertCommitted());ordinary.assertCommitted();assert((await writer.flush()).integrity);
  checks.push('strict tool rejection preserves original ordinary custody');
  // Actual native deduplication: original diagnostic insertion already exists.
  const dedupId={runId:'synthetic-native-dedup',lifecycleGeneration:id.lifecycleGeneration};
  const dedupEvent=event(dedupId.runId,'agent.run.finished');assert(writer.record(dedupEvent));await writer.flush();
  const dedup=writer.protectRunTerminal(dedupId,{requireOriginalEventReceipt:true});assert(writer.recordRunEvent(dedupId,dedupEvent));
  assert((await writer.flush()).integrity);assert.throws(()=>dedup.assertCommitted());ordinary.assertCommitted();assert.deepEqual(errors,[]);
  checks.push('actual native deduplication has no witness and preserves unrelated ordinary guard');
  for(const field of ['snapshotComplete','snapshotId','totalCount','limitApplied','truncated','hasMore'])assert.equal(page[field],undefined);
  checks.push('exhausted native diagnostic page does not become complete audit authority');
  await writer.stop();writerClosed=true;assert.throws(()=>ordinary.assertCommitted());
  scheduler.beginClose();await scheduler.stop();schedulerClosed=true;
  await modules.cache.closeOpenClawStateDatabaseByPathAsync(databasePath);databaseClosed=true;assert.equal(database.db.isOpen,false);
  result={status:'ACTUAL_NATIVE_RECEIPT_CONSUMER_COMPONENT_ONLY',nativeCommit:PIN,checks,
   originalActorKey:actor.key,flushedSequence:flushed.committedSequence,
   privateLeaseOrIssuerQualified:false,completeAuditAuthority:false,providerAcknowledgementQualified:false,
   matchingBuildQualified:false,dispatch:false,providerCalls:0,productionChanged:false};
 } catch(error) {primaryFailure=error;throw error;}
 finally {
  const failures=[];
  if(writer&&!writerClosed)try{await writer.stop()}catch(e){failures.push(e)}
  if(!schedulerClosed)try{scheduler.beginClose();await scheduler.stop()}catch(e){failures.push(e)}
  if(database&&!databaseClosed)try{await modules.cache.closeOpenClawStateDatabaseByPathAsync(databasePath)}catch(e){failures.push(e)}
  if(failures.length)throw new AggregateError(primaryFailure?[primaryFailure,...failures]:failures,'Native fixture/drain unresolved; preserve all temporary evidence and HOLD');
 }
 assert.deepEqual(errors,[],'Native audit stop/cleanup reported integrity failure');
 // Publish only after successful native operation and owned cleanup settlement.
 writeFileSync(join(fixtureRoot,'native-original-receipt-result.json'),JSON.stringify(result,null,2)+'\n');return result;
}
