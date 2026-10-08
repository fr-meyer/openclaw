// Fixed source-owned requirements; descriptive data, never a permission issuer.
import {canonical,sha} from './native-memory-codec.mjs';
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
export const LOGICAL_ASSURANCE=freeze({
 contract:'workboard.logical-recovery-assurance.v1',
 source:{opaqueOriginalOwnerRequired:true,captureRegistryEpochRequired:true,coherentReadTransactionRequired:true,readCutoff:'first-read-in-source-transaction',postCutoffCommitsIncluded:false,reopenByPathAllowed:false,deployedStoreSelectionProven:false,deployedStoreSelectionRequiredBeforeProduction:true,kernelMainWalShmBackingProven:false,kernelMainWalShmBackingRequired:false},
 preservation:{exactSchemaRequired:true,tableCount:17,rawValuesRequired:true,textEncoding:'UTF-8',lossyTextAllowed:false,claimsAndLeasesRequired:true,attachmentReferencesAndBytesRequired:true},
 destination:{sealedWorkerRequired:true,descriptorCustodyRequired:true,overwriteExistingAllowed:false},
 restore:{acceptedOriginalCaptureRequired:true,sourceProfileBindingRequired:true,inertQuarantineRequired:true,runtimeStartAllowed:false,claimsRearmed:false,notificationsDelivered:false,overwriteLiveSourceAllowed:false},
});
export const LOGICAL_ASSURANCE_SHA256=sha(canonical(LOGICAL_ASSURANCE));
export function assertLogicalAssurance(value){
 if(canonical(value)!==canonical(LOGICAL_ASSURANCE)){const error=new Error('LOGICAL_ASSURANCE_REQUIRED');error.code='LOGICAL_ASSURANCE_REQUIRED';throw error;}
 return LOGICAL_ASSURANCE;
}
export function assertCaptureInterval(value){
 if(!value||Object.keys(value).sort().join(',')!=='completedAtMs,cutoff,elapsedMs,exactCommitTimestampProven,startedAtMs'||
  !Number.isSafeInteger(value.startedAtMs)||!Number.isSafeInteger(value.completedAtMs)||!Number.isSafeInteger(value.elapsedMs)||
  value.startedAtMs<0||value.completedAtMs<value.startedAtMs||value.elapsedMs<0||value.cutoff!==LOGICAL_ASSURANCE.source.readCutoff||value.exactCommitTimestampProven!==false){
  const error=new Error('CAPTURE_INTERVAL_INVALID');error.code='CAPTURE_INTERVAL_INVALID';throw error;
 }
 return Object.freeze({...value});
}
