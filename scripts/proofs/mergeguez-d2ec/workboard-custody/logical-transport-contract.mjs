// Host transport contract only. No SQLite imports, semantic inspector or authority issuer.
import crypto from 'node:crypto';
export const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
export const canonical = value => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
export const schemaDdlSha256 = 'ddf7208a4e79d53b4cde461de6c6ce32d322537069cefd5c603f835e13f2bc25';
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
export const LOGICAL_ASSURANCE=freeze({
 contract:'workboard.logical-recovery-assurance.v1',
 source:{opaqueOriginalOwnerRequired:true,captureRegistryEpochRequired:true,coherentReadTransactionRequired:true,readCutoff:'first-read-in-source-transaction',postCutoffCommitsIncluded:false,reopenByPathAllowed:false,deployedStoreSelectionProven:false,deployedStoreSelectionRequiredBeforeProduction:true,kernelMainWalShmBackingProven:false,kernelMainWalShmBackingRequired:false},
 preservation:{exactSchemaRequired:true,tableCount:17,rawValuesRequired:true,textEncoding:'UTF-8',lossyTextAllowed:false,claimsAndLeasesRequired:true,attachmentReferencesAndBytesRequired:true},
 destination:{sealedWorkerRequired:true,descriptorCustodyRequired:true,overwriteExistingAllowed:false},
 restore:{acceptedOriginalCaptureRequired:true,sourceProfileBindingRequired:true,inertQuarantineRequired:true,runtimeStartAllowed:false,claimsRearmed:false,notificationsDelivered:false,overwriteLiveSourceAllowed:false},
});
export const LOGICAL_ASSURANCE_SHA256='536844e6da186aa8c6e5c23506ed1727f56c7f0f56e4d7149abc4f4d9c9d6387';
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
