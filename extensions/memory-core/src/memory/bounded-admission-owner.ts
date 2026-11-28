import {
  boundedMemoryAdmissionActive,
  requireBoundedMemoryAdmission,
  installBoundedMemoryAdmission,
  validateBoundedMemoryPolicy,
  type BoundedMemoryPolicy,
  type BoundedMemoryEscrow,
} from "./bounded-admission.js";
// The runtime owner must join every manager purpose, including transient CLI
// handles not retained in the default manager cache. No synthetic drain receipt.
export async function beginBoundedMemoryAdmission(
  policy: BoundedMemoryPolicy,
  escrow: BoundedMemoryEscrow,
  retireNative: () => Promise<void>,
  phase: "forward" | "recovery" = "forward",
) {
  validateBoundedMemoryPolicy(policy);
  if (!boundedMemoryAdmissionActive(policy.agent)) {
    requireBoundedMemoryAdmission(policy.agent);
  }
  await retireNative();
  return installBoundedMemoryAdmission(policy, escrow, phase);
}
