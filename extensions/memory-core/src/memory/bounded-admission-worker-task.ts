import type { BoundedMemoryPolicy } from "./bounded-admission.js";
export type BoundedAllocation = { calls: number; mass: number; money: number };
export type BoundedWorkerBinding = { agentId: string };
export type BoundedWorkerOperations = {
  initialize: {
    input: {
      policy: BoundedMemoryPolicy;
      allocation: Record<"forward" | "recovery", BoundedAllocation>;
    };
    output: unknown;
  };
  debit: {
    input: {
      operation: string;
      phase: "forward" | "recovery";
      root: string;
      need: BoundedAllocation;
    };
    output: unknown;
  };
  stop: { input: { operation: string }; output: unknown };
  recovery: { input: { operation: string }; output: unknown };
  resume: { input: { operation: string }; output: unknown };
  receipt: { input: { operation: string }; output: unknown };
  required: { input: { agentId: string }; output: boolean };
};
