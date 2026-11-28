// Additive declarations mirror the canonical agent SQL. Lazy ensure on feature use.
export const BOUNDED_MEMORY_SCHEMA = `CREATE TABLE IF NOT EXISTS memory_operation_owners (agent TEXT NOT NULL PRIMARY KEY, required INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS memory_operation_escrow (
 operation TEXT NOT NULL PRIMARY KEY, policy_pin TEXT NOT NULL, expires INTEGER NOT NULL,
 phase TEXT NOT NULL, stopped INTEGER NOT NULL DEFAULT 0,
 forward_calls INTEGER NOT NULL, forward_mass INTEGER NOT NULL, forward_money INTEGER NOT NULL,
 recovery_calls INTEGER NOT NULL, recovery_mass INTEGER NOT NULL, recovery_money INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS memory_operation_debits (
 operation TEXT NOT NULL, root TEXT NOT NULL, phase TEXT NOT NULL,
 calls INTEGER NOT NULL, mass INTEGER NOT NULL, money INTEGER NOT NULL,
 PRIMARY KEY(operation, root)
) STRICT;`;
