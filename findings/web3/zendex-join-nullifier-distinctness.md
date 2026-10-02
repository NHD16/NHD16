# [CRITICAL] Join circuit omits nullifier distinctness, allowing one note to fund both sides of a join

```text
id         : W3-007
protocol   : Zendex
platform   : HackenProof
severity   : critical
class      : ZK circuit under-constraint / double spend
status     : confirmed by HackenProof triage
bounty     : $17.24
affected   : circuits/join/src/main.nr, contracts/ZendexVaultManager.sol#join
```

## Summary

`join()` merges two private notes into one. Neither the Noir circuit nor the on-chain manager checks that the two input notes are actually *different*. An attacker supplies the same note as both inputs, and the circuit's `amount_a + amount_b == amount_c` constraint mints a note worth double the input while only one nullifier is burned. Repeating the operation doubles the balance each round, and the inflated note is then withdrawn from the shared `ZendexVault`, which backs every user's funds across all three managers.

Any EOA with a single genuine deposit can drain the vault. No privileged role, no capital beyond one note.

## Root cause

`circuits/join/src/main.nr` verifies both input notes independently:

```rust
assert(amount_a as u64 as Field == amount_a);
assert(amount_b as u64 as Field == amount_b);
assert(amount_c as u64 as Field == amount_c);
assert(amount_a + amount_b == amount_c);

verify_nullifier(nullifier_a, rho_a, pk_x, pk_y);
verify_nullifier(nullifier_b, rho_b, pk_x, pk_y);

verify_commitment(commitment_a, asset_id, amount_a, rho_a, pk_x, pk_y);
verify_commitment(commitment_b, asset_id, amount_b, rho_b, pk_x, pk_y);
verify_commitment(commitment_c, asset_id, amount_c, rho_c, pk_x, pk_y);

verify_tag(tag_a, epoch_id_a, commitment_a, salt_a);
verify_tag(tag_b, epoch_id_b, commitment_b, salt_b);
```

There is no `assert(rho_a != rho_b)`, no `assert(commitment_a != commitment_b)`, and no `assert(nullifier_a != nullifier_b)`. Every constraint above is satisfied when side A and side B are literally the same note.

`ZendexVaultManager.join` repeats the same omission on-chain:

```solidity
_validateNullifier(jp.nullifierA);
_validateNullifier(jp.nullifierB);
...
_consume(jp.nullifierA);
_consume(jp.nullifierB);
_insert(jp.commitmentC);
```

`_validateNullifier` only asserts the nullifier is currently unused. When `nullifierA == nullifierB`, both checks pass because the shared nullifier has not been consumed yet at the time either check runs. `_consume` is `nullifierUsed[nullifier] = true` — writing it twice is idempotent, so one note is burned while a note of double the value is inserted.

The `tag` glue does not help. `tag = Poseidon3(epoch_id, commitment, salt)` with a freely chosen `salt`, so the same commitment at the same epoch produces unlimited distinct tags. Two inclusion proofs for the same leaf with different salts yield `tag_a != tag_b`, satisfying `_validateTags` on both sides.

## Attack path

1. Attacker deposits `X` of any supported asset, creating note `A` with secret `rho_A`.
2. Attacker generates two inclusion proofs for note `A` using two different salts, producing `tag_a != tag_b`.
3. Attacker generates a join proof with `rho_a = rho_b = rho_A`, `amount_a = amount_b = X`, `commitment_a = commitment_b = commitment_A`, and `amount_c = 2X`. The circuit accepts.
4. Attacker calls `join(inclusionA, inclusionB, joinData)`. Both nullifier checks pass; a note worth `2X` is inserted.
5. Repeat from step 2 using the new note. Each round doubles the balance, bounded only by the circuit's `u64` range check (~1.8e19 wei).
6. Attacker calls `withdraw()` on the final note and receives the inflated amount from `ZendexVault`.

## Impact

Unlimited value creation from a single deposit: every self-join doubles the note, and the inflated note is redeemed against the shared `ZendexVault`, so the attacker walks away with other depositors' funds.

## Proof of concept

Runnable Hardhat test (`test/PoC.JoinSelfDoubleSpend.test.ts`), generating real Noir proofs against the deployed `JoinVerifier`, `InclusionVerifier`, `DepositVerifier` and `WithdrawVerifier`:

```bash
npx hardhat test test/PoC.JoinSelfDoubleSpend.test.ts
```

Observed output:

```text
PoC: join() accepts the same note twice -> unlimited value creation
  [1] attacker deposited: 1.0 ZEN
  [*] building inclusion proofs...
  [*] join proof generated (circuit accepted identical A and B)
  [2] join(noteA, noteA) accepted -> note worth 2.0 ZEN
  [3] withdrawn: 2.0 ZEN
  [4] net profit: 1.0 ZEN (stolen from other depositors)
  ✔ doubles a note by joining it with ITSELF, then withdraws other users' funds

  start: deposited 1.0 ZEN
  round 1: note now worth 2.0 ZEN
  round 2: note now worth 4.0 ZEN
  round 3: note now worth 8.0 ZEN
  withdrew 8.0 ZEN from a 1.0 ZEN deposit (8x)
  ✔ compounds: repeated self-joins multiply one deposit 8x, drained from the vault
```

The second test compounds three rounds for an 8x multiplier and asserts `withdrawn == principal * 8`. The vault is pre-funded with other depositors' ZEN, which is what the attacker walks away with.

## Fix

Enforce distinctness in the circuit, which is the authoritative constraint, and add a cheap on-chain check as defence in depth.

```diff
  // circuits/join/src/main.nr — inside main(), before the amount assertions
+ // The two inputs must be distinct notes, otherwise one note funds both sides.
+ assert(rho_a != rho_b);
+ assert(commitment_a != commitment_b);
+ assert(nullifier_a != nullifier_b);
```

```diff
  // contracts/ZendexVaultManager.sol — join()
  _validateNullifier(jp.nullifierA);
  _validateNullifier(jp.nullifierB);
+ require(jp.nullifierA != jp.nullifierB, BaseManager__NullifierConsumed());
```

Separately, consider making `_consume` revert on an already-consumed nullifier rather than silently rewriting the slot. That would have failed closed here and will catch the same class of bug in any future multi-input circuit.
