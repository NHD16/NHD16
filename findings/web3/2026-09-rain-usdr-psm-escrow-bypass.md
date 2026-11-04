# [HIGH] Collateral deposited for one transaction unlocks the whole PSM reserve, including the escrow held back for losses

```text
id         : W3-008
protocol   : Rain — USDR
platform   : HackenProof (RAIN-USDR Smart Contract Audit Contest, Sept 2026)
severity   : high
class      : Solvency accounting / flash collateral
status     : confirmed by HackenProof triage (High)
report id  : RAINUSDR-1899
commit     : hackenproof-public/rain-usdr-contracts@bd6e03abe34936b7dbece2509b90457bd5c9b119
date       : 2026-09-29
```

## Summary

The PSM reserve (USDT/USDC) is protected by two mechanisms, and both depend on
`SolvencyEngine.worstCaseLoss()`:

- **Escrow**: part of the reserve equal to the estimated loss is set aside as `committedEscrow`.
  `buyStable` can only pay out of `freeSlack = totalReserve - committedEscrow`. This applies at all
  times, including normal operation.
- **Breach gate**: if the estimated loss exceeds `reserveFactor × totalReserve`, the protocol is
  breached and `buyStable` is blocked.

Anyone can push the estimated loss down to whatever value they need for exactly one transaction:
deposit RAIN into a fresh vault without borrowing, call `buyStable`, then withdraw the RAIN again. The
loss estimate counts the debt-free collateral as if it backed everyone else's debt, the deposit skips
the solvency check, and the withdrawal is checked against the state *before* the collateral leaves.

Result: one public transaction, with no price move, drains the whole reserve **including the escrow**.
During a breach, the same transaction bypasses the redemption block. The RAIN can come from a flash
swap and is returned in full.

## Root cause

**1. The loss estimate counts collateral that backs no debt.**
`contracts/reserve/SolvencyEngine.sol:256-277`

```solidity
(uint256 globalArt, uint256 globalInk, uint256 rate, , , , , ) = VAULT_ENGINE.ilks(ilkId);
uint256 ilkDebt = (globalArt * rate) / _RAY;                                       // :256
collateralValue = (globalInk * uint256(val)) / _WAD;                                // :267
uint256 recoverable = (((collateralValue * stressMarkdown) / _WAD) * stressDepth) / _WAD; // :272
if (ilkDebt > recoverable) loss += ilkDebt - recoverable;                           // :274-276
```

`globalInk` sums the collateral of *every* vault of the ilk, including vaults with `art == 0`. A
debt-free vault can never be liquidated and its owner can withdraw it at any time. Even so, it lowers
the loss exactly as much as collateral that backs real debt.

**2. The loss directly sets how much of the reserve can be withdrawn.**
`contracts/reserve/SolvencyEngine.sol:221-224`, `contracts/reserve/PegStabilityModule.sol:216-234`

```solidity
breached = loss > (reserve * reserveFactor) / _WAD;
RESERVE_ACCOUNTING.updateCommittedEscrow(loss > reserve ? reserve : loss);
```

```solidity
ISolvencyEngine(solvencyEngine).checkInvariant();
if (ISolvencyEngine(solvencyEngine).isBreached()) _revert(SolvencyGateActive.selector);
...
if (stableAmt18 > RESERVE_ACCOUNTING.freeSlack()) _revert(InsufficientFreeSlack.selector);
```

**3. Adding collateral skips the check.** `contracts/core/VaultEngine.sol:463-473`

```solidity
if ((dart > 0 || dink < 0) && solvencyEngine != address(0) && ISolvencyEngine(solvencyEngine).isVolatile(ilkId)) {
    ISolvencyEngine(solvencyEngine).checkInvariant();
    if (ISolvencyEngine(solvencyEngine).isBreached()) {
        _revert(SolvencyGateActive.selector);
    }
}
urn.ink = Math.add(urn.ink, dink); // :473 — applied only AFTER the check
```

The code assumes that "collateral top-ups (dink > 0) always remain available because they reduce
risk" (`:459-460`). For a vault with no debt, a deposit reduces no risk, but it still lowers the loss
estimate.

**4. The check runs on the pre-change state.** When collateral is removed, `checkInvariant()` runs
before `urn.ink` and `globalInk` are reduced. It still counts the collateral that is about to leave
and lets the withdrawal through, even though that withdrawal puts the protocol straight back into
breach.

## Attack path

Launch configuration from `tests/shared/BaseTest.sol`: `mat` 400%, stress 0.5 × 0.35 (recoverable =
17.5% of collateral value), `reserveFactor` 0.9. The oracle price is correct at every step.

**Scenario A: normal operation, whole reserve including escrow**

Setup: the LP deposits 100 USDT into the PSM. Bob deposits 800 RAIN and borrows 200 USDR at RAIN = $1.
Loss = 200 − 800 × 0.175 = **60** < 90, so the protocol is not breached. `committedEscrow` = 60 and
`freeSlack` = 40, so `buyStable(100 USDT)` reverts as intended.

In one transaction:

1. `collateralAdapter.join(RAIN, attacker, 400e18)`, `vaultEngine.open`,
   `vaultEngine.frob(w, attacker, attacker, +400e18, 0)`. No check runs.
2. `psm.buyStable(USDT, attacker, 100e6)`. Loss = 200 − 1200 × 0.175 = 0, so escrow becomes 0 and
   `freeSlack` = 100. The attacker receives **100 USDT**.
3. `vaultEngine.frob(w, attacker, attacker, −400e18, 0)` and `collateralAdapter.exit`. The check runs
   before the RAIN is removed, so it passes.

The attacker ends with 100 USDT and all 400 RAIN back. The reserve is **0**, the loss is still **60**,
and the protocol is breached. The LP's `buyStable(1 USDT)` reverts.

**Scenario B: during a breach, with no liquidatable vault**

Reserve = 100 (LP 60, attacker 40). Bob deposits 800 RAIN and borrows 200 USDR. RAIN then falls 30% to
$0.70. Loss = **102** > 90, so the protocol is breached. Bob's vault is at 280% (> 260%), so `bark`
reverts and `buyStable(40)` reverts.

The same three steps with 600 RAIN and `buyStable(40e6)` succeed. The attacker gets **40 USDT** and
600 RAIN back. The reserve drops to 60, the protocol is still breached, and the LP's `buyStable(60)`
reverts.

## Impact

- **The whole PSM reserve, including the loss escrow, can be withdrawn** in normal operation with no
  price move (100 of 100 USDT while 60 was escrowed against a loss of 60).
- **The breach gate on `buyStable` can be bypassed.** The attacker redeems at par ahead of other
  holders while redemptions are blocked.
- **Remaining USDR holders carry the loss.** They can no longer redeem through the PSM, and no stable
  reserve is left behind their USDR at shutdown (`End.flow` / `cash`).
- **No preconditions.** Only public calls and temporary collateral (for example a flash swap repaid in
  the same transaction). No liquidatable vault, no oracle fault, no admin action.

Redemption is at $1 per USDR, so the attack is profitable whenever USDR trades below peg: buy USDR
cheaply and redeem it at $1 against the escrowed reserve.

## Proof of concept

The Foundry PoC (`tests/PoC.t.sol`) builds on the repository's `tests/shared/BaseTest.sol` and does
not modify anything in `contracts/`. It was submitted with the report.

```bash
cp PoC.t.sol tests/
forge test --match-path tests/PoC.t.sol -vv
```

```text
[PASS] test_bypassesBreachWithNoLiquidatableVault()
  worstCaseLoss             : 102.000000000000000000
  breach threshold          : 90.000000000000000000
  breached                  : YES
  USDT withdrawn by attacker: 40.000000
  RAIN returned to attacker : 600.000000000000000000
  reserve left              : 60.000000000000000000
  breached after            : YES
[PASS] test_drainsWholeReserveIncludingEscrow()
  breached                  : no
  worstCaseLoss             : 60.000000000000000000
  committedEscrow (locked)  : 60.000000000000000000
  freeSlack (withdrawable)  : 40.000000000000000000
  USDT withdrawn by attacker: 100.000000
  RAIN returned to attacker : 400.000000000000000000
  reserve left              : 0.000000000000000000
  worstCaseLoss after       : 60.000000000000000000
  breached after            : YES
Suite result: ok. 2 passed; 0 failed; 0 skipped
```

## Fix

Both changes are needed. The second one alone does not protect the escrow.

1. **Stop counting collateral that backs no debt.** Track collateral held in vaults with `art == 0`
   and subtract it from `globalInk` in `worstCaseLoss()`.
2. **Gate on the post-change state.** In `frob`, re-run `checkInvariant()` *after* the storage writes
   for `dart > 0 || dink < 0` on volatile ilks, and revert if breached. Without this, fix 1 can be
   bypassed by borrowing the `dust` minimum in the temporary vault and repaying it in the same `frob`
   that withdraws the collateral.

## Timeline

- 2026-09-29: reported
- 2026-10-20: triaged as High
