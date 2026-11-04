# [HIGH] Fee-exempt stable ilks accept non-PSM debt: permanent PSM redemption freeze and permanent `distributeSurplus` revert

```text
id         : W3-010
protocol   : Rain — USDR
platform   : HackenProof (RAIN-USDR Smart Contract Audit Contest, Sept 2026)
severity   : high
class      : Accounting desync / reserve ledger
status     : confirmed by HackenProof triage (High)
report id  : RAINUSDR-1683
commit     : hackenproof-public/rain-usdr-contracts@bd6e03abe34936b7dbece2509b90457bd5c9b119
date       : 2026-09-25
```

## Summary

`ReserveAccounting.totalReserve` is the protocol's record of the stablecoins backing USDR, and only
the PSM writes to it. But `USDT-A` / `USDC-A` are ordinary ilks: any address can
`join` → `open` → `frob` → `exit` and mint USDR 1:1 against them **outside the PSM**, where
`recordIncrease` never fires.

Deposits made this way are invisible to the ledger, while redemptions through `buyStable` are not.
This asymmetry lets a non-privileged attacker **drain `totalReserve` to zero while every custodied
token stays exactly where it was**, which permanently freezes redemption for all PSM depositors.
Separately, **1e-6 USDT** is enough to permanently brick `distributeSurplus`.

## Root cause

**1. The counter has one writer, and it is not the ledger.**
`recordIncrease` / `recordDecrease` (`contracts/reserve/ReserveAccounting.sol:47-48, 56-57`) are
`onlyRole(_RECORDER_ROLE)`, and that role is granted only to the PSM (`scripts/deploy-reserve.js:69`).
The PSM calls them from exactly two places: `PegStabilityModule.sol:188` (`sellStable`) and `:242`
(`buyStable`). So `totalReserve` tracks *PSM flows*, not the state of the ilk it describes.

**2. The ilk itself is open to everyone.** There is no role modifier on `CollateralAdapter.join`
(`:102`), `VaultEngine.open` (`:280`), `VaultEngine.frob` (`:420`) or `CollateralAdapter.exit`
(`:156`).

**3. The configuration makes the direct path identical to the PSM.** Stable ilks use `mat = RAY`
(`scripts/deploy-oracles.js:69-82`), so `spot = RAY` and the safety check passes at exactly
`dink == dart`, the same 1:1 rate the PSM uses. `dust` is set only for `rainIlk`
(`scripts/deploy-governance.js:109-115`), so 1 wei of `art` is a valid position.

**4. The backing assertion compares two different populations.** `contracts/reserve/BalanceSheet.sol:213-221`
sums `globalArt` over *all* vaults on a `noFee` ilk, then compares it against a `totalReserve` that
counts *PSM flows only*:

```solidity
if (VAULT_ENGINE.noFee(ilkId)) {
    (uint256 globalArt, , uint256 rate, , , , , ) = VAULT_ENGINE.ilks(ilkId);
    stableDebt += globalArt * rate;
}
...
if (reserveAccounting.totalReserve() * _RAY < stableDebt) {
    _revert(ReserveBackingShortfall.selector);
}
```

## Attack path

The attacker needs no privilege, only an EOA with at least 1 unit of USDT (1e-6). The launch
configuration already provides everything else: `USDT-A` / `USDC-A` are registered with the PSM,
`mat = RAY`, and the adapter is live.

**Variant A: brick `distributeSurplus` for 1e-6 USDT**

1. `collateralAdapter.join(USDT_ILK, self, 1)` credits `1e12`. No `recordIncrease`.
2. `vaultEngine.open(USDT_ILK, self)`.
3. `vaultEngine.frob(v, self, self, +1e12, +1)` creates one wei of `art`. The safety check passes
   (`spot == RAY`) and so does the dust check (`dust == 0`).
4. `globalArt` is now 1 wei above anything the PSM recorded. `distributeSurplus()` reverts with
   `ReserveBackingShortfall` for every caller, permanently.

**Variant B: drain the reserve and freeze all redemption**

Each cycle uses working capital `X`:

1. `join(USDT_ILK, self, X)` creates a *new* ledger claim. `totalReserve` is unchanged.
2. `open` + `frob(v, self, self, +X18, +X18)` mints `X` USDR at 1:1.
3. `hope(collateralAdapter)` + `exit(_USDR_ILK, self, X18)` converts the USDR to ERC-20.
4. `buyStable(USDT_ILK, self, X)` consumes the PSM's *existing* claim. `:238` frobs the PSM's own
   vault, and `:242` fires `recordDecrease(X)`. The attacker receives `X` USDT back.

Net per cycle: the attacker's balance and the adapter's balance are both unchanged, and
`totalReserve` drops by `X`. The attacker has swapped a fresh claim for the PSM's pre-existing one,
and the counter only sees the outflow. The working capital comes back in the same transaction, so
no capital is ever at risk and the attack scales to any reserve size. The only cost is the number of
transactions.

## Impact

1. **Permanent DoS of `distributeSurplus` for 1e-6 USDT.** The protocol runs no surplus auction.
   Surplus leaves only through the RAIN buyback-and-burn (`BalanceSheet.sol:21-22`), and `:251` is the
   contract's only outward transfer. Bricking it permanently halts value accrual for RAIN holders.
   `End.thaw` is blocked too, since it requires `usdr[balanceSheet] == 0` (`End.sol:339-340`). One wei
   is enough because both sides of the assertion are exactly equal in the honest state.
2. **Permanent freeze of PSM redemption.** `freeSlack()` reaches 0 and `buyStable` reverts with
   `InsufficientFreeSlack` for everyone. The obvious fix does not work: governance can grant itself
   `_RECORDER_ROLE` and restore `totalReserve`, but redemption *still* reverts with `AddUnderflow()`,
   because the PSM's vault really was emptied. Real recovery needs fresh capital or phantom `slip`
   collateral, both behind the 48-hour timelock.
3. **Asymmetric exit.** Users who entered through `join` + `frob` own a vault and can still unwind it,
   because `frob` + `exit` never reads `freeSlack()`. Users who entered through `sellStable` only hold
   ERC-20 USDR, and all four exit routes revert. `sellStable` keeps working with no guard
   (`PegStabilityModule.sol:164-165`), so the peg ceiling survives and only the floor is destroyed.
   That makes the attacker the natural buyer of distressed USDR, with profit `art × (1 − price)`.
4. **Collateral freeze for uninvolved RAIN borrowers.** `checkInvariant` sets
   `committedEscrow = min(loss, reserve)` (`SolvencyEngine.sol:224`). Draining the free slack therefore
   leaves the reserve at exactly `loss`, and the breach test `loss > 0.9 × reserve` (`:221`) becomes
   `loss > 0.9 × loss`, which is true for any `loss > 0`. A single cycle is enough. No price drop or
   unsafe vault is needed, because `loss > 0` already holds whenever aggregate volatile collateral is
   below the 571% stress break-even (`mat` is 400%). Every RAIN vault owner is then blocked from
   withdrawing collateral or borrowing (`VaultEngine.sol:463-471`).

What this is not: USDR never becomes unbacked. Total `ink` always equals the adapter's balance, and
the round trip is exactly token-neutral. The attacker cannot walk off with the pool. The value
transfer is indirect: the attacker buys distressed USDR from the holders they froze.

## Proof of concept

The Foundry PoC extends the repository's `tests/shared/BaseTest.sol` and adds nothing to
`contracts/`. Its `setUp()` wires `balanceSheet.file("reserveAccounting", ...)` the same way production
does (`scripts/deploy-reserve.js:128-129`). `BaseTest` skips this, which leaves the reserve-backing
assertion dead in all 166 repo tests.

```bash
forge test --match-contract S1_PoC -vv
# Expected: 6 failed, 0 passed. Every test asserts the CORRECT behaviour, so every failure is the bug.
```

| Test | What it shows |
|---|---|
| `test_impact1_oneWeiBricksDistributeSurplus` | Spending 1e-6 USDT creates a `1e27` rad shortfall. `distributeSurplus()` then reverts `ReserveBackingShortfall` for every caller. |
| `test_impact2a_tokenNeutralDrainFreezesRedemption` | `totalReserve` drops 1000 → 0 over 10 cycles while adapter and attacker USDT balances are unchanged. The honest depositor's `buyStable` reverts. |
| `test_impact2b_governanceLedgerFixIsInsufficient` | Governance restores `totalReserve` via `recordIncrease(1000e18)`, yet `buyStable` still reverts with `AddUnderflow()`, because the PSM vault's `ink`/`art` are 0. |
| `test_impact3a_psmDepositorHasNoExitPath` | All four exit routes for a PSM depositor revert. |
| `test_impact3b_attackerExitsAtParAndProfits` | While the victim is frozen, the attacker unwinds their own vaults at par. Modelling a 0.80 buyback, the attacker gains 200 USDT and the victim loses 200. |
| `test_impact4_uninvolvedRainBorrowerFrozen` | With RAIN held at $1, one cycle drives the reserve 1000 → 37.5 (= loss) against a threshold of 33.75. A 500%-collateralised borrower cannot withdraw 1 RAIN. |

```text
adapter USDT  before: 1000000000    after: 1000000000   <- unchanged
attacker USDT before: 100000000     after: 100000000    <- unchanged
totalReserve  after : 0
freeSlack     after : 0
```

## Fix

1. **Make stable-ilk minting PSM-exclusive (root cause).** `noFee[ilkId]` carries the intent "this
   ilk belongs to the PSM" without enforcing it. Record the authorised minter and check it:

```solidity
// VaultEngine: set alongside exemptFee(ilkId)
mapping(bytes32 ilkId => address) public stableMinter;

// VaultEngine.frob, before the ceiling check at :488
if (dart > 0 && noFee[ilkId] && ownerOf[vaultId] != stableMinter[ilkId]) {
    _revert(NotStableMinter.selector);
}
```

2. **Compare like with like in the assertion.** `BalanceSheet.sol:213-216` should read the PSM's own
   vault instead of the ilk aggregate. `PegStabilityModule.ilks(ilkId).vaultId` is public and
   immutable after `init` (written once at `:129`, guarded by `IlkAlreadyInitialized` at `:104`), so
   `VAULT_ENGINE.urns(psmVaultId).art` is a safe replacement for `globalArt`.

## Timeline

- 2026-09-25: reported
- 2026-10-20: triaged as High
