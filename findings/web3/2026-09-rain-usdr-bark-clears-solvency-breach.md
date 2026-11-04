# [HIGH] `worstCaseLoss()` drops liquidated debt: `bark` clears a solvency breach, and realized bad debt counts as zero loss

```text
id         : W3-009
protocol   : Rain — USDR
platform   : HackenProof (RAIN-USDR Smart Contract Audit Contest, Sept 2026)
severity   : high
class      : Solvency accounting / liquidation
status     : confirmed by HackenProof triage (High)
report id  : RAINUSDR-1893
commit     : hackenproof-public/rain-usdr-contracts@bd6e03abe34936b7dbece2509b90457bd5c9b119
date       : 2026-09-29
```

## Summary

`SolvencyEngine.worstCaseLoss()` drives the solvency gate. It sets `committedEscrow` and decides
whether the protocol is breached, which blocks `buyStable` and risk-increasing `frob`.

`worstCaseLoss()` only looks at debt and collateral **that are still inside vaults**. When a vault is
liquidated (`bark`), both its debt and its collateral move out of the vault: the debt goes to the
Balance Sheet as `sin`, and the collateral goes to the auction contract. `worstCaseLoss()` reads
neither, so a liquidated vault's risk disappears from the calculation.

- **A. Liquidation alone clears the breach.** `bark` removes the vault's risk before the auction has
  sold anything, so the breach clears and PSM withdrawals reopen.
- **B. A realized loss is reported as zero.** If the auction sells the collateral for less than the
  debt, the shortfall sits in `sin` as unbacked USDR, but `worstCaseLoss()` still returns 0. Nothing
  is locked and the whole reserve stays withdrawable.

Losing money on a liquidation is a normal risk for any collateral-backed stablecoin. The bug is that
once that loss has happened, the safety check that exists to protect the reserve in exactly that
situation does not trigger.

## Root cause

The loss estimate only reads vault aggregates.
`contracts/reserve/SolvencyEngine.sol:257-276`

```solidity
(uint256 globalArt, uint256 globalInk, uint256 rate, , , , , ) = VAULT_ENGINE.ilks(ilkId);
uint256 ilkDebt = (globalArt * rate) / _RAY;                                       // :257
collateralValue = (globalInk * uint256(val)) / _WAD;                                // :268
uint256 recoverable = (((collateralValue * stressMarkdown) / _WAD) * stressDepth) / _WAD; // :273
if (ilkDebt > recoverable) loss += ilkDebt - recoverable;                           // :276
```

It never reads `VAULT_ENGINE.sin(...)`, the collateral held by the auction, or
`BalanceSheet.totalQueuedSin`. The only reader of `sin` is `BalanceSheet` (`:160`, `:184`), which
does not feed the solvency check.

Liquidation moves both sides out of the aggregates. `bark` calls `VaultEngine.grab`
(`LiquidationTrigger.sol:260`):

```solidity
VAULT_ENGINE.grab(vaultId, milk.clip, address(balanceSheet), -int256(dink), -int256(dart));
```

```solidity
// VaultEngine.sol:544-551
ilk.globalArt = Math.add(ilk.globalArt, dart);                    // read by worstCaseLoss
ilk.globalInk = Math.add(ilk.globalInk, dink);                    // read by worstCaseLoss
int256 dtab = Math.mul(ilk.rate, dart);
collateral[ilkId][v] = Math.sub(collateral[ilkId][v], dink);      // auction: NOT read
sin[w] = Math.sub(sin[w], dtab);                                  // sin[BalanceSheet]: NOT read
```

`kick` also adds the keeper reward to `sin` (`DutchAuction.sol:224`). The USDR the vault borrowed is
still in circulation.

`sin` is bad debt, and only the reserve backs it. `IVaultEngine.sol:388` and `:479` describe
`vice`/`sin` as "bad debt", and `BalanceSheet.sol:21-22` says the protocol "uses no surplus or debt
auctions". The reserve is the only backstop until surplus pays the debt off.

The same collateral is therefore valued two different ways. Inside a vault it counts at 17.5%
(`stressMarkdown × stressDepth`). Once `bark` starts its liquidation, it leaves the calculation
together with its debt, which silently assumes a 100% recovery.

## Attack path

Launch settings from `tests/shared/BaseTest.sol`. Every call is public, and the oracle price is
correct throughout.

**Scenario A: liquidation alone clears the breach**

1. The LP deposits 100 USDT into the PSM. Bob deposits 800 RAIN and borrows 200 USDR at RAIN = $1.
2. RAIN falls to $0.60. Loss = 200 − 800 × 0.6 × 0.175 = **116** > 90, so the protocol is breached
   and `buyStable(100 USDT)` reverts.
3. Anyone calls `bark` on Bob's vault.

| | Before `bark` | After `bark` |
|---|---|---|
| `worstCaseLoss()` | 116 (breached) | **0 (not breached)** |
| RAIN in auction (not counted) | 0 | 800, none sold yet |
| `sin[BalanceSheet]` (not counted) | 0 | 204.52 (200 debt + 4.52 keeper reward) |

4. `buyStable(100 USDT)` now **succeeds**, and the reserve is emptied while the auction is still open.

**Scenario B: realized bad debt counts as zero loss**

1. Reserve = 400 (the LP deposits 100 USDT, and a bidder deposits 300 USDT to get USDR for the
   auction). Bob deposits 800 RAIN and borrows 200 USDR at RAIN = $1.
2. RAIN falls to **$0.20**, so the collateral ($160) is worth less than the debt.
3. `bark`: `sin[BalanceSheet]` = 204.52.
4. After 300 s the auction price is $0.1925 (3.75% below the oracle). The bidder buys all 800 RAIN for
   **154 USDR**, and the auction closes.
5. **50.52 USDR** is now in circulation with nothing behind it. Yet `checkInvariant()` reports a loss
   of 0, `committedEscrow` = 0, no breach, and all 400 of the reserve is withdrawable.

**Required price drop.** A loss appears once the price at `bark` is below
`204.52 / (800 × sale price as a share of the oracle)`:

| Keeper buys at | Loss if the price at `bark` is below | Drop from $1 |
|---|---|---|
| 3.75% below the oracle (fast keeper, as in the PoC) | $0.266 | > 73% |
| 47.5% below the oracle (lowest price before a reset) | $0.487 | > 51% |

A vault liquidated at its $0.65 trigger never loses money. A loss therefore needs the price to jump
from above $0.65 to below ~$0.49 before the oracle catches up, which lags by 1-2 hours. That means a
~25% drop within an hour or two, or a queue of vaults waiting for auction capacity.

## Impact

- **The safety check turns off during a liquidation wave.** The same market drop causes both the
  breach and the liquidations. Each `bark` removes its vault's risk before anything is sold
  (116 → 0 in scenario A). That re-enables PSM withdrawals, releases the locked reserve and lets
  borrowers take on more risk (`VaultEngine.sol:464-468`), exactly when those protections are needed.
  The liquidated borrower keeps their USDR and can redeem it too.
- **A realized loss never reaches the safety check.** After scenario B, 50.52 USDR is definitely lost,
  but nothing is locked. USDR holders can redeem at $1 until the reserve is empty. Early redeemers are
  paid in full, and late holders absorb the loss (`End.flow` / `cash`). This is the bank-run ordering
  that the check itself is meant to prevent (`PegStabilityModule.sol:211-214`).
- **The documented guarantee is broken.** `SolvencyEngine.sol:23-26` says the check "fails CLOSED".
  For losses created by liquidations, it fails open.

No oracle fault and no special permissions are needed. The loss is not erased (it stays in `sin`, and
surplus can still pay it off), but the reserve is unprotected in the meantime.

## Proof of concept

The Foundry PoC (`tests/PoC.t.sol`) builds on the repository's `tests/shared/BaseTest.sol` and does
not modify anything in `contracts/`. It was submitted with the report.

```bash
cp PoC.t.sol tests/
forge test --match-path tests/PoC.t.sol -vv
```

```text
[PASS] test_S10_barkClearsBreachBeforeAnythingIsSold()
  worstCaseLoss before bark: 116.000000000000000000
  breach threshold         : 90.000000000000000000
  breached before bark     : YES
  worstCaseLoss after bark : 0.000000000000000000
  breached after bark      : no
  sin[BalanceSheet] (USDR) : 204.520000000000000000
  RAIN unsold in auction   : 800.000000000000000000
[PASS] test_S10_realizedBadDebtCountsAsZeroLoss()
  sin[BalanceSheet] after bark (USDR): 204.520000000000000000
  auction proceeds          (USDR)   : 154.000000000000000000
  UNBACKED USDR (realized loss)      : 50.520000000000000000
  worstCaseLoss()                    : 0.000000000000000000
  committedEscrow                    : 0.000000000000000000
  freeSlack (redeemable reserve)     : 400.000000000000000000
  totalReserve                       : 400.000000000000000000
```

## Fix

Add the debt that has left the vaults, minus available surplus, to the loss estimate, and value the
collateral held by the auction at the same 17.5% as vault collateral. In
`SolvencyEngine.worstCaseLoss()`:

```solidity
// inside the volatile-ilk loop, after `recoverable`:
if (has && address(liquidationTrigger) != address(0)) {
    (address clip, , , , ) = liquidationTrigger.ilks(ilkId);
    if (clip != address(0)) {
        uint256 auctionValue = (VAULT_ENGINE.collateral(ilkId, clip) * uint256(val)) / _WAD;
        auctionRecoverable += (((auctionValue * stressMarkdown) / _WAD) * stressDepth) / _WAD;
    }
}

// after the loop:
if (balanceSheet != address(0)) {
    uint256 sinBs = VAULT_ENGINE.sin(balanceSheet);
    uint256 surplusBs = VAULT_ENGINE.usdr(balanceSheet);
    if (sinBs > surplusBs) {
        uint256 netSin = (sinBs - surplusBs) / _RAY;
        if (netSin > auctionRecoverable) loss += netSin - auctionRecoverable;
    }
}
```

`balanceSheet` and `liquidationTrigger` are new addresses set through `file`. A simpler and more
conservative option is to add `max(0, sin[BalanceSheet] − usdr[BalanceSheet])` directly to the loss.

## Timeline

- 2026-09-29: reported
- 2026-10-20: triaged as High
