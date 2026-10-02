# [MEDIUM] Deposit cap can be bypassed because `deposit_limit_breached()` subtracts `cash_reserve` twice

```text
id         : W3-006
protocol   : Current (Sui Move lending protocol)
platform   : Sherlock contest, March 2026 (as NHD16)
severity   : medium
class      : accounting / deposit cap bypass
date       : 2026-03-13
commit     : 81add07abbebeceadb65293a22a94ab100b8e915
affected   : sui-move-contract/contracts/protocol/sources/internal/market/reserve.move#L82-L92
```

## Summary

The deposit-cap check in `reserve.move` (line 82) understates total supplier assets after protocol reserves accrue.

`total_deposit_plus_interest()` already derives from `exchange_rate()`, and `exchange_rate()` already excludes protocol reserves by using `cash + debt - cash_reserve` in its numerator (`reserve.move` line 92). However, `deposit_limit_breached()` subtracts `cash_reserve` one more time (`reserve.move` line 87).

As a result, once `cash_reserve > 0`, a depositor can pass the cap check in `market.move` (line 278) and push real supplier-backed deposits above the configured `max_deposit_amount`.

## Root cause

`total_deposit_plus_interest()` computes supplier-backed assets as:

```move
exchange_rate * total_supply
```

`exchange_rate()` is already:

```move
(cash + debt - cash_reserve) / total_supply
```

So `total_deposit_plus_interest()` already represents lender-owned assets net of protocol reserve. But `deposit_limit_breached()` does:

```move
total_deposit_plus_interest.ceil() + increment - self.cash_reserve.ceil() > limit
```

This effectively checks:

```move
(cash + debt - cash_reserve) + increment - cash_reserve > limit
```

instead of:

```move
(cash + debt - cash_reserve) + increment > limit
```

So the check creates false headroom roughly equal to `cash_reserve`.

## Preconditions

1. The asset has a non-zero `cash_reserve`.
2. The asset has a finite `max_deposit_amount`.
3. Real supplier-backed deposits are close enough to the cap that the artificial headroom matters.
4. Deposits for the asset are not paused, and the market is not under circuit break.
5. The attacker has a valid obligation, which is publicly obtainable through the normal market entry flow.

No external preconditions.

## Attack path

1. A market accumulates protocol reserves through normal operation, such as interest accrual, liquidation revenue, flash-loan fees, or repay-overage donations.
2. Real supplier-backed deposits approach the configured deposit cap.
3. An attacker submits a new deposit.
4. `handle_mint()` calls `deposit_limit_breached()` before minting cTokens.
5. Because the function subtracts `cash_reserve` twice, the check underestimates current deposits and incorrectly returns `false`.
6. The deposit is accepted even though true supplier-backed deposits now exceed `max_deposit_amount`.

## Impact

- The protocol's deposit cap can be bypassed by approximately the current reserve balance of the asset.
- Governance-set exposure limits are no longer reliably enforced.
- More capital than intended can enter a capped market, increasing protocol exposure to that asset.
- If deposit positions are reward-bearing or collateralizable, the attacker also gains economic utility from deposits that should have been rejected.

## Proof of concept

```move
#[test]
fun test_deposit_limit_double_subtracts_reserves_and_allows_cap_bypass() {
    let admin = @0xAD;
    let mut scenario_value = sui::test_scenario::begin(admin);

    let ctx = scenario_value.ctx();
    let mut reserve = new<MainMarket, BTC>(ctx, 0);

    let initial_deposit = 1000;
    let deposit_limit = 1010;
    let exploit_deposit = 10;

    let btc = sui::balance::create_for_testing<BTC>(initial_deposit).into_coin(ctx);
    let initial_ctokens = reserve.mint_ctokens<MainMarket, BTC>(btc).into_coin(ctx);

    let borrowed = reserve.borrow_amount<MainMarket, BTC>(100);
    let reserve_factor = float::from_percent(50);
    let interest_rate = float::from_percent(10);
    reserve.accrue_interest(reserve_factor, interest_rate, 1);

    assert!(reserve.protocol_reserve<MainMarket>() == 5);
    assert!(reserve.total_deposit_plus_interest<MainMarket>().floor() == 1005);
    assert!(reserve.cash_plus_borrows_minus_reserves<MainMarket>().floor() == 1005);

    // Live call path: market.handle_mint() trusts this predicate before minting cTokens.
    assert!(!reserve.deposit_limit_breached<MainMarket>(exploit_deposit, deposit_limit));

    let exploit_coin = sui::balance::create_for_testing<BTC>(exploit_deposit).into_coin(ctx);
    let exploit_ctokens = reserve.mint_ctokens<MainMarket, BTC>(exploit_coin).into_coin(ctx);

    assert!(reserve.cash_plus_borrows_minus_reserves<MainMarket>().floor() == 1015);
    assert!(reserve.cash_plus_borrows_minus_reserves<MainMarket>().floor() > deposit_limit);

    sui::balance::destroy_for_testing(borrowed);
    std::unit_test::destroy(initial_ctokens);
    std::unit_test::destroy(exploit_ctokens);
    std::unit_test::destroy(reserve);
    scenario_value.end();
}
```

## Fix

Update the cap check so reserves are excluded exactly once.

```move
self.cash_plus_borrows_minus_reserves().ceil() + increment > limit
```
