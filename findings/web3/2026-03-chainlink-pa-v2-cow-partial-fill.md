# [MEDIUM] Partially fillable CoW orders become permanently unfillable after the first partial execution because `isValidSignature()` validates against the original `sellAmount` instead of the remaining executable amount

```text
id         : W3-005
protocol   : Chainlink Payment Abstraction V2
platform   : Code4rena audit 2026-03-chainlink-payment-abstraction-v2, submission S-898 (as duan)
severity   : medium
class      : DoS / incorrect ERC-1271 order validation
status     : confirmed
affected   : GPV2CompatibleAuction.sol#L145
```

Original submission: <https://code4rena.com/audits/2026-03-chainlink-payment-abstraction-v2/submissions/S-898>

## Summary

`GPV2CompatibleAuction.isValidSignature()` requires CoW orders to be partially fillable, but checks the auction's current token balance against the order's original full `sellAmount`. After a first partial fill the balance is lower than `sellAmount`, so every later validation of the same order reverts and the remainder can no longer be settled.

## Root cause

`GPV2CompatibleAuction.isValidSignature()` is intended to validate CoW Protocol orders signed via ERC-1271. The function explicitly requires orders to be partially fillable:

```solidity
if (!order.partiallyFillable) {
  revert OrderNotPartiallyFillable();
}
```

However, it also validates the order against the auction's current token balance using the order's original full sell amount:

```solidity
uint256 assetInBalance = order.sellToken.balanceOf(address(this));
if (order.sellAmount > assetInBalance) {
  revert InsufficientAssetInBalance(address(order.sellToken), order.sellAmount, assetInBalance);
}
```

This is incompatible with how partially fillable CoW orders work.

For a partially fillable CoW order, `order.sellAmount` represents the total amount of the original order, while each execution only settles a portion of that amount. After a first partial fill, the auction contract's token balance decreases, but subsequent settlement attempts still call `isValidSignature()` with the same original order data.

As a result, once the auction's remaining balance drops below the original `order.sellAmount`, `isValidSignature()` reverts with `InsufficientAssetInBalance`, even though the order is marked as partially fillable and the remaining quantity should still be executable.

In practice, a supposedly partially fillable order becomes effectively single-use: it may be partially filled once, but the remainder of the same order can no longer be settled.

## Attack path

No attacker is needed; this happens in the normal settlement flow:

1. Auction starts with 100,000 USDC.
2. A CoW order is created with `sellAmount = 100,000 USDC` and `partiallyFillable = true`.
3. First partial fill executes 40,000 USDC.
4. Auction balance becomes 60,000 USDC.
5. A second fill attempts to execute the remainder of the same order; `isValidSignature()` is called again with the same original order.
6. The function checks:

   ```solidity
   if (100,000 > 60,000) revert;
   ```

7. The order remainder becomes unfillable.

## Impact

This issue breaks the intended partial-fill behavior of CoW orders and can cause the remaining portion of an order to become permanently stuck after an earlier partial execution. Impact includes:

- partially fillable orders becoming effectively one-shot
- inability to continue selling the remaining inventory through the same order
- degraded auction execution, especially in low-liquidity markets where multiple partial fills are expected
- requirement for manual operational intervention to cancel and recreate replacement orders
- risk of delayed liquidation / delayed auction completion / reduced execution quality if the protocol depends on progressive fills

This is not direct theft of funds, but it is a real denial-of-service on the remainder of the order and materially disrupts the expected auction flow.

## Proof of concept

The test needs these extra imports:

```solidity
import {GPv2Order} from "src/vendor/@cowprotocol/contracts/src/contracts/libraries/GPv2Order.sol";
import {IERC20 as CowIERC20} from "src/vendor/@cowprotocol/contracts/src/contracts/interfaces/IERC20.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
```

```solidity
function testSubmissionValidity() public {
    // Start a live auction with 100,000 USDC in inventory.
    _startAuction(address(mockUSDC), 100_000e6);

    uint256 fullSellAmount = 100_000e6;
    uint256 firstFillAmount = 40_000e6;
    uint256 remainingAmount = 60_000e6;

    uint256 fullBuyAmount = _getAssetOutAmount(address(mockUSDC), fullSellAmount);

    GPv2Order.Data memory order = GPv2Order.Data({
        sellToken: CowIERC20(address(mockUSDC)),
        buyToken: CowIERC20(address(mockLINK)),
        receiver: address(auction),
        sellAmount: fullSellAmount,
        buyAmount: fullBuyAmount,
        validTo: uint32(block.timestamp + 1 hours),
        appData: bytes32(0),
        feeAmount: 0,
        kind: GPv2Order.KIND_SELL,
        partiallyFillable: true,
        sellTokenBalance: GPv2Order.BALANCE_ERC20,
        buyTokenBalance: GPv2Order.BALANCE_ERC20
    });

    bytes32 orderDigest = GPv2Order.hash(order, mockGPV2Settlement.domainSeparator());

    // 1) Before any fill, the original order is valid.
    bytes4 magic = auction.isValidSignature(orderDigest, abi.encode(order));
    assertEq(magic, IERC1271.isValidSignature.selector);

    // 2) Simulate a successful PARTIAL SETTLEMENT:
    //    the CowSwap vault relayer pulls only part of the sellToken from the auction.
    _changePrank(gpV2VaultRelayer);
    IERC20(address(mockUSDC)).transferFrom(address(auction), address(this), firstFillAmount);

    assertEq(IERC20(address(mockUSDC)).balanceOf(address(auction)), remainingAmount);

    // 3) The SAME original partially-fillable order should still be usable for the remainder,
    //    but it now reverts because isValidSignature compares ORIGINAL sellAmount (100k)
    //    against CURRENT balance (60k).
    vm.expectRevert(
        abi.encodeWithSelector(
            GPV2CompatibleAuction.InsufficientAssetInBalance.selector,
            address(mockUSDC),
            fullSellAmount,
            remainingAmount
        )
    );
    auction.isValidSignature(orderDigest, abi.encode(order));
}
```

## Fix

Validate against the remaining executable amount rather than the original full `sellAmount`.
