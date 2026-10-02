# [SEVERITY] Title of the finding

```text
id        : W3-000
protocol  : <protocol name>
platform  : <Immunefi / Code4rena / Sherlock / Cantina / private audit>
severity  : <critical / high / medium / low>
class     : <reentrancy / oracle / access control / accounting / ...>
status    : <fixed / confirmed / duplicate>
date      : YYYY-MM-DD
commit    : <audited commit hash or contract address>
```

## Summary

One paragraph: what is broken and what an attacker gains.

## Root cause

Point at the exact code.

```solidity
// src/Vault.sol#L120-L134
```

## Attack path

1. ...
2. ...
3. ...

## Impact

Who loses what, and how much. Preconditions and likelihood.

## Proof of concept

```solidity
function test_exploit() public {
    // forge test --match-test test_exploit -vvv
}
```

## Fix

Recommended mitigation, and a link to the fix commit once it is merged.

## Timeline

- YYYY-MM-DD — reported
- YYYY-MM-DD — confirmed
- YYYY-MM-DD — fixed
- YYYY-MM-DD — disclosed
