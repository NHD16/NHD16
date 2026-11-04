<p align="center">
  <img src="assets/banner.svg" alt="NHD16 — security researcher: smart contracts and web" width="860">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/WEB3-smart%20contract%20audit-39ff14?style=flat-square&labelColor=0d1117" alt="web3: smart contract audit">
  <img src="https://img.shields.io/badge/WEB2-bug%20bounty-39ff14?style=flat-square&labelColor=0d1117" alt="web2: bug bounty">
  <img src="https://img.shields.io/badge/STATUS-hunting-ff5f56?style=flat-square&labelColor=0d1117" alt="status: hunting">
</p>

```console
nhd16@kali:~$ cat /etc/motd
> I break things so they can be fixed before someone else breaks them.
> Everything listed here was reported responsibly and is published with permission.
```

## `0x00` loot

<!-- STATS:START -->
```text
$ ./loot --summary
┌──────────┬──────┬──────┬───────┐
│ SEVERITY │ WEB3 │ WEB2 │ TOTAL │
├──────────┼──────┼──────┼───────┤
│ CRITICAL │    1 │    0 │     1 │
│ HIGH     │    5 │    2 │     7 │
│ MEDIUM   │    4 │    0 │     4 │
│ LOW      │    0 │    0 │     0 │
├──────────┼──────┼──────┼───────┤
│ TOTAL    │   10 │    2 │    12 │
└──────────┴──────┴──────┴───────┘
```
<!-- STATS:END -->

## `0x01` smart contract findings

```console
nhd16@kali:~/loot$ ls -t web3/
```

<!-- WEB3:START -->
| ID | Severity | Protocol | Finding | Class | Platform | Report |
|---|---|---|---|---|---|---|
| `W3-007` | 🟥 `CRITICAL` | Zendex | Join circuit omits nullifier distinctness, allowing one note to fund both sides of a join | ZK circuit / double spend | HackenProof | [`read →`](findings/web3/zendex-join-nullifier-distinctness.md) |
| `W3-008` | 🟧 `HIGH` | Rain — USDR | Collateral deposited for one transaction unlocks the whole PSM reserve, including the escrow held back for losses | Solvency accounting / flash collateral | HackenProof | [`read →`](findings/web3/2026-09-rain-usdr-psm-escrow-bypass.md) |
| `W3-009` | 🟧 `HIGH` | Rain — USDR | `worstCaseLoss()` drops liquidated debt: `bark` clears a solvency breach, and realized bad debt counts as zero loss | Solvency accounting / liquidation | HackenProof | [`read →`](findings/web3/2026-09-rain-usdr-bark-clears-solvency-breach.md) |
| `W3-010` | 🟧 `HIGH` | Rain — USDR | Fee-exempt stable ilks accept non-PSM debt: permanent PSM redemption freeze and permanent `distributeSurplus` revert | Accounting desync / reserve ledger | HackenProof | [`read →`](findings/web3/2026-09-rain-usdr-stable-ilk-non-psm-debt.md) |
| `W3-001` | 🟨 `MEDIUM` | Revert Finance — StableSwap Hooks | Exact-input swaps can zero output reserves and permanently brick pool math | DoS / missing reserve check | Cantina | [`read →`](findings/web3/2026-05-revert-stableswap-zero-reserve.md) |
| `W3-002` | 🟧 `HIGH` | Revert Finance — StableSwap Hooks | Native ETH `removeLiquidity` reentrancy allows swaps against stale reserves and profitable LP fund extraction | Reentrancy / stale reserves | Cantina | [`read →`](findings/web3/2026-05-revert-stableswap-native-eth-reentrancy.md) |
| `W3-004` | 🟨 `MEDIUM` | K2 | `execute_liquidation` allows stale prepared liquidations to seize collateral after the collateral reserve is paused | Missing pause check | Code4rena | [`read →`](findings/web3/2026-04-k2-stale-liquidation-paused-reserve.md) |
| `W3-005` | 🟨 `MEDIUM` | Chainlink Payment Abstraction V2 | Partially fillable CoW orders become permanently unfillable after the first partial execution | DoS / ERC-1271 order validation | Code4rena | [`read →`](findings/web3/2026-03-chainlink-pa-v2-cow-partial-fill.md) |
| `W3-006` | 🟨 `MEDIUM` | Current (Sui) | Deposit cap can be bypassed because `deposit_limit_breached()` subtracts `cash_reserve` twice | Accounting / cap bypass | Sherlock | [`read →`](findings/web3/2026-03-current-sui-deposit-cap-bypass.md) |
| `W3-003` | 🟧 `HIGH` | SukukFi | Vaults can burn user shares without user approval after self-allowance is set | Access control / allowance | Code4rena | [`read →`](findings/web3/2025-12-sukukfi-vault-burn-self-allowance.md) |
<!-- WEB3:END -->

## `0x02` web2 findings

```console
nhd16@kali:~/loot$ ls -t web2/
```

<!-- WEB2:START -->
| ID | Severity | Target | Finding | Class | CVE / Platform | Report |
|---|---|---|---|---|---|---|
| `W2-001` | 🟧 `HIGH` | Thelia v2.6.1 | Path traversal in `item_name` plus PHP string-literal breakout in the translation editor lets an admin write executable PHP to web-accessible paths (RCE) | RCE / path traversal + PHP code injection | [`CVE-2026-103535`](https://nvd.nist.gov/vuln/detail/CVE-2026-103535) | `redacted` |
| `W2-002` | 🟧 `HIGH` | Thelia v2.6.1 | `checkTemplate()` fails open for absolute paths, letting an authorized user load arbitrary files as Smarty templates (SSTI to code execution) | SSTI / template path validation | [`CVE-2026-103537`](https://nvd.nist.gov/vuln/detail/CVE-2026-103537) | `redacted` |
<!-- WEB2:END -->

<sub>`redacted` = report is private or still under disclosure embargo.</sub>

<p align="center"><sub><code>[ EOF ] — connection closed by remote host</code></sub></p>
