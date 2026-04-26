# ERC-4626 Vault Security Audit — Solidity DeFi

Specialized security audit for ERC-4626 tokenized vault implementations. Covers inflation attacks, rounding exploits, share manipulation, and integration pitfalls.

## What You Get

- Full manual audit of ERC-4626 vault Solidity code
- 40+ vault-specific attack vector checklist
- CVSS-scored findings (Critical to Informational)
- Working PoC for confirmed vulnerabilities (Foundry)
- Fix recommendations with code snippets
- Delivery in 2-4 business days for < 3K nSLOC

## Coverage Areas

**Share Inflation & Rounding**
- Virtual share offset bypass (decimalsOffset manipulation)
- Rounding direction asymmetry (deposit vs redeem favoring vault)
- First depositor griefing and share price manipulation
- Decimal mismatch misleading integrators (decimals() vs asset.decimals() + offset)

**totalAssets Manipulation**
- Donation attacks inflating vault share price
- Async totalAssets leading to stale exchange rate
- Flash loan manipulation of vault backing

**Hooks & Reentrancy**
- beforeWithdraw/afterDeposit hook reentrancy vectors
- ERC777 token integration with vault callbacks
- Multi-step deposit/redeem reentrancy paths

**Integration Risks**
- Slippage on deposit/withdraw (maxDeposit/maxWithdraw not enforced)
- Composability with lending protocols using vault shares as collateral
- Permit2 signature replay in vault context

## Track Record

- Monetrix Protocol (Code4rena, 2K USDC): sUSDM ERC-4626 with _decimalsOffset=6 — full analysis of virtual share inflation design, confirmed intentional vs exploitable patterns
