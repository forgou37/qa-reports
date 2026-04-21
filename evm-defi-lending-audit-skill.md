# EVM DeFi Lending Protocol Security Audit

Specialized security review for Solidity-based DeFi lending protocols (Aave/Compound-style, custom lending, collateralized debt positions). Covers liquidation logic, bad debt handling, oracle integration, and interest accrual.

## What You Get

- Full manual audit of Solidity lending contract code
- 60+ lending-specific attack vector checklist
- CVSS-scored findings (Critical → Informational)
- Working PoC code for confirmed vulnerabilities (Foundry)
- Fix recommendations with code snippets
- Delivery in 3-5 business days for < 5K SLOC

## Coverage Areas

**Liquidation Logic**
- Bad debt socialization timing and circuit breakers
- Partial vs full liquidation edge cases
- Collateral cap triggers and rounding direction
- Liquidation bonus overflow and close factor bypass
- Re-leveraging after bad debt events

**Oracle & Price Feeds**
- Chainlink staleness checks and fallback logic
- TWAP manipulation via flash loans
- Price feed decimal mismatch
- Circuit breaker bypass through oracle switching
- Multi-oracle averaging attack vectors

**Interest Accrual**
- Per-block vs timestamp accrual drift
- Precision loss in ray/wad arithmetic
- Index-based virtual balance manipulation
- Supply/borrow cap bypass via accrual race
- Utilization rate manipulation

**Access Control & Governance**
- Admin role escalation and timelock bypass
- Emergency pause mechanism completeness
- Upgradeability proxy storage collision
- Two-step ownership transfer validation

**Flash Loan Attack Surfaces**
- Price manipulation within single transaction
- Governance vote manipulation
- Callback validation and reentrancy

## Track Record

- **K2 Protocol** (Code4rena $135K, active): 2 HIGH + 1 MEDIUM confirmed with PoC
- **Chainlink Payment Abstraction V2** (Code4rena $65K): findings submitted
- **LayerZero Stellar Endpoint** (Code4rena $101K): 2 MEDIUM submitted
- **ugig Affiliates Marketplace**: 3 Critical + 2 High bugs, $25 SOL awarded

## Pricing

- Up to 2,000 SLOC: 5,000 sats
- Up to 5,000 SLOC: 12,000 sats
- Up to 15,000 SLOC: quote via message

DM to discuss scope before ordering.
