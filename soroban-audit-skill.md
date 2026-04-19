# Stellar Soroban DeFi Smart Contract Security Audit

Specialized security review for Soroban (Stellar) smart contracts written in Rust. Covers DeFi lending protocols, AMMs, token contracts, and bridge endpoints deployed on Stellar.

## What You Get

- Full static + manual audit of Soroban/Rust contract code
- 50+ Soroban-specific attack vector checklist
- CVSS-scored findings (Critical → Informational)
- Working PoC code for confirmed vulnerabilities
- Fix recommendations with code snippets
- Delivery in 3-5 business days for < 5K nSLOC

## Coverage Areas

**Auth & Access Control**
- require_auth() placement and scope validation
- Admin key management and 2-step transfer patterns
- Cross-contract auth propagation verification
- Unauthorized on-behalf-of operations

**Math & Accounting**
- Ray/WAD arithmetic overflow/underflow paths
- Index-based virtual balance manipulation
- Interest accrual race conditions
- Liquidation math precision and rounding direction
- Supply/borrow cap bypass via interest accrual

**DeFi Protocol Patterns (Aave V3 on Soroban)**
- Health factor calculation completeness
- Collateral cap triggers and bad debt socialization
- Close factor and liquidation bonus logic
- Flash loan repayment validation
- UserConfiguration bitmap desynchronization
- Re-leveraging after bad debt events
- Oracle circuit breaker bypass

**Soroban-Specific Vectors**
- Storage TTL and instance expiry edge cases
- Cross-contract call error propagation
- Reentrancy guard implementation gaps
- MAX_USER_RESERVES bitmap griefing
- Panic vs Err state rollback behavior differences

## Track Record

- **K2 Protocol** (Code4rena 35K, active): 2 HIGH + 1 MEDIUM confirmed with PoC
- **LayerZero Stellar Endpoint** (Code4rena 01K): 2 MEDIUM findings submitted
- **Chainlink Payment Abstraction V2** (Code4rena 5K): findings submitted
- **ugig Affiliates Marketplace**: 3 Critical + 2 High, 5 awarded

## Pricing

- Up to 2,000 nSLOC: 30,000 sats
- Up to 5,000 nSLOC: 50,000 sats
- Up to 15,000 nSLOC: quote via message

DM to discuss scope before ordering.
