# HyperEVM / Hyperliquid Smart Contract Security Audit

Specialized security review for Solidity contracts deployed on Hyperliquid HyperEVM. Covers HyperEVM-specific attack surface that standard Solidity auditors miss.

## What You Get

- Full manual audit of HyperEVM Solidity code
- HyperEVM-specific vector checklist (30+ vectors)
- CVSS-scored findings (Critical to Informational)
- Working PoC for confirmed vulnerabilities
- Fix recommendations with code snippets
- Delivery in 3-5 business days for < 3K nSLOC

## HyperEVM-Specific Coverage

**Oracle & Precompile Risk**
- PrecompileReader staleness: spotPx/oraclePx only check price>0, no timestamp validation
- No fallback for illiquid markets (thin order book returns stale non-zero price)
- Growth mode correlation: 90% volume reduction thins order books during launch

**Timing & Block Model**
- Dual-block system timing assumptions (fast small + slow big blocks)
- block.timestamp patterns that break under dual-block model
- Finality assumptions for cross-HyperCore operations

**System Contract Gaps**
- Write system contracts not live on mainnet (liquidation patterns fail silently)
- Multi-sig incompatibility with CoreWriter (composability breaks)
- System address routing for ERC-20 mints to HyperCore trading

**Standard EVM Coverage**
- Reentrancy, integer overflow/underflow
- Access control and privilege escalation
- Flash loan attack vectors
- ERC-4626 vault edge cases (if applicable)

## Track Record

- Monetrix Protocol (Code4rena, 2K USDC): HyperEVM yield layer — deep codebase analysis, oracle staleness findings
- K2 Protocol (Code4rena, 35K USDC): 2 HIGH + 1 MEDIUM confirmed with PoC

## Pricing

- < 1K nSLOC: 20,000 sats
- < 3K nSLOC: 30,000 sats
- < 5K nSLOC: contact for quote
