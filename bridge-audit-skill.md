# Cross-Chain Bridge Security Audit — LayerZero / Wormhole / Axelar

Security review for cross-chain bridge integrations and OApp implementations. Covers message spoofing, replay attacks, oracle manipulation across chains, and DVN configuration errors.

## What You Get

- Full manual audit of bridge/OApp Solidity and Rust code
- 50+ cross-chain attack vector checklist
- CVSS-scored findings (Critical to Informational)
- Working PoC for confirmed vulnerabilities
- Fix recommendations with code snippets
- Delivery in 3-5 business days for < 5K nSLOC

## Coverage Areas

**Message Integrity**
- Cross-chain message replay attacks (nonce reuse, sequence gaps)
- Message spoofing via compromised DVN/relayer
- Payload validation bypass (type confusion, length mismatch)
- Out-of-order message delivery exploits

**Oracle & Finality**
- Finality assumption bugs (accepting unfinalized blocks as source)
- Oracle price manipulation across chains (inconsistent decimals/feeds)
- Timestamp skew between source and destination chains

**LayerZero Specific**
- DVN configuration errors (threshold bypass, quorum reduction)
- EndpointV2 OApp configuration (setPeer spoofing, executor manipulation)
- SendULN302/ReceiveULN302 library mismatches
- lzToken fee griefing and fee theft vectors

**Wormhole Specific**
- VAA replay and signature threshold attacks
- Guardian set update race conditions
- Consistency level manipulation

**Access Control**
- Bridge ownership and admin key risks
- Pausing mechanism bypass under emergency
- Token mint/burn authority across chains

## Track Record

- LayerZero Stellar Endpoint (Code4rena, 01K USDC): 2 MEDIUM confirmed — deep analysis of Stellar OApp implementation, cross-chain message validation
