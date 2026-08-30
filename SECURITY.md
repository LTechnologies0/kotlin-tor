# Security Policy

kotlin-tor is an experimental Tor engine. Until a formal audit and a non-SNAPSHOT release:

- Do **not** rely on it for high-risk anonymity.
- Prefer **C Tor** or **Arti** for production.
- Report issues privately if they are wire-protocol or crypto bugs.

## Hard rules

1. No silent clearnet fallback.
2. DNS for SOCKS must use hostname BEGIN (SOCKS5H), never local resolve-then-CONNECT-to-IP for anonymity use.
3. Control/SOCKS listeners default to localhost.
4. Never log cookies, bridge lines, or private keys (SafeLogging).
5. Wipe key material where practical (`secureWipe`).
6. Circuit SENDME credit requires authenticated digest check (`Sendme.isValid`) when v1 payloads are present.
7. Link variable cells are capped (`Cell.MAX_VAR_CELL_PAYLOAD`); oversize closes the link.
8. TUN userspace stack drops IP fragments and ICMP non-echo (no reassembly / no redirect handling).
9. Path country/continent/recent-hop filters are **client-local** only (`EnforceDistinctCountries`,
   `EnforceDistinctContinents`, `CircuitAvoidRecentHops`); they must not alter consensus documents
   or CREATE/EXTEND wire formats.
