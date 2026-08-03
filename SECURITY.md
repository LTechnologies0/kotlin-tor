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
