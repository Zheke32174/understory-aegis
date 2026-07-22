
# Signing material boundary

No signing private key belongs in this public repository.

Local debug builds use the developer's normal Android debug identity. Such APKs
are untrusted development artifacts and do not authenticate Understory
authorship, siblings, or cross-app capabilities.

The former shared debug key is public and revoked for trust decisions. Trusted
distribution requires the offline release key documented in
`understory-common/docs/SIGNING.md`.
