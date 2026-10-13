# Security

API Vault keeps all data on your computer. The vault file is encrypted with ChaCha20-Poly1305; the key comes from your PIN/password via Argon2id.
In "No lock" mode the key is stored next to the vault (`vault.key`), so it only protects against casual browsing of the file, not against someone with access to your account.
Forgotten PIN/password = data cannot be recovered. Use a long password rather than a short PIN if the vault matters.

Found a vulnerability? Please open a private security advisory on GitHub (Security tab) instead of a public issue.
