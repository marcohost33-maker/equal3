# Equal3 v0.7.11 — CodeFactory / assurance transfer

Reusable rules (design only; not pushed or integrated into other repos):
1. Prefer negative-first tests for unsigned caller-controlled 'approvals', duplicate JSON keys, other-deployment signed documents, unsigned zip source, manipulated artifact bytes, mismatched effective dynamic library.
2. Hermetic/offline build recipe: exact official archive name, official SHA3-256, inner C source hash/source ID, isolated non-existing build destination; fresh runtime smoke mapping, NO_GO until external attestation.
3. Evidence levels: self-consistent checksum < cryptographically signed declared policy < trust-root/admin isolation < live release/DR under adverse fault injection. Never auto-promote from unit test counts.
4. Host runtime inventory: hash O_NOFOLLOW file descriptor matching executable mapped file's dev/inode, not just Python extension path.
5. Measured overhead is only synthetic signed-policy CPU cost, not a database benchmark. Do not aggregate or imply speedup.
