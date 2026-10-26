# Equal3 v0.7.13 – Compliance and security-matrix transfer (proposed, not applied)

- EQ0713-01 SQLITE_RUNTIME: OPEN/P0 – still linked to SQLite 3.46.1; upstream patched
  source/build and signed runtime policy missing in actual writer startup.
- EQ0713-02 DELETE_EXTRA: RESEARCH/PARTIAL – synthetically tested rollback journal
  is opt-in, not an OS-enforced universal security boundary.
- EQ0713-03 MIGRATION: OPEN/P0 – refuse unsafe automatic conversion, require exclusive
  maintenance, source receipt integrity, authenticated provenance, external anchor.
- EQ0713-04 KEY_MANAGEMENT: OPEN/P0 – independent cryptographic key domain and rotation.
- EQ0713-05 DATA_PROTECTION: OPEN/P0 – plaintext DB/journal/backup/temporary state;
  plan Swiss DSG/DSFA depending on actual data, role and processing purpose.
- EQ0713-06 VFS_FAULT: OPEN/P0 – process-abort tests ≠ physical power-loss/torn sectors.
- EQ0713-07 DEPLOYMENT: OPEN/P0 – no enforced privilege separated writer service.

No real user data used. These are proposed matrix entries, NOT evidence that the
central Compliance Matrix was updated. Independent security/legal approval pending.
