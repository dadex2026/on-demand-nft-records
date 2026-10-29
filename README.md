# on-demand-nft records

Public records for the on-demand NFT project: published configs and their
fingerprints, daily commitments and reveals, and contest records.

Every clone must enable the guard before pushing:
`git config core.hooksPath .githooks` (it runs `tools/guard.py` on each push).

## Verifier page

`verifier/index.html` checks a card against these records in a browser,
opened as a file. Download it and compare its SHA-256 (`sha256sum index.html`,
or `Get-FileHash -Algorithm SHA256 index.html` on Windows) with the line for
its date; old lines stay when the page is rebuilt. Until the first config is
published, it says it cannot verify.

- 29 October 2026: `3f0a860068c385a486dd71743be97dd7cc3545f346255d6ae41eb141ce0b9049`,
  built from on-demand-nft commit `0e1ae22`.
