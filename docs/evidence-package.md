# Portable evidence packages

An authenticated case reader can download
`GET /api/v1/cases/{case_id}/samples/{sample_id}/reports/{report_id}/export/package`.
The ZIP contains exactly `report.json`, `reviews.json`, and `manifest.json`.
It preserves report bytes and review references; it does not include original
APKs or all raw capture sources. Export is limited to 24 MiB.

Verify without extracting:

```powershell
python -m godeep.reporting.evidence_package verify --package report.zip
```

Unsigned verification establishes internal consistency, not authenticity.
For offline signing, set `GODEEP_SIGNING_PASSPHRASE` privately to at least 16 bytes,
then use a new directory outside the repository:

```powershell
python -m godeep.reporting.evidence_package keygen --directory PRIVATE_DIRECTORY
python -m godeep.reporting.evidence_package sign --package report.zip --private-key PRIVATE_DIRECTORY/private.pem --output report.signature.json --signer "Investigator label"
python -m godeep.reporting.evidence_package verify --package report.zip --signature report.signature.json --trusted-public-key PRIVATE_DIRECTORY/public.pem
```

Outputs are exclusive: existing files are not overwritten. Private keys use
encrypted PKCS8 PEM; signatures use Ed25519. The directory requests Unix mode
0700; on Windows, operators must configure and verify directory ACLs. Keep keys
and passphrases outside version control, restrict access, and establish backup,
rotation and revocation procedures. Distribute the trusted public key through an
independent authenticated channel; do not trust a key merely because it arrived
with a package.

A signature proves possession of the pinned private key and binds package bytes
and signer metadata. The signer label is self-asserted. It does not establish
legal identity, a trusted timestamp, institutional approval, or the correctness
of a malware conclusion. Existing report coverage limitations still apply.
