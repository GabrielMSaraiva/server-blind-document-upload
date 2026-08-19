# Security Policy

## Supported scope

This repository is a local educational demo. Do not deploy it as a production document service without completing hardening listed in README.

## Threat model

Primary goal: application API and object store never receive plaintext document bytes or usable private keys.

Project addresses:

- accidental plaintext upload;
- simple MIME spoofing;
- upload-token disclosure after storage;
- token replay;
- metadata/object digest mismatch;
- storage-key and tenant-scope substitution;
- ciphertext modification before local decryption.

Project does not address:

- compromised browser or malicious extension;
- plaintext exfiltration before encryption or after decryption;
- traffic analysis and metadata privacy;
- malicious files opened after decryption;
- authenticated multi-tenant authorization;
- denial of service;
- cryptographic side-channel analysis;
- durable key recovery or rotation.

## Reporting

Open a private GitHub security advisory for vulnerabilities. Do not attach real documents, keys, credentials, or personal data.
