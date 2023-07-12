# KeyAttestation
Key Management for OffChain Attestations.

The purpose of this project is provide a flexible way to authenticate off-chain attestations to be used for any purpose eg ticket attestations for Events, minting NFTs with attestation, interacting with external services and so on.

The simplest form of off-chain authentication is to hard code a public key into all services that require the attestation. When you have a closed system this is a reasonable solution. However, once 3rd parties become involved which hold signing keys, and derivative keys are required this quickly becomes unmanagable especially when these keys are being using in services and in smart contracts - esp if new keys are required to be issued.

This KeyChain attestation system uses the EAS attestation format and infrastructure with a custom resolver to create an easy to setup and use keychain system that resolves keys as NFTs and allows you to see keys or even manage them from your wallet if it supports the TokenScript standard.



## Run tests

```> cd contracts```

```> npm install```

```> npm test```

