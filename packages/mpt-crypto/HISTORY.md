# @xrplf/mpt-crypto Release History

Subscribe to [the **xrpl-announce** mailing list](https://groups.google.com/g/xrpl-announce) for release announcements. We recommend that `@xrplf/mpt-crypto` users stay up-to-date with the latest stable release.

## Unreleased

### Added

- Low-level XLS-96 proof components for the Confidential Lending Protocol: `getSendSigmaProof` / `verifySendSigmaProof` (the Send sigma proof over any recipients), `getConvertBackSigmaProof` / `verifyConvertBackSigmaProof`, `getAggregatedRangeProof` / `verifyAggregatedRangeProof`, `verifyClawbackProof`, and the blinding-factor arithmetic `subtractScalars` / `multiplyScalar`.
- `decryptAmount` takes an optional `rangeLow`, so a claimed amount can be checked in constant time.

### Changed

- The vendored WASM is an unreleased build that exports the low-level provers (see the README's "Confidential lending build").

## 0.1.1 (2026-08-20)

### Fixed

- Browser bundling: the Node ESM glue (`mpt_crypto.mjs`) contains a Node-only `await import("node:module")` that browser bundlers reject at build time. Added a `node:`-free browser glue (`mpt_crypto.web.mjs`), selected via the package's `browser` export condition, so bundlers (webpack, Vite, …) and browsers resolve a working module. The package now ships three WASM glues — CommonJS (Node `require`), ESM (Node `import`), and browser — chosen automatically per environment.

## 0.1.0 (2026-08-16)

### Added

- Initial release: Confidential MPT (XLS-0096) cryptographic primitives for the XRP Ledger — EC-ElGamal encryption, Pedersen commitments, per-transaction context hashes, and zero-knowledge proofs — exposed as a hex-in / hex-out TypeScript API over a vendored WebAssembly build of the reference [`XRPLF/mpt-crypto`](https://github.com/XRPLF/mpt-crypto) C library. Ships a CommonJS and an ES-module WASM glue for Node.
