# Implementation Status

## Finished

- Workspace scaffolded as a multi-crate Solana/Rust repository for Vaulkyrie.
- `vaulkyrie-core` Pinocchio program initialized with stable account/state encoding and instruction parsing.
- Vault registry lifecycle implemented for active, locked, and recovery status transitions.
- Policy receipt staging, binding, nonce replay protection, and action-session coordination implemented onchain.
- Wallet authority checks implemented for signer and public-key alignment.
- PQC authority statement binding implemented with expiry, sequence, action hash, and next-authority commitments.
- WOTS+ proof verification implemented in the shared protocol crate.
- XMSS-style Merkle root verification and strict leaf-index consumption implemented for authority rotation.
- Staged authority-proof transport implemented to split large PQC proofs across chunk writes before onchain verification.
- `vaulkyrie-frost` DKG/TSS harness implemented for threshold Ed25519 signing with deterministic tests.
- Share refresh and retry-signing harness flows implemented for spend-layer recovery and orchestration testing.
- Solana signature conformance harness implemented over serialized legacy message bytes.
- Workspace lockfile kept compatible with both host cargo and `cargo-build-sbf`.
- Shared policy request and decision envelope encodings implemented in the protocol crate.
- `vaulkyrie-policy-mxe` scaffolded as a separate program crate with config, evaluation state, instruction parsing, and finalize/abort transitions.
- Blueshift-style quantum-vault `open`, `split`, and `close` instruction/data paths are implemented in `vaulkyrie-core`.
- Quantum-vault spend proofs are now message-bound to split/refund or refund-only recipients using the existing WOTS/XMSS proof type.
- **Phase D**: Spend orchestration state, instruction variants, and full lifecycle transitions (init → commit → complete/fail) implemented in `vaulkyrie-core`.
- **Phase E**: Arcium MXE computation-queue bridge added to `vaulkyrie-policy-mxe`:
  - `ComputationQueued = 4` status added to `PolicyEvaluationStatus`.
  - `queue_arcium_computation` transition and updated finalize/abort guards for `ComputationQueued` state.
  - `QueueArciumComputation` instruction variant (discriminator `4`) with 40-byte wire format (32-byte request commitment + u64 computation offset).
  - `process_queue_arcium_computation_data` handler in `vaulkyrie-policy-mxe` processor.
  - `arcium_cpi.rs` module with Arcium MXE CPI constants and `build_queue_computation_data()` helper (raw-byte CPI; actual Anchor CPI deferred until SDK version conflict is resolved).
  - `StageBridgedReceipt` instruction (discriminator `21`) added to `vaulkyrie-core`: cross-validates a finalized `PolicyEvaluationState` account via byte-level layout checks (`POLEVAL1` discriminator, `Finalized = 2` status, receipt commitment match) and stages the receipt to a `PolicyReceiptState` account.
  - `validate_bridged_receipt_claim` transition helper added to `vaulkyrie-core`.
  - `process_stage_bridged_receipt_data` processor helper added to `vaulkyrie-core`.
  - `crates/encrypted-ixs/` Arcis circuit scaffold created (excluded from workspace build; requires Arcis toolchain).

## Left To Do

- Add explicit spend-session state for offchain TSS orchestration metadata and failure recovery hints.
- Model reshare and rekey flows in onchain coordination state instead of treating rotation as a single-step authority action.
- Add staged policy-receipt transport if Arcium callback payloads exceed single-instruction limits.
- **Resolve Anchor/SDK version conflict** so `vaulkyrie-policy-mxe` can use actual Arcium Anchor CPI instead of raw-byte construction. (`arcium-anchor 0.9.6` needs `anchor-lang 0.32.1` which requires `solana-sdk ~2.2`, conflicting with workspace `solana-pubkey 4.x`.)
- Add the actual Arcium callback verification path and Anchor/MXE account wiring inside `vaulkyrie-policy-mxe`.
- Add PDA derivation/enforcement for the dedicated quantum-vault accounts so the runtime path matches the full Blueshift-style ownership model.
- Add PDA derivation helpers and client-side builders for vault, session, receipt, and proof accounts.
- Add integration tests that assemble real Solana transactions around the program instruction flows.
- Add end-to-end spend-plane tests that sign actual transaction messages and verify wallet-compatible key handling.
- Add PQC recovery and rollover flows for exhausted trees, authority migration, and dual-control admin actions.
- Add client/service crates for device coordination, DKG session management, and retry orchestration.
- Add observability/error surfaces for failed chunk staging, stale receipts, and aborted authority rotations.
- Define deployment/devnet scripts and local validator workflows for the full repo.
- Include `crates/encrypted-ixs` in the workspace once the Arcis Rust SDK is available and the dependency conflict is resolved.
