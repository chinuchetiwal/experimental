// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {IConfidentialAirdropTypes} from "./IConfidentialAirdropTypes.sol";

/**
 * @title IMerkleConfidentialAirdropTypes
 * @author TokenOps
 * @notice Merkle-variant-only init-params, events and errors, kept separate from the shared
 *         `IConfidentialAirdropTypes` so the ECDSA implementation never inherits Merkle-only types.
 * @dev Inherits the shared types for `BaseInitParams`. Inherited by `ConfidentialAirdropMerkleStorage`,
 *      `MerkleConfidentialAirdrop` and (via `IMerkleConfidentialAirdrop`) by Merkle integrators.
 */
interface IMerkleConfidentialAirdropTypes is IConfidentialAirdropTypes {
    /// @dev Init struct where the factory injects the `base.*` fields and the campaign sets the
    ///      commitment `merkleRoot` plus its `isMerkleRootMutable` flag.
    struct MerkleInitParams {
        BaseInitParams base;
        bytes32 merkleRoot;
        bool isMerkleRootMutable;
    }

    // ─────────────────────────────────────────── events ──────────────────────────────────────────
    /// @notice Emitted on each Merkle root rotation.
    /// @param oldRoot The previous Merkle root.
    /// @param newRoot The newly set Merkle root.
    event MerkleRootSet(bytes32 indexed oldRoot, bytes32 indexed newRoot); // emitted on each rotation

    // ──────────────────────────────────────────── errors ──────────────────────────────────────────
    error ZeroMerkleRoot(); //     init when !isMerkleRootMutable && root==0; rotation to 0
    /// @notice OZ MerkleProof.verify rejected the (leaf, proof) pair against the CURRENT root.
    /// @dev Carries the rejecting root so a claimer holding a proof built against a since-rotated root can
    ///      see the drift directly from the revert instead of re-querying `merkleRoot()`.
    /// @param leaf The computed leaf that failed verification.
    /// @param merkleRoot The current on-chain root the proof was checked against.
    error InvalidMerkleProof(bytes32 leaf, bytes32 merkleRoot);
    error RootImmutable(); //      setMerkleRoot when !isMerkleRootMutable
    /// @notice A claim entrypoint was called with `account == address(0)`.
    /// @dev The claim identity is always explicit and is never defaulted from the caller, so the address the
    ///      leaf and the claimed-amount accounting are keyed on is always the address the caller named.
    error ZeroAccount();
    /// @notice A caller tried to redirect payout to a different beneficiary on behalf of another account.
    /// @dev Only the account itself may redirect its own payout; a third-party submitter must leave `to`
    ///      equal to `account` (or zero, which defaults to `account`).
    /// @param account The account whose claim was being submitted.
    /// @param to The disallowed payout destination.
    error UnauthorizedRedirect(address account, address to);
}
