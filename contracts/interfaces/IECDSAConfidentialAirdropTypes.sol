// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {IConfidentialAirdropTypes} from "./IConfidentialAirdropTypes.sol";

/**
 * @title IECDSAConfidentialAirdropTypes
 * @author TokenOps
 * @notice ECDSA-variant-only enums, init-params and errors. Kept separate from the shared
 *         `IConfidentialAirdropTypes` so the Merkle impl never inherits ECDSA-specific types.
 * @dev Inherits the base type bag for `BaseInitParams`. Inherited by `ConfidentialAirdropECDSAStorage`,
 *      `ECDSAConfidentialAirdrop` and (via `IECDSAConfidentialAirdrop`) by ECDSA integrators.
 */
interface IECDSAConfidentialAirdropTypes is IConfidentialAirdropTypes {
    /// @notice ECDSA dedup policy, set once at init: "same address and/or same dedupId claims once", or
    ///         `None` to disable both dedup dimensions and rely solely on the consumed EIP-712 digest.
    enum DedupMode {
        PerAddress,
        PerDedupId,
        Both,
        None
    }

    /// @notice Which replay guard, if any, has already been consumed for a claim under the frozen `DedupMode`.
    ///         Used only by the implementation's internal views; the member order is the consuming path's
    ///         revert order: the mode-specific dedup slot(s) first, the EIP-712 digest second.
    enum ReplayStatus {
        NotConsumed,
        AddressConsumed,
        DedupIdConsumed,
        DigestConsumed
    }

    /// @dev Split init struct: the factory injects `base.admin`/`base.complianceManager`/
    ///      `base.feeCollector`/`base.gasFee` and the campaign sets `signer` + `dedupMode`.
    struct ECDSAInitParams {
        BaseInitParams base;
        address signer;
        DedupMode dedupMode;
    }

    // ──────────────────────────────────────────── errors ──────────────────────────────────────────
    error ZeroSigner(); //             init: signer == 0
    /// @notice The signature's `deadline` has passed — DISTINCT from InvalidSignature().
    /// @param deadline The expiry timestamp the signature was bound to.
    /// @param currentTime The block timestamp that exceeded it.
    error SignatureExpired(uint256 deadline, uint256 currentTime);
    error InvalidSignature(); //       recovered signer lacks SIGNER_ROLE
    error AddressAlreadyClaimed(); //  PerAddress/Both dedup slot already consumed
    error DedupIdAlreadyClaimed(); //  PerDedupId/Both dedup slot already consumed
    /// @notice Defense-in-depth guard under `PerAddress`/`PerDedupId`/`Both`: the EIP-712 claim digest was
    ///         already consumed. Primary replay protection is still address/dedupId dedup + the EIP-712
    ///         domain + `deadline`; this consumed-digest guard is a deliberately conservative extra net.
    ///         Under `DedupMode.None` there is no dedup dimension at all, so this becomes the PRIMARY (and
    ///         only) per-signature replay stop: the exact same signature can never be replayed, but the
    ///         signer can still authorize the same claimant repeatedly with a fresh signature (a new
    ///         `deadline`/`dedupId` produces a new digest).
    error SignatureAlreadyUsed();
}
