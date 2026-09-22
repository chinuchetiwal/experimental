// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {ECDSAConfidentialAirdrop} from "../airdrop/ECDSAConfidentialAirdrop.sol";

/// @title ECDSATestAirdrop
/// @author TokenOps
/// @notice TEST-ONLY subclass of `ECDSAConfidentialAirdrop` that exposes the internal replay-guard helpers
///         so they get first-class white-box Hardhat coverage. The production claim path runs the primary
///         dedup BEFORE the defense-in-depth digest guard, and the dedup key is always a subset of the
///         digest preimage — so `_consumeDigest` is structurally shadowed and `SignatureAlreadyUsed` is not
///         reachable as a first revert through `claim`. These thin hooks let the suite drive `_consumeDigest`
///         / `_consumeDedup` / `_claimKey` directly (and makes a dropped consume mutation-detectable).
/// @dev Deploy it exactly like the real impl — a clone/proxy with the 32-byte `gasFee` arg appended — then
///      `initialize(ECDSAInitParams)`. Adds no production behavior; only public passthroughs.
contract ECDSATestAirdrop is ECDSAConfidentialAirdrop {
    /// @notice Test hook: the primary dedup consume.
    /// @param recipient The claim recipient.
    /// @param dedupId The off-chain claim id.
    function consumeDedup(address recipient, bytes32 dedupId) external {
        _consumeDedup(recipient, dedupId);
    }

    /// @notice Test hook: the defense-in-depth digest consume.
    /// @param digest The EIP-712 claim digest to consume.
    function consumeDigest(bytes32 digest) external {
        _consumeDigest(digest);
    }

    /// @notice Test hook: read the defense-in-depth `usedClaimDigest` slot directly, so a
    ///         white-box test can prove the non-consuming preview (`getClaimAmount`) leaves the digest UNSET
    ///         ("preview consumes NOTHING"). A pure view; adds no production behavior.
    /// @param digest The EIP-712 claim digest to inspect.
    /// @return True iff the digest has been consumed via `_consumeDigest`.
    function usedDigest(bytes32 digest) external view returns (bool) {
        return _getECDSAStorage().usedClaimDigest[digest];
    }

    /// @notice Test hook: the dedup-aware event key.
    /// @param recipient The claim recipient.
    /// @param dedupId The off-chain claim id.
    /// @return The claim event key.
    function claimKey(address recipient, bytes32 dedupId) external view returns (bytes32) {
        return _claimKey(recipient, dedupId);
    }
}
