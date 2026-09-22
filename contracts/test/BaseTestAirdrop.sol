// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {euint64} from "@fhevm/solidity/lib/FHE.sol";
import {ConfidentialAirdropBase} from "../airdrop/ConfidentialAirdropBase.sol";

/// @title BaseTestAirdrop
/// @author TokenOps
/// @notice TEST-ONLY concrete subclass of the abstract `ConfidentialAirdropBase`. Adds an external
///         `initialize(BaseInitParams)` plus thin public wrappers over the base internal helpers, so the
///         shared base surface gets first-class Hardhat coverage WITHOUT the ECDSA/Merkle claim paths.
///         Deploy it as a plain clone / ERC-1967 proxy (no immutable args — `gasFee` flows in through
///         `BaseInitParams` and is frozen into config storage by `initialize`; the impl constructor
///         disables initializers).
contract BaseTestAirdrop is ConfidentialAirdropBase {
    /// @notice Arbitrary type discriminator — the base carries no runtime type branch.
    uint8 public constant TEST_AIRDROP_TYPE = 0;

    /// @notice External initializer mirroring an impl's `initialize` (calls the shared base init).
    /// @param p The shared base init params (factory-shaped).
    function initialize(BaseInitParams calldata p) external initializer {
        __ConfidentialAirdropBase_init(p);
    }

    /// @inheritdoc ConfidentialAirdropBase
    function airdropType() public pure override returns (uint8) {
        return TEST_AIRDROP_TYPE;
    }

    /// @notice Test hook: the compliance-manager grant helper.
    /// @param h The handle to grant to the instance's compliance manager clone.
    function grantCompliance(euint64 h) external {
        _grantCompliance(h);
    }

    /// @notice Test hook: the shared plain-claim payout helper.
    /// @param beneficiary The payout destination.
    /// @param amount The already-held encrypted amount to transfer.
    /// @return moved The token-returned delivered-amount handle (compliance-granted by the helper).
    function transferTo(address beneficiary, euint64 amount) external returns (euint64 moved) {
        return _transferTo(beneficiary, amount);
    }

    /// @notice Test hook: the unwrap helper.
    /// @param to The unwrap beneficiary.
    /// @param amount The already-held encrypted amount to unwrap.
    /// @return reqId The wrapper's unwrap request id.
    function unwrapTo(address to, euint64 amount) external returns (bytes32 reqId) {
        return _unwrapTo(to, amount);
    }

    /// @notice Test hook: the deploy-time wrapper probe.
    /// @param token_ The candidate token.
    /// @return True iff `token_` looks like a genuine wrapper.
    function isWrapperToken(address token_) external view returns (bool) {
        return _isWrapperToken(token_);
    }

    /// @notice Test hook: the shared claim-window gate.
    function requireClaimWindowActive() external view {
        _requireClaimWindowActive();
    }
}
