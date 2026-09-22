// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {MockERC7984Token} from "./MockERC7984Token.sol";

/// @title IReentrantClaim
/// @author TokenOps
/// @notice Minimal view of the ECDSA claim entrypoint we re-enter (dummy args suffice — the
///         `nonReentrant` guard runs before any window/fee/signature validation).
interface IReentrantClaim {
    /// @notice The ECDSA claim entrypoint re-entered from within `confidentialTransfer`.
    /// @param to Redirect-only payout destination (0 ⇒ msg.sender).
    /// @param inputAmount Encrypted claim amount handle.
    /// @param inputProof FHE input proof for `inputAmount`.
    /// @param dedupId Off-chain allocation identifier bound into dedup + the digest.
    /// @param deadline Signature expiry timestamp.
    /// @param signer The authorizing signer (SIGNER_ROLE holder).
    /// @param signature EIP-712 authorization signature.
    function claim(
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) external payable;
}

/// @title ReentrantERC7984Token
/// @author TokenOps
/// @notice Test-only ERC-7984 that attempts to re-enter `ECDSAConfidentialAirdrop.claim` from inside
///         `confidentialTransfer` (the token move on the claim hot path). Used to confirm that the claim
///         entrypoint is guarded by `nonReentrant` (ReentrancyGuardTransient) and rejects the nested call.
/// @dev The outer claim should SUCCEED while the single nested `claim` attempt is blocked. The nested
///      revert data (expected selector: `ReentrancyGuardReentrantCall`) is recorded for assertion; the
///      real transfer then proceeds via `super`.
contract ReentrantERC7984Token is MockERC7984Token {
    /// @notice The airdrop instance whose `claim` we re-enter (set by the test after deploy).
    address public reentryTarget;

    /// @notice The 4-byte selector captured from the nested `claim` revert (0x0 if it did not revert).
    bytes4 public innerRevertSelector;

    /// @notice True once a re-entrant `claim` attempt has fired, so we re-enter exactly once.
    bool private _reentered;

    // solhint-disable-next-line no-empty-blocks
    constructor(string memory name_, string memory symbol_) MockERC7984Token(name_, symbol_) {}

    /// @notice Point the token at the airdrop instance to re-enter on the next transfer.
    /// @param airdrop The `ECDSAConfidentialAirdrop` instance exposing `claim`.
    function setReentryTarget(address airdrop) external {
        reentryTarget = airdrop;
    }

    /// @notice Re-enters `claim` once with dummy args, records the revert selector, then does the real transfer.
    /// @param to Transfer recipient (forwarded to the genuine ERC-7984 transfer).
    /// @param amount Encrypted amount (forwarded to the genuine ERC-7984 transfer).
    /// @return The encrypted amount actually moved by the underlying transfer.
    function confidentialTransfer(address to, euint64 amount) public override returns (euint64) {
        if (!_reentered && reentryTarget != address(0)) {
            _reentered = true;
            try
                IReentrantClaim(reentryTarget).claim(
                    address(0),
                    externalEuint64.wrap(bytes32(0)),
                    "",
                    bytes32(0),
                    0,
                    address(0),
                    ""
                )
            {
                innerRevertSelector = bytes4(0);
            } catch (bytes memory reason) {
                innerRevertSelector = _selectorOf(reason);
            }
        }
        return super.confidentialTransfer(to, amount);
    }

    /// @notice Extract the leading 4-byte selector from raw revert-return data (0x0 if too short).
    /// @param reason The raw bytes captured in a low-level `catch (bytes memory reason)`.
    /// @return sel The first 4 bytes of `reason`, or `bytes4(0)` if `reason` is shorter than 4 bytes.
    function _selectorOf(bytes memory reason) private pure returns (bytes4 sel) {
        if (reason.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            sel := mload(add(reason, 0x20))
        }
    }
}
