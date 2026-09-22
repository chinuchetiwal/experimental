// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {MockERC7984Token} from "./MockERC7984Token.sol";

/// @title IReentrantDisclosureTarget
/// @author TokenOps
/// @notice The two airdrop entrypoints this token re-enters: the raw-handle disclosure surface and the
///         fee-free preview. Neither carries the reentrancy guard, so both are genuinely reachable from
///         inside the token move on the claim hot path.
interface IReentrantDisclosureTarget {
    /// @notice Two-gate raw-handle disclosure.
    /// @param handle The handle to disclose.
    /// @param party The address to grant.
    function discloseHandleToParty(euint64 handle, address party) external;

    /// @notice Fee-free preview of an account's outstanding amount.
    /// @param account The claim identity.
    /// @param inputAmount Encrypted cumulative-total handle.
    /// @param inputProof FHE input proof for `inputAmount`.
    /// @param merkleProof Merkle proof path for the identity's leaf.
    /// @return The outstanding-amount handle.
    function getClaimAmount(
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external returns (euint64);
}

/**
 * @title ReentrantDisclosureERC7984Token
 * @author TokenOps
 * @notice Test-only ERC-7984 that re-enters the airdrop from inside `confidentialTransfer`, i.e. at the
 *         exact moment the airdrop instance holds a live transient ACL allowance on the encrypted input it
 *         verified earlier in the same transaction. It attempts two things and records the outcome of each
 *         rather than reverting: a raw-handle disclosure to an arbitrary party - of a pre-named handle, or of
 *         the very handle the transfer is handed - and a nested fee-free preview.
 * @dev The point of this double is that the claim entrypoints are `nonReentrant` but the disclosure surface
 *      and the preview are NOT, so the guard cannot be what stops a reentrant disclosure. Whatever stops it
 *      has to be the disclosure surface's own gates.
 */
contract ReentrantDisclosureERC7984Token is MockERC7984Token {
    /// @notice The airdrop instance re-entered from inside the transfer.
    address public reentryTarget;

    /// @notice The handle the nested disclosure attempt tries to disclose (the verified encrypted input).
    euint64 public disclosureHandle;

    /// @notice When true the nested disclosure names the handle the transfer is HANDED instead of
    ///         `disclosureHandle` - the one the airdrop just lent this token a transient allowance on.
    bool public discloseLiveAmount;

    /// @notice The handle the nested disclosure attempt actually named.
    euint64 public attemptedHandle;

    /// @notice The address the nested disclosure attempt names as the grantee.
    address public disclosureParty;

    /// @notice Claim identity the nested preview attempt submits for.
    address public previewAccount;

    /// @notice Encrypted cumulative-total handle for the nested preview attempt.
    externalEuint64 public previewAmount;

    /// @notice Input proof for the nested preview attempt.
    bytes public previewProof;

    /// @notice Merkle proof path for the nested preview attempt.
    bytes32[] public previewMerkleProof;

    /// @notice Selector captured from the nested disclosure attempt (0x0 if it SUCCEEDED).
    bytes4 public discloseRevertSelector;

    /// @notice True once the nested disclosure attempt has run.
    bool public discloseAttempted;

    /// @notice Selector captured from the nested preview attempt (0x0 if it SUCCEEDED).
    bytes4 public previewRevertSelector;

    /// @notice True once the nested preview attempt has run.
    bool public previewAttempted;

    /// @notice The outstanding handle the nested preview returned, if it succeeded.
    euint64 public previewResult;

    /// @notice True once a re-entrant sequence has fired, so it runs exactly once.
    bool private _reentered;

    // solhint-disable-next-line no-empty-blocks
    constructor(string memory name_, string memory symbol_) MockERC7984Token(name_, symbol_) {}

    /// @notice Arm the nested disclosure attempt.
    /// @param airdrop The airdrop instance to re-enter.
    /// @param handle The handle to attempt to disclose.
    /// @param party The grantee the nested disclosure names.
    function armDisclosure(address airdrop, euint64 handle, address party) external {
        reentryTarget = airdrop;
        disclosureHandle = handle;
        disclosureParty = party;
        discloseLiveAmount = false;
    }

    /// @notice Arm the nested disclosure against the handle the airdrop lends this token for the transfer.
    /// @dev The derived handles an implementation computes on its claim path (the Merkle outstanding amount)
    ///      are not known off-chain, so they can only be named from inside the transfer that receives them.
    /// @param airdrop The airdrop instance to re-enter.
    /// @param party The grantee the nested disclosure names.
    function armLiveDisclosure(address airdrop, address party) external {
        reentryTarget = airdrop;
        disclosureParty = party;
        discloseLiveAmount = true;
    }

    /// @notice Arm the nested preview attempt.
    /// @param account The claim identity to preview.
    /// @param inputAmount Encrypted cumulative-total handle.
    /// @param inputProof FHE input proof for `inputAmount`.
    /// @param merkleProof Merkle proof path for the identity's leaf.
    function armPreview(
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external {
        previewAccount = account;
        previewAmount = inputAmount;
        previewProof = inputProof;
        previewMerkleProof = merkleProof;
    }

    /// @notice Re-enters the disclosure surface and the preview once each, records both, then transfers.
    /// @param to Transfer recipient (forwarded to the genuine ERC-7984 transfer).
    /// @param amount Encrypted amount (forwarded to the genuine ERC-7984 transfer).
    /// @return The encrypted amount actually moved by the underlying transfer.
    function confidentialTransfer(address to, euint64 amount) public override returns (euint64) {
        if (!_reentered && reentryTarget != address(0)) {
            _reentered = true;
            if (disclosureParty != address(0)) {
                discloseAttempted = true;
                attemptedHandle = discloseLiveAmount ? amount : disclosureHandle;
                try IReentrantDisclosureTarget(reentryTarget).discloseHandleToParty(attemptedHandle, disclosureParty) {
                    discloseRevertSelector = bytes4(0);
                } catch (bytes memory reason) {
                    discloseRevertSelector = _selectorOf(reason);
                }
            }
            if (previewAccount != address(0)) {
                previewAttempted = true;
                try
                    IReentrantDisclosureTarget(reentryTarget).getClaimAmount(
                        previewAccount,
                        previewAmount,
                        previewProof,
                        previewMerkleProof
                    )
                returns (euint64 outstanding) {
                    previewRevertSelector = bytes4(0);
                    previewResult = outstanding;
                } catch (bytes memory reason) {
                    previewRevertSelector = _selectorOf(reason);
                }
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
