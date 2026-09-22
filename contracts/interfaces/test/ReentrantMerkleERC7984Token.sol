// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {MockERC7984Token} from "./MockERC7984Token.sol";

/// @title IReentrantMerkleClaim
/// @author TokenOps
/// @notice Minimal view of the Merkle claim entrypoint we re-enter. Dummy arguments suffice: the
///         `nonReentrant` guard runs before the identity guards, the window gate, the fee check and any
///         proof verification.
interface IReentrantMerkleClaim {
    /// @notice The Merkle claim entrypoint re-entered from within `confidentialTransfer`.
    /// @param account The claim identity keying the leaf and the claimed-amount accounting (0 => caller).
    /// @param to Redirect-only payout destination (0 => the resolved identity).
    /// @param inputAmount Encrypted cumulative-total handle.
    /// @param inputProof FHE input proof for `inputAmount`.
    /// @param merkleProof Merkle proof path for the identity's leaf.
    function claim(
        address account,
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external payable;
}

/// @title ReentrantMerkleERC7984Token
/// @author TokenOps
/// @notice Test-only ERC-7984 that attempts to re-enter `MerkleConfidentialAirdrop.claim` from inside
///         `confidentialTransfer` (the token move on the claim hot path). Used to confirm that the claim
///         entrypoint is guarded by `nonReentrant` and rejects the nested call, which is what keeps the
///         window between the payout and the claimed-amount write closed.
/// @dev The Merkle claim selector differs from the ECDSA one, so this is a distinct double rather than a
///      reuse of `ReentrantERC7984Token`: calling the ECDSA selector on a Merkle instance would revert
///      with empty returndata and record nothing distinguishable. The outer claim should SUCCEED while
///      the single nested `claim` attempt is blocked; the nested revert data (expected selector:
///      `ReentrancyGuardReentrantCall`) is recorded for assertion, then the real transfer proceeds via
///      `super`.
contract ReentrantMerkleERC7984Token is MockERC7984Token {
    /// @notice The airdrop instance whose `claim` we re-enter (set by the test after deploy).
    address public reentryTarget;

    /// @notice The claim identity the nested attempt passes as `account` (set by the test after deploy).
    address public reentryAccount;

    /// @notice The 4-byte selector captured from the nested `claim` revert (0x0 if it did not revert).
    bytes4 public innerRevertSelector;

    /// @notice True once a re-entrant `claim` attempt has fired, so we re-enter exactly once.
    bool private _reentered;

    // solhint-disable-next-line no-empty-blocks
    constructor(string memory name_, string memory symbol_) MockERC7984Token(name_, symbol_) {}

    /// @notice Point the token at the airdrop instance and claim identity to re-enter with.
    /// @param airdrop The `MerkleConfidentialAirdrop` instance exposing `claim`.
    /// @param account The claim identity the nested attempt submits for.
    function setReentryTarget(address airdrop, address account) external {
        reentryTarget = airdrop;
        reentryAccount = account;
    }

    /// @notice Re-enters `claim` once with dummy args, records the revert selector, then does the real transfer.
    /// @param to Transfer recipient (forwarded to the genuine ERC-7984 transfer).
    /// @param amount Encrypted amount (forwarded to the genuine ERC-7984 transfer).
    /// @return The encrypted amount actually moved by the underlying transfer.
    function confidentialTransfer(address to, euint64 amount) public override returns (euint64) {
        if (!_reentered && reentryTarget != address(0)) {
            _reentered = true;
            bytes32[] memory emptyProof = new bytes32[](0);
            try
                IReentrantMerkleClaim(reentryTarget).claim(
                    reentryAccount,
                    address(0),
                    externalEuint64.wrap(bytes32(0)),
                    "",
                    emptyProof
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
