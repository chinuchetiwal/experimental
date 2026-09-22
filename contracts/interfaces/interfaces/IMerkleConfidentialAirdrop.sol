// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {IConfidentialAirdropBase} from "./IConfidentialAirdropBase.sol";
import {IMerkleConfidentialAirdropTypes} from "./IMerkleConfidentialAirdropTypes.sol";

/**
 * @title IMerkleConfidentialAirdrop
 * @author TokenOps
 * @notice External surface of the Merkle airdrop implementation. Consumed by the factory's post-deploy
 *         `initialize` call and by claimers/integrators.
 * @dev `initialize(MerkleInitParams)` performs initialization. No EIP-712 domain. Verification
 *      is exclusively OZ `MerkleProof.verify` (sorted-pair, double-hashed leaf). Each leaf commits the
 *      recipient's CUMULATIVE total allocation (instance + recipient + ciphertext handle); a claim pays the
 *      outstanding difference over the recipient's delivered running total and advances that total by what
 *      was actually delivered — re-presenting a settled leaf nets to an encrypted-zero payout, and a root
 *      rotation publishes updated totals rather than replacement allocations. Every claim and preview
 *      names its claim identity explicitly through a mandatory, non-zero `account` parameter.
 */
interface IMerkleConfidentialAirdrop is IConfidentialAirdropBase, IMerkleConfidentialAirdropTypes {
    // ───────────────────────────── roles / root ────────────────────────────────────────────────────
    /// @notice Role id allowed to rotate the Merkle root.
    function MERKLE_ADMIN_ROLE() external view returns (bytes32);

    /// @notice The current Merkle root used to verify claim leaves.
    function merkleRoot() external view returns (bytes32);

    /// @notice Whether the Merkle root may be rotated.
    function isMerkleRootMutable() external view returns (bool);

    // ───────────────────────────── lifecycle ──────────────────────────────────────────────────────
    /// @notice Calls the shared base init with AirdropType.Merkle, sets the root +
    ///         mutability (revert ZeroMerkleRoot if !isMerkleRootMutable && root==0), grants MERKLE_ADMIN_ROLE.
    /// @param p Merkle init params (base config + root + mutability).
    function initialize(MerkleInitParams calldata p) external;

    /// @notice Rotate the root — allowed any time, any number of times, iff isMerkleRootMutable.
    ///         Reverts RootImmutable when immutable, ZeroMerkleRoot when newRoot == 0.
    /// @param newRoot The new Merkle root to set.
    function setMerkleRoot(bytes32 newRoot) external;

    // ───────────────────────────── claim ───────────────────────────────────────────────────────────
    /// @notice Claim the outstanding amount (committed cumulative total net of already delivered) against
    ///         the Merkle root; advances the account's delivered running total by what actually moved.
    /// @param account The account whose leaf and running total this claim is submitted for. Mandatory and
    ///        never defaulted from the caller: address(0) reverts ZeroAccount. Authorization (leaf) and the
    ///        claimed accounting are bound to this account, not necessarily the submitter. The FHE input
    ///        proof is bound by the coprocessor to (address(this), msg.sender), the literal caller, never
    ///        to `account`.
    /// @param to The payout destination for the claimed amount; pass address(0) to default to `account`.
    ///        Only the account itself may redirect to a different `to`: a third-party submitter must leave
    ///        `to` equal to `account` (or zero), else the call reverts UnauthorizedRedirect.
    /// @param inputAmount The encrypted cumulative-total amount input.
    /// @param inputProof The FHE input proof for inputAmount, bound to (address(this), msg.sender).
    /// @param merkleProof The Merkle proof for the account's leaf.
    function claim(
        address account,
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external payable;

    /// @notice Claim the outstanding amount then route it straight to the wrapper's unwrap (`to` = ERC-20
    ///         beneficiary). Reverts TokenNotUnwrappable on a non-unwrappable campaign, and
    ///         ZeroUnwrapRequestId if the wrapper returns the zero request id (the interface requires a
    ///         non-zero one, and the zero word names no handle to read the delivered amount from). Unlike `claim`, this
    ///         entrypoint takes no account parameter and is always submitted for the caller: converting a
    ///         confidential allocation into a plain, publicly visible ERC-20 transfer is the account's own
    ///         choice to make, not a third party's. The leaf, the running total and the FHE input proof are
    ///         therefore all bound to msg.sender. A third party may still submit a plain confidential
    ///         `claim` on the account's behalf. The running total advances by the amount the wrapper
    ///         reports burned for the request it returned, which is encrypted-zero when the pool could not
    ///         cover the payout; a reported amount this instance may not read reverts the whole claim.
    /// @param to The payout destination for the claimed amount; pass address(0) to default to msg.sender.
    ///        The caller is the account here, so any `to` is a self-redirect and none is rejected.
    /// @param inputAmount The encrypted cumulative-total amount input.
    /// @param inputProof The FHE input proof for inputAmount, bound to (address(this), msg.sender).
    /// @param merkleProof The Merkle proof for the caller's leaf.
    function claimAndUnwrap(
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external payable;

    // ───────────────────────────── preview / views ─────────────────────────────────────────────────
    /// @notice Preview/ACL-grant path: no fee, writes NO accounting. Grants the account + compliance ACL.
    /// @param account The account whose leaf and running total this preview is computed for. Mandatory and
    ///        never defaulted from the caller: address(0) reverts ZeroAccount.
    /// @param inputAmount The encrypted cumulative-total amount input.
    /// @param inputProof The FHE input proof for inputAmount.
    /// @param merkleProof The Merkle proof for the account's leaf.
    /// @return amount The encrypted OUTSTANDING amount handle (committed total net of already delivered).
    function getClaimAmount(
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external returns (euint64 amount);

    /// @notice The account's encrypted delivered running total (zero-handle before its first settled claim).
    /// @param account The account whose cumulative delivered total to read.
    function getClaimedAmount(address account) external view returns (euint64);
}
