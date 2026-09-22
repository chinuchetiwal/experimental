// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {FHE, euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
// Reached directly in `_verifyInputAmount`; the reasoning for not using `FHE.fromExternal` is there.
import {Impl, IFHEVMExecutor, CoprocessorConfig} from "@fhevm/solidity/lib/Impl.sol";
import {FheType} from "@fhevm/solidity/lib/FheType.sol";

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {ConfidentialAirdropBase} from "./ConfidentialAirdropBase.sol";
import {ConfidentialAirdropMerkleStorage} from "../storage/ConfidentialAirdropMerkleStorage.sol";
import {IMerkleConfidentialAirdrop} from "../interfaces/IMerkleConfidentialAirdrop.sol";
// `unwrapAmount(reqId)` on the unwrap path: the wrapper's own handle for the amount the burn took.
import {IERC7984ERC20Wrapper} from "../interfaces/IERC7984ERC20Wrapper.sol";
// Referenced only in `airdropType()`'s override specifier — `airdropType` is declared in both this and
// `ConfidentialAirdropBase`, so Solidity requires both to be named explicitly.
import {IConfidentialAirdropBase} from "../interfaces/IConfidentialAirdropBase.sol";

/**
 * @title MerkleConfidentialAirdrop
 * @author TokenOps
 * @notice Confidential airdrop whose claims are authorized by a Merkle inclusion proof against a published
 *         root. Each leaf binds this instance, a recipient and the exact encrypted handle of the recipient's
 *         CUMULATIVE total allocation; a claim pays out the outstanding difference between that committed
 *         total and what was already delivered to the recipient, and records the delivered amount against
 *         the recipient's running total. Rotating the root (mutable campaigns) publishes updated totals that
 *         top prior ones up rather than replacing them, so value already paid is netted out at claim time
 *         and a rotation can never re-open it. `claim` and `getClaimAmount` take a mandatory, non-zero
 *         `account` that keys the leaf and the accounting, so anyone may submit a claim on that account's
 *         behalf; `to` redirects delivery only, and only the account itself may point it elsewhere.
 *         `claimAndUnwrap` takes no `account`: releasing an allocation as a public ERC-20 transfer is the
 *         recipient's own choice, so its identity is always the caller. The FHE input proof is bound by the
 *         coprocessor to the caller at the point of verification, never to `account`.
 * @dev Concrete implementation #2 over the shared `ConfidentialAirdropBase`, deployable as a minimal-proxy
 *      clone or a UUPS proxy. It has no EIP-712 domain — authorization is inclusion in the tree, not a
 *      signature. All proof verification is OpenZeppelin `MerkleProof.verify` (sorted-pair, double-hashed
 *      leaf, the standard OpenZeppelin merkle-tree library output); the only first-party cryptographic input
 *      is the leaf preimage. The root is committed at initialization and, when the campaign is created
 *      mutable, may be rotated any number of times by `MERKLE_ADMIN_ROLE`.
 *
 *      There is no per-leaf consumption: replay safety is the accounting itself. Re-presenting an
 *      already-settled leaf computes an encrypted-zero outstanding amount and pays nothing (the exact gas
 *      fee is still charged — the amounts are encrypted, so a zero-outstanding claim cannot be detected or
 *      rejected on-chain). The accounting advances by the amount actually DELIVERED, so a payout the token
 *      clamped to encrypted-0 (under-funded pool) leaves the entitlement intact and the claim can simply be
 *      retried once the pool is funded. A total rotated below what an account already received clamps that
 *      account's outstanding amount to encrypted-0 — it never underflows and never claws anything back.
 *
 *      Verifying an encrypted input grants the submitter NO ACL allowance on the result.
 *      `_verifyInputAmount` is the single place that reaches the coprocessor and carries the reasoning; the
 *      consequence is that a submitter never holds an allowance on the amount it submits, so it can neither
 *      read that amount nor make it public, and a proof it was handed rather than generated stays opaque to
 *      it. The proof binding itself is unchanged: an input is created against this instance and its
 *      submitter.
 *
 *      The claim hot path performs one FHE input verification, one `min`, one `sub` and one `add` on both
 *      the transfer and the unwrap path, together with the ACL writes and one token transfer or unwrap.
 */
contract MerkleConfidentialAirdrop is
    IMerkleConfidentialAirdrop,
    ConfidentialAirdropBase,
    ConfidentialAirdropMerkleStorage
{
    // ───────────────────────────── role ────────────────────────────────────────────────────────────
    /// @inheritdoc IMerkleConfidentialAirdrop
    bytes32 public constant override MERKLE_ADMIN_ROLE = keccak256("MERKLE_ADMIN_ROLE");

    // ───────────────────────────────────── initialization ─────────────────────────────────────────
    /// @inheritdoc IConfidentialAirdropBase
    function airdropType() public pure override(ConfidentialAirdropBase, IConfidentialAirdropBase) returns (uint8) {
        return uint8(AirdropType.Merkle);
    }

    /// @inheritdoc IMerkleConfidentialAirdrop
    function initialize(MerkleInitParams calldata p) external override initializer {
        // Shared base init runs first (validates config, wires the coprocessor, grants the admin roles).
        __ConfidentialAirdropBase_init(p.base);
        MerkleStorage storage m = _getMerkleStorage();
        // An immutable campaign MUST commit a non-zero root now (a zero root would brick every claim with no
        // way to fix it). A mutable campaign MAY initialize with a zero root and publish later — that first
        // publication is simply the first rotation.
        if (!p.isMerkleRootMutable && p.merkleRoot == bytes32(0)) revert ZeroMerkleRoot();
        m.merkleRoot = p.merkleRoot;
        m.isMerkleRootMutable = p.isMerkleRootMutable;
        // MERKLE_ADMIN_ROLE is administered by DEFAULT_ADMIN_ROLE (the factory-injected admin), so it can be
        // rotated post-deploy without a dedicated role admin.
        _grantRole(MERKLE_ADMIN_ROLE, p.base.admin);
    }

    // ───────────────────────────── root management ────────────────────────────────────────────────
    /// @inheritdoc IMerkleConfidentialAirdrop
    function merkleRoot() external view override returns (bytes32) {
        return _getMerkleStorage().merkleRoot;
    }

    /// @inheritdoc IMerkleConfidentialAirdrop
    function isMerkleRootMutable() external view override returns (bool) {
        return _getMerkleStorage().isMerkleRootMutable;
    }

    /// @inheritdoc IMerkleConfidentialAirdrop
    function setMerkleRoot(bytes32 newRoot) external override onlyRole(MERKLE_ADMIN_ROLE) {
        MerkleStorage storage m = _getMerkleStorage();
        // On an immutable campaign the function always reverts, so its mere existence is not a footgun.
        if (!m.isMerkleRootMutable) revert RootImmutable();
        // Rotating to the empty root would silently brick all claims; pausing is the intended stop-claims tool.
        if (newRoot == bytes32(0)) revert ZeroMerkleRoot();
        bytes32 oldRoot = m.merkleRoot;
        m.merkleRoot = newRoot;
        // Value already paid stays paid: the new tree's leaves commit UPDATED cumulative totals, and each
        // account's delivered running total (`claimedAmount`, keyed by account, not by root) is netted out
        // of every future claim.
        emit MerkleRootSet(oldRoot, newRoot);
    }

    // ───────────────────────────────────────── claim ───────────────────────────────────────────────
    /// @inheritdoc IMerkleConfidentialAirdrop
    function claim(
        address account,
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external payable override nonReentrant {
        // The claim identity is mandatory and explicit: it decides which leaf authorizes the claim and whose
        // running total advances, so it is never inferred from the caller. to(0) defaults payout to that
        // identity. Only the identity itself may redirect payout elsewhere: a third-party submitter must
        // leave `to` at the identity (or zero). Checked before any FHE work so a rejected call burns no
        // coprocessor budget.
        if (account == address(0)) revert ZeroAccount();
        address beneficiary = to == address(0) ? account : to;
        if (beneficiary != account && msg.sender != account) revert UnauthorizedRedirect(account, beneficiary);
        (euint64 outstanding, euint64 claimed, bytes32 leaf) = _verifyOutstanding(
            account,
            beneficiary,
            inputAmount,
            inputProof,
            merkleProof
        );
        // The amount is never emitted in clear, and the leaf is the claim's event key. The base payout helper
        // transfers and returns the DELIVERED handle - encrypted-0 when the ERC-7984 all-or-nothing clamp
        // fires - and only that delivered amount advances the accounting, so an under-funded claim keeps the
        // entitlement and can be retried once funded.
        emit Claimed(account, beneficiary, leaf);
        euint64 moved = _transferTo(beneficiary, outstanding);
        _recordClaimed(account, claimed, moved);
    }

    /// @inheritdoc IMerkleConfidentialAirdrop
    function claimAndUnwrap(
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external payable override nonReentrant {
        // Reject early on a non-unwrappable campaign so a claimer never spends the fee on a doomed unwrap.
        if (!_getConfigStorage().unwrappable) revert TokenNotUnwrappable();
        // Redirect-only payout: address(0) defaults delivery to the caller.
        address beneficiary = to == address(0) ? msg.sender : to;
        (euint64 outstanding, euint64 claimed, bytes32 leaf) = _verifyOutstanding(
            msg.sender,
            beneficiary,
            inputAmount,
            inputProof,
            merkleProof
        );
        // Base helper: ACL transiently, then enqueue the unwrap (burns this instance's balance now; the
        // underlying ERC-20 is released later by a permissionless finalizeUnwrap). `unwrapAmount(reqId)` is
        // the wrapper's own record of the amount burned for this request - the value finalizeUnwrap pays
        // out against - so credits the wrapper makes to this instance's balance inside the burn cannot
        // move it. It is already ACL'd to this instance by the token and is encrypted-0 under the
        // all-or-nothing clamp (the accounting then does not advance; retry once funded). A handle this
        // instance cannot operate on reverts the whole claim rather than recording zero; a misreporting
        // token is a trusted-component failure, as on the transfer path trusting the returned `moved`.
        // `beneficiary` is the underlying-ERC-20 recipient; the accounting identity stays msg.sender.
        bytes32 reqId = _unwrapTo(beneficiary, outstanding);
        euint64 burned = IERC7984ERC20Wrapper(_getConfigStorage().token).unwrapAmount(reqId);
        _grantCompliance(burned);
        _recordClaimed(msg.sender, claimed, burned);
        emit ClaimedAndUnwrapInitiated(msg.sender, beneficiary, leaf, reqId);
    }

    // ───────────────────────────── preview / views ─────────────────────────────────────────────────
    /// @inheritdoc IMerkleConfidentialAirdrop
    function getClaimAmount(
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external override returns (euint64 amount) {
        _requireClaimWindowActive();
        // Preview consumes NO fee and writes NO accounting: the same input still pays the same amount after
        // a preview (the only state it writes is appended, append-only FHE ACL grants). What is previewed is
        // the OUTSTANDING amount - the committed cumulative total net of what was already delivered. The
        // account is mandatory and explicit, exactly as on the claim paths, and is passed as both the claim
        // identity and the grantee, so a third party previewing on someone else's behalf learns nothing (the
        // ACL lands on the account, never the caller).
        if (account == address(0)) revert ZeroAccount();
        bytes32 leaf;
        (amount, , leaf) = _outstandingOf(account, account, inputAmount, inputProof, merkleProof);
        emit ClaimPreviewed(account, leaf);
    }

    /// @inheritdoc IMerkleConfidentialAirdrop
    function getClaimedAmount(address account) external view override returns (euint64) {
        // Zero-handle (uninitialized) before the account's first settled claim; ACL'd to the account, this
        // instance and the compliance manager clone at every write.
        return _getMerkleStorage().claimedAmount[account];
    }

    // ───────────────────────────── Merkle-impl internals ──────────────────────────────────────────
    /**
     * @notice Run the window and fee gates, then verify the encrypted input and compute the outstanding
     *         amount. Shared by `claim` and `claimAndUnwrap`.
     * @dev The window and fee checks gate entry (the fee is an exact-equality check against `gasFee()`);
     *      everything else — proof verification, the outstanding-amount arithmetic and the ACL grants — is
     *      the same `_outstandingOf` core the fee-less preview uses, so the two paths cannot drift. Nothing
     *      is consumed here: the caller advances the accounting with the DELIVERED amount after its payout
     *      call returns.
     * @param claimant The account whose leaf and running total this claim is verified against; always the
     *        explicit, non-zero `account` the caller named. The FHE input proof is NOT bound to this
     *        address, see `inputProof`.
     * @param beneficiary The payout destination that receives the recipient sender-ACL grant; resolved by
     *        the caller (`to == address(0)` => `claimant`).
     * @param inputAmount The external encrypted cumulative-total handle.
     * @param inputProof The input proof for `inputAmount`, bound by the coprocessor to (address(this),
     *        msg.sender) - the literal caller, never `claimant`.
     * @param merkleProof The Merkle proof path for `claimant`'s leaf.
     * @return outstanding The encrypted amount still owed (committed total net of already delivered),
     *         ACL'd to the instance, the beneficiary and the manager clone.
     * @return claimed `claimant`'s running delivered total BEFORE this claim (for `_recordClaimed`).
     * @return leaf The verified leaf (also the claim's event key).
     */
    function _verifyOutstanding(
        address claimant,
        address beneficiary,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) internal returns (euint64 outstanding, euint64 claimed, bytes32 leaf) {
        _requireClaimWindowActive(); // !paused && start <= now <= end (base)
        uint256 fee = gasFee();
        if (msg.value != fee) revert InsufficientFee(msg.value, fee); // exact equality
        (outstanding, claimed, leaf) = _outstandingOf(claimant, beneficiary, inputAmount, inputProof, merkleProof);
    }

    /**
     * @notice Verify the claimant's leaf and encrypted input, then compute the outstanding amount: the
     *         committed cumulative total net of what was already delivered. Shared by the claim paths (via
     *         `_verifyOutstanding`) and the preview, so the outstanding-amount rule cannot drift.
     * @dev The leaf - which binds this instance, `claimant` and the exact ciphertext handle - is checked
     *      against the CURRENT root; the input proof is verified by the coprocessor against (address(this),
     *      msg.sender) - the literal caller, not `claimant` - so a forged or mismatched proof reverts rather
     *      than silently decrypting to zero. The outstanding amount is `total - min(total, claimed)`: capping
     *      the subtrahend first makes the subtraction clamp to encrypted-0 instead of silently wrapping when
     *      the committed total does not exceed what was already delivered (an already-settled leaf, or a
     *      total rotated below the delivered amount). The leaf and the accounting stay bound to `claimant` -
     *      `grantee` only redirects the recipient ACL (and, in the claim callers, token delivery), so a
     *      different `to` can never change what `claimant` is owed. The input proof binds to msg.sender
     *      regardless of either address.
     * @param claimant The account whose leaf and running total are read and advanced; the accounting
     *        identity, independent of who submits the transaction or whom the input proof is bound to.
     * @param grantee The address granted the recipient sender-ACL on the outstanding handle (the payout
     *        beneficiary, or the previewer).
     * @param inputAmount The external encrypted cumulative-total handle.
     * @param inputProof The input proof for `inputAmount`, bound by the coprocessor to (address(this),
     *        msg.sender) - the literal caller, never `claimant`.
     * @param merkleProof The Merkle proof path for `claimant`'s leaf.
     * @return outstanding The encrypted amount still owed, ACL'd to the instance, `grantee` and the manager
     *         clone.
     * @return claimed `claimant`'s running delivered total BEFORE this claim (zero-handle on first claim -
     *         the FHE ops read an uninitialized handle as encrypted-0).
     * @return leaf The verified leaf.
     */
    function _outstandingOf(
        address claimant,
        address grantee,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) internal returns (euint64 outstanding, euint64 claimed, bytes32 leaf) {
        MerkleStorage storage m = _getMerkleStorage();
        leaf = _leafOf(claimant, inputAmount); // accounting identity is claimant, independent of `grantee`
        if (!MerkleProof.verify(merkleProof, m.merkleRoot, leaf)) revert InvalidMerkleProof(leaf, m.merkleRoot);

        euint64 total = _verifyInputAmount(inputAmount, inputProof); // binds (this, msg.sender) or reverts
        claimed = m.claimedAmount[claimant];
        outstanding = FHE.sub(total, FHE.min(total, claimed)); // clamps to encrypted-0, never wraps
        FHE.allowThis(outstanding);
        FHE.allow(outstanding, grantee); // payout destination / previewer holds sender-ACL on the handle
        _grantCompliance(outstanding); // grants the instance's OWN manager clone, once
    }

    /**
     * @notice Verify an external encrypted input, granting the submitter no ACL allowance on the result.
     * @dev Deliberately not `FHE.fromExternal`, which appends `IACL.allowTransient(result, msg.sender)`.
     *      That write gives the submitter a transient allowance on the committed total it is submitting,
     *      and a transient allowance is accepted by `ACL.allow`/`allowForDecryption` as authority to write a
     *      persistent grant that can never be revoked - so a contract submitter could make an amount it has
     *      no entitlement to permanently readable, or public. Do not restore it: `verifyInput` already
     *      grants the CALLING CONTRACT its own allowance, which is the one `_outstandingOf` consumes, so
     *      omitting it costs the instance nothing.
     *
     *      The proof binding is unchanged from the library wrapper: `msg.sender` stays the verified user, so
     *      a proof is still created against (this instance, its submitter). Going direct also drops the
     *      wrapper's empty-proof branch, which admits an unproven handle its caller already holds.
     * @param inputAmount The external encrypted cumulative-total handle.
     * @param inputProof The input proof, bound to (address(this), msg.sender). Empty or mismatched proofs
     *        revert in the coprocessor.
     * @return The verified handle, usable by this instance for the rest of the transaction.
     */
    function _verifyInputAmount(externalEuint64 inputAmount, bytes calldata inputProof) internal returns (euint64) {
        CoprocessorConfig storage $ = Impl.getCoprocessorConfig();
        return
            euint64.wrap(
                IFHEVMExecutor($.CoprocessorAddress).verifyInput(
                    externalEuint64.unwrap(inputAmount),
                    msg.sender,
                    inputProof,
                    FheType.Uint64
                )
            );
    }

    /**
     * @notice Advance the claimant's cumulative claimed accounting by the amount actually DELIVERED.
     * @dev Delivered-based on purpose: under the ERC-7984 all-or-nothing clamp an under-funded payout moves
     *      encrypted-0, and adding that zero leaves the accounting untouched — the entitlement survives and
     *      the claim can be retried once the pool is funded. The write necessarily happens after the payout
     *      call (the delivered amount does not exist before it); the claim entrypoints are nonReentrant, so
     *      no second claim can read the stale total mid-flight. The sum cannot wrap: the delivered amount
     *      never exceeds `total - claimed`, so the new running total never exceeds the committed 64-bit
     *      total. The new handle is ACL'd to the instance (the next claim's arithmetic reads it back), to
     *      the claimant (off-chain decrypt of their own progress) and to the compliance manager clone.
     * @param claimant The account whose running total this claim advances.
     * @param claimed The claimant's running delivered total BEFORE this claim.
     * @param delivered The delivered-amount handle this claim actually moved.
     */
    function _recordClaimed(address claimant, euint64 claimed, euint64 delivered) internal {
        euint64 newClaimed = FHE.add(claimed, delivered);
        FHE.allowThis(newClaimed);
        FHE.allow(newClaimed, claimant);
        _grantCompliance(newClaimed);
        _getMerkleStorage().claimedAmount[claimant] = newClaimed;
    }

    /**
     * @notice Compute the Merkle leaf committing this instance, a recipient and the encrypted handle of the
     *         recipient's cumulative total allocation.
     * @dev The OZ-standard double-`keccak256`, sorted-pair leaf: the inner hash is over `abi.encode` (not
     *      packed, to avoid ambiguity) of `(address(this), recipient, handle)`. Including `address(this)`
     *      domain-separates the leaf so a tree built for one instance can never be replayed against another
     *      (it is leaf hashing, not address derivation, so no chain id enters any address). This single helper
     *      is the source of truth for the leaf rule, used by the claim paths and the preview so they cannot
     *      drift. It is the prescribed input to `MerkleProof.verify` and the OpenZeppelin merkle-tree
     *      library, not a reimplementation of any tree or verifier.
     * @param recipient The leaf recipient (the claim identity - not necessarily the transaction submitter).
     * @param inputAmount The external encrypted cumulative-total handle committed in the leaf.
     * @return The Merkle leaf hash.
     */
    function _leafOf(address recipient, externalEuint64 inputAmount) internal view returns (bytes32) {
        bytes32 encHandle = bytes32(externalEuint64.unwrap(inputAmount));
        return keccak256(bytes.concat(keccak256(abi.encode(address(this), recipient, encHandle))));
    }
}
