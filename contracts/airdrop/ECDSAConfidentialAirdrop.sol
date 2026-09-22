// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {FHE, euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";

import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {ConfidentialAirdropBase} from "./ConfidentialAirdropBase.sol";
import {ConfidentialAirdropECDSAStorage} from "../storage/ConfidentialAirdropECDSAStorage.sol";
import {IECDSAConfidentialAirdrop} from "../interfaces/IECDSAConfidentialAirdrop.sol";
// Referenced only in `airdropType()`'s override specifier — `airdropType` is declared in both this and
// `ConfidentialAirdropBase`, so Solidity requires both to be named explicitly.
import {IConfidentialAirdropBase} from "../interfaces/IConfidentialAirdropBase.sol";

/**
 * @title ECDSAConfidentialAirdrop
 * @author TokenOps
 * @notice Confidential airdrop whose claims are authorized by an off-chain EIP-712 signature from a holder
 *         of `SIGNER_ROLE`. Each signature binds the authorized claimant (`msg.sender`), the exact encrypted
 *         allocation handle, an opaque off-chain identifier and an expiry; the claimant presents it together
 *         with the matching encrypted input to receive (or directly unwrap) the allocation. The claimant may
 *         redirect token delivery to an arbitrary payout destination via the leading `to` parameter on the
 *         consuming claim functions (`to == address(0)` defaults to `msg.sender`); authorization, replay dedup
 *         and the FHE input proof remain bound to `msg.sender`. A signed
 *         allocation can be claimed only once: the same claimant address and/or the same `dedupId` may
 *         claim a single time, chosen at deploy time by the `DedupMode` (or neither dimension, under
 *         `DedupMode.None`, relying solely on the consumed EIP-712 digest).
 * @dev Concrete implementation #1 over the shared `ConfidentialAirdropBase`, deployable as a minimal-proxy
 *      clone or a UUPS proxy. The EIP-712 domain (`name = "ConfidentialAirdrop"`, `version = "1"`) lives on
 *      this implementation only — the base carries no domain and the Merkle implementation defines its own
 *      authorization. All signature machinery is OpenZeppelin (`EIP712Upgradeable` for the domain/digest and
 *      `SignatureChecker` for verification); the only first-party cryptographic input is the claim struct
 *      hash. Replay is enforced primarily by recipient/`dedupId` dedup, with a defense-in-depth
 *      consumed-digest guard (the PRIMARY guard under `DedupMode.None`). The claim hot path performs a single
 *      FHE input verification plus ACL writes and one token transfer or unwrap — no airdrop-side FHE
 *      arithmetic.
 *
 *      There is a SINGLE signer-explicit claim surface. Every `claim`/`claimAndUnwrap`/`getClaimAmount`/
 *      `isSignatureValid` entrypoint takes the authorizing `signer` address explicitly, requires it to hold
 *      `SIGNER_ROLE` (checked FIRST, before any external call), then verifies the signature via OZ
 *      `SignatureChecker.isValidSignatureNow` — which dispatches to the EOA fallback (canonical low-s
 *      `ECDSA.tryRecover`) or the on-chain ERC-1271 `isValidSignature` staticcall, so both EOA and
 *      smart-account signers are supported by one path. The signer is the SIGNER_ROLE authorizer and is NOT
 *      bound into the digest — the signature itself proves who signed — so `CLAIM_TYPEHASH` and the domain
 *      (name "ConfidentialAirdrop", version "1") are unchanged. The single claim path's replay guards
 *      (`usedClaimDigest`, `claimedByAddress`, `claimedByDedupId`) protect every consuming claim.
 */
contract ECDSAConfidentialAirdrop is
    IECDSAConfidentialAirdrop,
    ConfidentialAirdropBase,
    EIP712Upgradeable,
    ConfidentialAirdropECDSAStorage
{
    // ───────────────────────────── role / typed-data ───────────────────────────────────────
    /// @inheritdoc IECDSAConfidentialAirdrop
    bytes32 public constant override SIGNER_ROLE = keccak256("SIGNER_ROLE");

    /// @inheritdoc IECDSAConfidentialAirdrop
    bytes32 public constant override CLAIM_TYPEHASH = keccak256(
        "Claim(address recipient,bytes32 encryptedAmount,bytes32 dedupId,uint256 deadline)"
    );

    // ───────────────────────────────────── initialization ────────────────────────────────────
    /// @inheritdoc IConfidentialAirdropBase
    function airdropType() public pure override(ConfidentialAirdropBase, IConfidentialAirdropBase) returns (uint8) {
        return uint8(AirdropType.ECDSA);
    }

    /// @inheritdoc IECDSAConfidentialAirdrop
    function initialize(ECDSAInitParams calldata p) external override initializer {
        // Shared base init runs first (validates config, wires the coprocessor, grants the admin roles).
        __ConfidentialAirdropBase_init(p.base);
        // EIP-712 domain — set HERE only (the base has no domain). chainId + address(this) are folded in by
        // OZ, so a signature is bound to this chain and this instance and cannot be replayed across either.
        __EIP712_init("ConfidentialAirdrop", "1");
        if (p.signer == address(0)) revert ZeroSigner();
        // SIGNER_ROLE is administered by DEFAULT_ADMIN_ROLE (the factory-injected admin), so it can be
        // rotated post-deploy without a dedicated role admin.
        _grantRole(SIGNER_ROLE, p.signer);
        _getECDSAStorage().dedupMode = p.dedupMode; // PerAddress | PerDedupId | Both | None — fixed at init
    }

    // ───────────────────────────────────────── claim ───────────────────────────────────────
    /// @inheritdoc IECDSAConfidentialAirdrop
    function claim(
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) external payable override nonReentrant {
        // Redirect-only payout: `to == address(0)` defaults to msg.sender;
        // authorization, dedup and the FHE input proof below all stay bound to msg.sender.
        address beneficiary = to == address(0) ? msg.sender : to;
        (euint64 amount, bytes32 claimKey) = _verifyAndConsume(
            beneficiary,
            inputAmount,
            inputProof,
            dedupId,
            deadline,
            signer,
            signature
        );
        // The amount is never emitted in clear. No claimed-amount accounting exists to update: the beneficiary
        // already holds sender-ACL on `amount` and the compliance manager clone already holds its grant on it
        // (both set in _verifyAndConsume). The base payout helper transfers and then grants the clone on the
        // transfer's RETURNED handle, so compliance reads the DELIVERED amount even when the ERC-7984 clamp pays
        // encrypted-0. `claimKey` is the key `_verifyAndConsume` already derived while consuming dedup — no
        // second dedupMode SLOAD to recompute it here.
        emit Claimed(msg.sender, beneficiary, claimKey);
        _transferTo(beneficiary, amount);
    }

    /// @inheritdoc IECDSAConfidentialAirdrop
    function claimAndUnwrap(
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) external payable override nonReentrant {
        // Reject early on a non-unwrappable campaign so a claimer never spends the fee on a doomed unwrap.
        if (!_getConfigStorage().unwrappable) revert TokenNotUnwrappable();
        // Redirect-only payout: `to == address(0)` defaults to msg.sender;
        // authorization, dedup and the FHE input proof below all stay bound to msg.sender.
        address beneficiary = to == address(0) ? msg.sender : to;
        (euint64 amount, bytes32 claimKey) = _verifyAndConsume(
            beneficiary,
            inputAmount,
            inputProof,
            dedupId,
            deadline,
            signer,
            signature
        );
        // Base helper: ACL the amount transiently to the wrapper, then enqueue the unwrap (burns this
        // instance's confidential balance; the underlying ERC-20 is released later in a permissionless
        // finalizeUnwrap tx). `beneficiary` is the underlying-ERC-20 beneficiary. `claimKey` comes from
        // `_verifyAndConsume` — see `claim`.
        bytes32 reqId = _unwrapTo(beneficiary, amount);
        emit ClaimedAndUnwrapInitiated(msg.sender, beneficiary, claimKey, reqId);
    }

    // ───────────────────────────── preview / views ─────────────────────────────────────────
    /// @inheritdoc IECDSAConfidentialAirdrop
    function getClaimAmount(
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) external override returns (euint64 amount) {
        _requireClaimWindowActive();
        if (block.timestamp > deadline) revert SignatureExpired(deadline, block.timestamp);
        bytes32 digest = _hashTypedDataV4(_claimStructHash(msg.sender, inputAmount, dedupId, deadline));
        if (!_verifySigner(digest, signer, signature)) revert InvalidSignature(); // role-first + SignatureChecker
        // Reject a voucher the consuming path would already refuse, with that path's own error and ordering.
        // Placed BEFORE the input verification so a rejected preview performs no FHE op, writes no ACL grant
        // and emits nothing. Reading the replay state is not consuming it: the preview still writes neither
        // the dedup slot(s) nor the digest, so an unconsumed voucher stays claimable after any number of
        // previews (the only state a successful preview writes is append-only FHE ACL grants).
        ReplayStatus status = _replayStatus(msg.sender, dedupId, digest);
        if (status == ReplayStatus.AddressConsumed) revert AddressAlreadyClaimed();
        if (status == ReplayStatus.DedupIdConsumed) revert DedupIdAlreadyClaimed();
        if (status == ReplayStatus.DigestConsumed) revert SignatureAlreadyUsed();
        amount = FHE.fromExternal(inputAmount, inputProof);
        FHE.allowThis(amount);
        FHE.allow(amount, msg.sender); // caller can off-chain decrypt their allocation
        _grantCompliance(amount); // grants the instance's own compliance manager clone, and only that clone
        emit ClaimPreviewed(msg.sender, _claimKey(msg.sender, dedupId));
    }

    /// @inheritdoc IECDSAConfidentialAirdrop
    function isSignatureValid(
        externalEuint64 inputAmount,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) external view override returns (bool) {
        ConfigStorage storage c = _getConfigStorage();
        // window (mirrors isClaimWindowActive) + deadline — return false rather than revert (this is a query)
        if (paused() || block.timestamp < c.startTime || block.timestamp > c.endTime) return false;
        if (block.timestamp > deadline) return false;
        // _verifySigner is view-safe (SignatureChecker: ECDSA.tryRecover for EOAs, an isValidSignature staticcall
        // for ERC-1271 smart accounts) — a malformed or unauthorized signature yields `false`, never reverting.
        bytes32 digest = _hashTypedDataV4(_claimStructHash(msg.sender, inputAmount, dedupId, deadline));
        if (!_verifySigner(digest, signer, signature)) return false;
        // Same replay classification the preview reverts on - the two surfaces cannot drift.
        return _replayStatus(msg.sender, dedupId, digest) == ReplayStatus.NotConsumed;
    }

    /// @inheritdoc IECDSAConfidentialAirdrop
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ───────────────────────────── ECDSA-impl internals ───────────────────────────────────────────
    /**
     * @notice Run every claim check, consume the replay guards, then verify the encrypted input and grant
     *         the required ACLs. Shared by `claim` and `claimAndUnwrap`.
     * @dev Order is load-bearing: the window, deadline, fee, role and signature checks gate entry; both replay
     *      slots (primary dedup and the defense-in-depth digest) are consumed BEFORE the input is verified and
     *      BEFORE the caller returns to make any external call (checks-effects-interactions). The fee is an
     *      exact-equality check against `gasFee()`. Authorization, replay dedup and the FHE input proof are
     *      all bound to `msg.sender`, so a signature is only ever usable by its named claimant; `beneficiary`
     *      only redirects token delivery and the recipient ACL. The `signer` role check runs FIRST (cheap,
     *      authorizes the signer before any external call), then the signature is verified via OZ
     *      `SignatureChecker.isValidSignatureNow` — which dispatches to the EOA fallback (canonical low-s
     *      `ECDSA.tryRecover`) or the on-chain ERC-1271 `isValidSignature` staticcall, so one path serves both
     *      EOA and smart-account signers. The signer is the authorizer only and is NOT bound into the digest.
     * @param beneficiary The payout destination (already resolved: `to`, or `msg.sender` when `to` is zero) —
     *        receives the recipient ACL and the token delivery; NOT bound into the digest or dedup.
     * @param inputAmount The external encrypted allocation handle.
     * @param inputProof The input proof for `inputAmount` (bound to this instance and `msg.sender`).
     * @param dedupId The off-chain claim id bound by the signature.
     * @param deadline The signature expiry timestamp.
     * @param signer The address that authorized the claim; must hold `SIGNER_ROLE`.
     * @param signature The EIP-712 signature (EOA or ERC-1271) verified against `signer`.
     * @return amount The verified encrypted allocation, ACL'd to the instance, the beneficiary and the
     *         compliance manager clone.
     * @return claimKey The dedup-derived event key for this claim (see `_consumeDedup`), passed through so
     *         the caller need not re-derive it with a second `dedupMode` SLOAD.
     */
    function _verifyAndConsume(
        address beneficiary,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) internal returns (euint64 amount, bytes32 claimKey) {
        _requireClaimWindowActive(); // !paused && start <= now <= end (base)
        // dedicated error — never InvalidSignature
        if (block.timestamp > deadline) revert SignatureExpired(deadline, block.timestamp);
        uint256 fee = gasFee();
        if (msg.value != fee) revert InsufficientFee(msg.value, fee); // exact equality

        bytes32 digest = _hashTypedDataV4(_claimStructHash(msg.sender, inputAmount, dedupId, deadline));
        if (!_verifySigner(digest, signer, signature)) revert InvalidSignature(); // role-first + SignatureChecker

        // Consume the replay guards and verify/ACL the input (recipient ACL → beneficiary).
        (amount, claimKey) = _consumeVerifyGrant(beneficiary, digest, inputAmount, inputProof, dedupId);
    }

    /**
     * @notice Single source of truth for the claim verification rule: `signer` holds `SIGNER_ROLE` AND
     *         `signature` is a valid EIP-712 signature over `digest` for `signer`.
     * @dev Role check FIRST via `&&` short-circuit, so the ERC-1271 `isValidSignature` staticcall to a (possibly
     *      hostile) `signer` contract is only reachable for an already-authorized signer. View-safe: OZ
     *      `SignatureChecker.isValidSignatureNow` uses canonical low-s `ECDSA.tryRecover` for EOAs or the ERC-1271
     *      staticcall for smart accounts and never reverts, so callers choose revert vs. return. Shared by the
     *      consuming path (`_verifyAndConsume`), the preview (`getClaimAmount`) and the view (`isSignatureValid`)
     *      so the three cannot drift.
     * @param digest The EIP-712 claim digest.
     * @param signer The claimed authorizer; must hold `SIGNER_ROLE`.
     * @param signature The EIP-712 signature (EOA or ERC-1271) to verify against `signer`.
     * @return True iff `signer` is role-authorized and `signature` is valid for `digest`.
     */
    function _verifySigner(bytes32 digest, address signer, bytes calldata signature) internal view returns (bool) {
        return hasRole(SIGNER_ROLE, signer) && SignatureChecker.isValidSignatureNow(signer, digest, signature);
    }

    /**
     * @notice Classify the replay state of a claim without consuming any of it.
     * @dev Single source of truth for "would the consuming path reject this voucher as already used?", shared
     *      by the preview (`getClaimAmount`, which maps each consumed status to that path's error) and the
     *      view (`isSignatureValid`, which maps anything but `NotConsumed` to `false`), so the two cannot
     *      drift. Mirrors `_consumeDedup` exactly: explicit per-mode checks (not `!=` guards) so
     *      `DedupMode.None` skips BOTH dedup reads entirely instead of incidentally reading maps that mode
     *      never consumes, and the dedup dimension is reported BEFORE the digest - the order in which
     *      `_consumeDedup` then `_consumeDigest` revert. The digest read is unconditional across every mode
     *      (one warm SLOAD; neither caller is gas-critical): under `PerAddress`/`PerDedupId`/`Both` a consumed
     *      digest already implies a consumed dedup slot, so it is redundant defense-in-depth, but under
     *      `DedupMode.None` - where neither dedup map is ever written - it is the ONLY replay signal there is.
     * @param recipient The claim recipient (the caller).
     * @param dedupId The off-chain claim id bound by the signature.
     * @param digest The EIP-712 claim digest.
     * @return The first guard found consumed, or `NotConsumed` when the claim is still available.
     */
    function _replayStatus(address recipient, bytes32 dedupId, bytes32 digest) internal view returns (ReplayStatus) {
        ECDSADedupStorage storage d = _getECDSAStorage();
        DedupMode mode = d.dedupMode;
        if ((mode == DedupMode.PerAddress || mode == DedupMode.Both) && d.claimedByAddress[recipient]) {
            return ReplayStatus.AddressConsumed;
        }
        if ((mode == DedupMode.PerDedupId || mode == DedupMode.Both) && d.claimedByDedupId[dedupId]) {
            return ReplayStatus.DedupIdConsumed;
        }
        if (d.usedClaimDigest[digest]) return ReplayStatus.DigestConsumed;
        return ReplayStatus.NotConsumed;
    }

    /**
     * @notice Consume both replay guards, verify the encrypted input and grant the required ACLs.
     * @dev The shared consume+verify core of the consuming claim path. Order is load-bearing: both replay slots
     *      (primary dedup and the defense-in-depth digest) are consumed BEFORE the input is verified and BEFORE
     *      the caller returns to make any external call (checks-effects-interactions). The caller is responsible
     *      for the window/deadline/fee/role/signature gates that precede it. Dedup and the FHE input proof stay
     *      bound to `msg.sender`; only the recipient sender-ACL follows `beneficiary`.
     * @param beneficiary The payout destination receiving the recipient sender-ACL; NOT used for dedup or the
     *        FHE proof binding.
     * @param digest The EIP-712 claim digest already computed and verified by the caller.
     * @param inputAmount The external encrypted allocation handle.
     * @param inputProof The input proof for `inputAmount` (bound to this instance and `msg.sender`).
     * @param dedupId The off-chain claim id bound by the signature.
     * @return amount The verified encrypted allocation, ACL'd to the instance, the beneficiary and the manager clone.
     * @return claimKey The dedup-derived event key for this claim, returned by `_consumeDedup`.
     */
    function _consumeVerifyGrant(
        address beneficiary,
        bytes32 digest,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32 dedupId
    ) internal returns (euint64 amount, bytes32 claimKey) {
        // PRIMARY guard (a no-op under DedupMode.None) — mark BEFORE any external call (CEI).
        claimKey = _consumeDedup(msg.sender, dedupId);
        // Defense-in-depth under PerAddress/PerDedupId/Both; the PRIMARY (and only) per-signature replay
        // stop under DedupMode.None — also BEFORE any external call (CEI).
        _consumeDigest(digest);

        amount = FHE.fromExternal(inputAmount, inputProof); // proof bound to (this, msg.sender) or it reverts
        FHE.allowThis(amount);
        FHE.allow(amount, beneficiary); // beneficiary holds sender-ACL on the payout handle
        _grantCompliance(amount); // grants the instance's own compliance manager clone, and only that clone
    }

    /**
     * @notice Build the EIP-712 claim struct hash binding recipient, encrypted amount, `dedupId` and
     *         deadline.
     * @dev `encryptedAmount` is the `bytes32` external handle (`externalEuint64.unwrap`); `recipient` is the
     *      caller. `abi.encode` (not packed) avoids ambiguity. This is the prescribed OZ struct-hash input,
     *      not a reimplementation of any signature primitive.
     * @param recipient The claim recipient (the caller).
     * @param inputAmount The external encrypted allocation handle.
     * @param dedupId The off-chain claim id.
     * @param deadline The signature expiry timestamp.
     * @return The claim struct hash (pre image of the EIP-712 digest).
     */
    function _claimStructHash(
        address recipient,
        externalEuint64 inputAmount,
        bytes32 dedupId,
        uint256 deadline
    ) internal pure returns (bytes32) {
        bytes32 encryptedAmount = bytes32(externalEuint64.unwrap(inputAmount));
        return keccak256(abi.encode(CLAIM_TYPEHASH, recipient, encryptedAmount, dedupId, deadline));
    }

    /**
     * @notice Consume the primary replay slot(s) for this claim, per the deploy-time `DedupMode`, and return
     *         the claim's event key derived from that same mode.
     * @dev Enforces "the same address and/or the same dedupId cannot claim twice" — or neither dimension
     *      under `DedupMode.None`, which consumes no slot here at all (replay for that mode rests entirely
     *      on the caller's `_consumeDigest`). Explicit per-mode booleans (not `!=` guards) so `None` cannot
     *      misfire into consuming a slot it should leave untouched: `PerAddress`/`Both` consume
     *      `claimedByAddress`; `PerDedupId`/`Both` consume `claimedByDedupId`. Reverts the dedicated
     *      `AddressAlreadyClaimed` / `DedupIdAlreadyClaimed` on a re-use. `dedupMode` is read ONCE into
     *      memory and reused both for the consume checks below and for the returned `claimKey`, instead of a
     *      second, separate `dedupMode` SLOAD in a follow-up `_claimKey` call.
     * @param recipient The claim recipient (the caller).
     * @param dedupId The off-chain claim id.
     * @return claimKey `dedupId` under `PerDedupId`/`None`, else the recipient address (matches `_claimKey`).
     */
    function _consumeDedup(address recipient, bytes32 dedupId) internal returns (bytes32 claimKey) {
        ECDSADedupStorage storage d = _getECDSAStorage();
        DedupMode mode = d.dedupMode; // one SLOAD, reused below
        bool consumeAddress = mode == DedupMode.PerAddress || mode == DedupMode.Both;
        bool consumeDedupId = mode == DedupMode.PerDedupId || mode == DedupMode.Both;
        if (consumeAddress) {
            if (d.claimedByAddress[recipient]) revert AddressAlreadyClaimed();
            d.claimedByAddress[recipient] = true;
        }
        if (consumeDedupId) {
            if (d.claimedByDedupId[dedupId]) revert DedupIdAlreadyClaimed();
            d.claimedByDedupId[dedupId] = true;
        }
        claimKey =
            (mode == DedupMode.PerDedupId || mode == DedupMode.None) ? dedupId : bytes32(uint256(uint160(recipient)));
    }

    /**
     * @notice Consume the EIP-712 claim digest as a replay guard.
     * @dev Stores the digest (not raw signature bytes), so `s`/`v` malleations of one signature map to the
     *      same key. Set on `claim`/`claimAndUnwrap` only; the non-consuming preview never calls this.
     *      Reverts `SignatureAlreadyUsed` on a re-used digest. Under `PerAddress`/`PerDedupId`/`Both` the
     *      primary dedup above (keyed on a subset of the digest's preimage) reverts first on a real replay,
     *      so this is a deliberately conservative extra net rather than the primary protection. Under
     *      `DedupMode.None` — where `_consumeDedup` consumes no slot at all — this digest consumption IS the
     *      primary (and only) per-signature replay stop: the exact same signature can never be reused, but
     *      the signer remains free to authorize the same claimant again with a fresh signature (a new
     *      `deadline` or `dedupId` yields a new digest).
     * @param digest The EIP-712 claim digest to consume.
     */
    function _consumeDigest(bytes32 digest) internal {
        ECDSADedupStorage storage d = _getECDSAStorage();
        if (d.usedClaimDigest[digest]) revert SignatureAlreadyUsed();
        d.usedClaimDigest[digest] = true;
    }

    /**
     * @notice Derive the event key for a claim, reflecting the deploy-time dedup dimension.
     * @dev `PerDedupId` and `None` key on the opaque `dedupId`; `PerAddress` and `Both` key on the recipient
     *      address. Used ONLY by the non-consuming preview (`getClaimAmount` → `ClaimPreviewed`), which never
     *      calls `_consumeDedup` and therefore has no other source for this key. The consuming path
     *      (`claim`/`claimAndUnwrap`) instead uses the `claimKey` `_consumeDedup` already derived while
     *      consuming dedup, avoiding a second `dedupMode` SLOAD.
     * @param recipient The claim recipient (the caller).
     * @param dedupId The off-chain claim id.
     * @return The claim event key.
     */
    function _claimKey(address recipient, bytes32 dedupId) internal view returns (bytes32) {
        DedupMode m = _getECDSAStorage().dedupMode;
        return (m == DedupMode.PerDedupId || m == DedupMode.None) ? dedupId : bytes32(uint256(uint160(recipient)));
    }
}
