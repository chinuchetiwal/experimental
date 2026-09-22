// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {IConfidentialAirdropBase} from "./IConfidentialAirdropBase.sol";
import {IECDSAConfidentialAirdropTypes} from "./IECDSAConfidentialAirdropTypes.sol";

/**
 * @title IECDSAConfidentialAirdrop
 * @author TokenOps
 * @notice External surface of the ECDSA (EIP-712) airdrop implementation. Consumed by the factory's
 *         post-deploy `initialize` call and by claimers/integrators.
 * @dev `initialize(ECDSAInitParams)` is the initialization surface. The EIP-712 domain lives on this
 *      implementation ONLY (name "ConfidentialAirdrop", version "1"). Replay is keyed on the claimant
 *      (`msg.sender`) address and/or `dedupId` per the deploy-time `DedupMode`, plus a consumed EIP-712
 *      claim-digest mapping that reverts `SignatureAlreadyUsed()` (defense-in-depth under
 *      `PerAddress`/`PerDedupId`/`Both`; the sole per-signature replay stop under `DedupMode.None`).
 *
 *      The consuming claim functions (`claim`/`claimAndUnwrap`) take a leading `address to` payout
 *      destination: `to == address(0)` defaults to `msg.sender`, otherwise the claimed tokens (and the
 *      recipient ACL) are redirected to `to`. Authorization (signature), replay dedup and the FHE input proof
 *      remain bound to `msg.sender` — `to` only redirects delivery. The
 *      previews/views (`getClaimAmount`/`isSignatureValid`) take NO `to`: authorization is unchanged, so the
 *      digest they recompute is unchanged.
 *
 *      A SINGLE signer-explicit claim surface: every `claim`/`claimAndUnwrap`/`getClaimAmount`/
 *      `isSignatureValid` entrypoint takes the authorizing `signer` address explicitly, which MUST hold
 *      `SIGNER_ROLE`, and verifies the signature via OZ `SignatureChecker` (EOA fallback OR on-chain ERC-1271
 *      `isValidSignature` staticcall) — so one path serves both EOA and smart-account signers. The signer is
 *      the authorizer only and is NOT bound into the digest — `CLAIM_TYPEHASH` and the domain do not encode it.
 *
 *      Inherits OpenZeppelin's `IERC5267` so the concrete implementation exposes the standard
 *      `eip712Domain()` via OZ `EIP712Upgradeable`, alongside the convenience `DOMAIN_SEPARATOR()` below.
 */
interface IECDSAConfidentialAirdrop is IConfidentialAirdropBase, IECDSAConfidentialAirdropTypes, IERC5267 {
    // ───────────────────────────── roles / typed-data ──────────────────────────────────────────────
    /// @notice Role id authorized to sign EIP-712 claim digests.
    function SIGNER_ROLE() external view returns (bytes32);

    /// @notice EIP-712 type hash for the claim struct (binds `dedupId`).
    function CLAIM_TYPEHASH() external view returns (bytes32);

    /// @notice EIP-712 domain separator (`_domainSeparatorV4()`), bound to (chainId, address(this)).
    function DOMAIN_SEPARATOR() external view returns (bytes32);

    // ───────────────────────────── lifecycle ──────────────────────────────────────────────────────
    /// @notice Calls the shared base init with AirdropType.ECDSA, sets the EIP-712 domain, grants
    ///         SIGNER_ROLE to p.signer (revert ZeroSigner if zero), and stores dedupMode.
    /// @param p The ECDSA init params (base config, signer, dedupMode).
    function initialize(ECDSAInitParams calldata p) external;

    // ───────────────────────────── claim ────────────────────────────────────────────────────────────
    /// @notice Claim the signed encrypted allocation (`msg.value == gasFee()` exact, consumes dedup),
    ///         delivering the tokens to `to`. The authorizing `signer` MUST hold SIGNER_ROLE and is verified
    ///         via OZ `SignatureChecker` (EOA fallback OR on-chain ERC-1271 `isValidSignature`), so EOA and
    ///         smart-account signers share one path; `signer` is the authorizer only and is NOT bound into the
    ///         digest.
    /// @param to The payout destination for the claimed allocation; pass address(0) to default to msg.sender.
    ///        Authorization (signature/leaf), replay dedup and the FHE input proof remain bound to msg.sender —
    ///        `to` only redirects token delivery and the recipient ACL.
    /// @param inputAmount The external encrypted allocation handle.
    /// @param inputProof The input proof for `inputAmount`.
    /// @param dedupId The off-chain claim id bound by the signature.
    /// @param deadline The signature expiry timestamp.
    /// @param signer The authorizing address (EOA or ERC-1271 smart account); must hold SIGNER_ROLE.
    /// @param signature The EIP-712 signature over the claim, verified against `signer`.
    function claim(
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) external payable;

    /// @notice Claim then route the amount straight to the wrapper's unwrap (`to` = ERC-20 beneficiary).
    ///         Reverts TokenNotUnwrappable on a non-unwrappable campaign, and ZeroUnwrapRequestId if the
    ///         wrapper returns the zero request id (the interface requires a non-zero one). The
    ///         authorizing `signer` MUST hold
    ///         SIGNER_ROLE and is verified via OZ `SignatureChecker` (EOA fallback OR on-chain ERC-1271);
    ///         `signer` is the authorizer only and is NOT bound into the digest.
    /// @param to The payout destination for the claimed allocation; pass address(0) to default to msg.sender.
    ///        Authorization (signature/leaf), replay dedup and the FHE input proof remain bound to msg.sender —
    ///        `to` only redirects token delivery and the recipient ACL.
    /// @param inputAmount The external encrypted allocation handle.
    /// @param inputProof The input proof for `inputAmount`.
    /// @param dedupId The off-chain claim id bound by the signature.
    /// @param deadline The signature expiry timestamp.
    /// @param signer The authorizing address (EOA or ERC-1271 smart account); must hold SIGNER_ROLE.
    /// @param signature The EIP-712 signature over the claim, verified against `signer`.
    function claimAndUnwrap(
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) external payable;

    // ───────────────────────────── preview / views ──────────────────────────────────────────────────
    /// @notice Preview/ACL-grant path: no fee, does NOT consume dedup or the digest. Grants caller +
    ///         compliance ACL. Callable any number of times while the claim is still available, and reverts
    ///         once it is not: a consumed dedup slot or a consumed digest raises the same error the consuming
    ///         claim would, in the same order (AddressAlreadyClaimed / DedupIdAlreadyClaimed, then
    ///         SignatureAlreadyUsed). A rejected preview performs no FHE op, grants no ACL and emits nothing.
    ///         The authorizing `signer` MUST hold SIGNER_ROLE and is verified via OZ `SignatureChecker` (EOA
    ///         fallback OR on-chain ERC-1271); `signer` is the authorizer only and is NOT bound into the digest.
    /// @param inputAmount The external encrypted allocation handle.
    /// @param inputProof The input proof for `inputAmount`.
    /// @param dedupId The off-chain claim id bound by the signature.
    /// @param deadline The signature expiry timestamp.
    /// @param signer The authorizing address (EOA or ERC-1271 smart account); must hold SIGNER_ROLE.
    /// @param signature The EIP-712 signature over the claim, verified against `signer`.
    /// @return amount The encrypted allocation handle, ACL-granted to the caller.
    function getClaimAmount(
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) external returns (euint64 amount);

    /// @notice Gas-optimized validity check: no FHE op; window + deadline + SIGNER_ROLE + not-yet-deduped +
    ///         digest not yet consumed. The authorizing `signer` MUST hold SIGNER_ROLE and is verified via OZ
    ///         `SignatureChecker` (EOA fallback OR ERC-1271 staticcall, both view-safe). Returns false (never
    ///         reverts) on any failure, including paused/window/deadline/role fail, an already-deduped claim,
    ///         or an already-consumed EIP-712 digest — the latter is the only replay signal available under
    ///         `DedupMode.None`, since that mode writes neither dedup map.
    /// @param inputAmount The external encrypted allocation handle.
    /// @param dedupId The off-chain claim id bound by the signature.
    /// @param deadline The signature expiry timestamp.
    /// @param signer The authorizing address (EOA or ERC-1271 smart account); must hold SIGNER_ROLE.
    /// @param signature The EIP-712 signature over the claim, verified against `signer`.
    /// @return True if the signature is currently valid for `signer`, its digest is unconsumed, and the
    ///         claim is not yet deduped.
    function isSignatureValid(
        externalEuint64 inputAmount,
        bytes32 dedupId,
        uint256 deadline,
        address signer,
        bytes calldata signature
    ) external view returns (bool);
}
