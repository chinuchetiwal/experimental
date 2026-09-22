// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {euint64} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @title IConfidentialAirdropTypes
 * @author TokenOps
 * @notice Shared (base/common) enums, the base init-param struct, shared events and shared errors used by
 *         both confidential airdrop implementations.
 * @dev The types are split across three interfaces. This base interface holds ONLY surfaces that both impls
 *      use. Variant-specific surfaces live in `IECDSAConfidentialAirdropTypes` (DedupMode, ECDSAInitParams,
 *      ECDSA errors incl. `SignatureAlreadyUsed`) and `IMerkleConfidentialAirdropTypes` (MerkleInitParams,
 *      `MerkleRootSet`, Merkle errors). The split means neither impl inherits the other's dead types.
 *      `IConfidentialAirdropBase` re-exports this base interface; the two impl interfaces additionally extend
 *      their own variant types interface.
 *
 *      Error policy (normative): every distinct failure condition gets its own dedicated custom error. The
 *      lone documented exception is `InvalidDuration`, which spans both zero-duration-at-init and
 *      `extendClaimWindow` not-forward.
 */
interface IConfidentialAirdropTypes {
    // ─────────────────────────────────────────── enums ───────────────────────────────────────────

    /// @notice Which authorization mechanism a deployed instance uses (fixed by which impl was deployed).
    enum AirdropType {
        ECDSA,
        Merkle
    }

    /// @notice Proxy shell selected at create time (clone vs UUPS proxy).
    enum DeploymentMode {
        Clone,
        UUPS
    }

    // NOTE: there is deliberately NO disclosure-selector enum. Exactly ONE airdrop-side encrypted
    // quantity exists — the instance's own ERC-7984 balance (the instance keeps no encrypted funded/claimed
    // accounting and stores no `euint64` of its own). A typed selector that could only ever mean
    // "balance" would carry zero information, so balance disclosure is direct and untyped
    // (`adminDiscloseBalanceToParty`/`adminBatchDiscloseBalanceToParties`), reading the instance's own
    // `confidentialBalanceOf(this)` directly. A future second encrypted quantity would introduce a typed
    // selector then, not pre-build one now.

    // ──────────────────────────────── base init params (split structs) ─────────────────────────────
    // Built by the factory: admin = createAirdrop caller (injected); complianceManager = the
    // instance's OWN manager clone (injected); feeCollector = the factory's current collector
    // (injected — seeds FEE_COLLECTOR_ROLE, never creator-chosen); gasFee = the factory's resolved
    // per-claim gas fee, frozen into this instance's config storage forever at init. The variant init
    // structs (`ECDSAInitParams` / `MerkleInitParams`) embed this base and add their own fields.

    struct BaseInitParams {
        address token;
        uint32 startTime;
        uint32 endTime;
        bool canExtendClaimWindow;
        bool unwrappable; //          token is an ERC7984ERC20Wrapper
        uint96 gasFee; //             factory-resolved per-claim gas fee, frozen at init
        address admin; //             factory-injected = createAirdrop caller
        address complianceManager; // factory-injected = the instance's manager clone
        address feeCollector; //      factory-injected = factory fee config at create; seeds
        //                            FEE_COLLECTOR_ROLE only — never storage, never in the address
    }

    // ─────────────────────────────────────────── events ──────────────────────────────────────────

    /// @notice Emitted once when an instance finishes initialization.
    /// @dev `feeCollector` is the initial seed member of the fee-collector role; membership may grow later.
    /// @param token The confidential token distributed by this airdrop.
    /// @param airdropType The `AirdropType` of the deployed instance (cast to uint8).
    /// @param admin The instance admin (the `createAirdrop` caller).
    /// @param feeCollector The initial seed member of `FEE_COLLECTOR_ROLE`.
    /// @param deploymentBlockNumber The block number at which the instance was initialized.
    /// @param gasFee The per-claim fee frozen into this instance's config storage at initialization.
    event AirdropInitialized(
        address indexed token,
        uint8 airdropType,
        address indexed admin,
        address indexed feeCollector,
        uint256 deploymentBlockNumber,
        uint256 gasFee
    );
    /// @notice Emitted on a successful claim; the amount is NEVER emitted in clear.
    /// @dev `claimant` is the dedup/authorization identity; `beneficiary` is the resolved payout destination
    ///      (`to`, or `claimant` when `to` was zero). `beneficiary` is NOT indexed - it is already publicly
    ///      observable via the ERC-7984 transfer event emitted in the same tx, so indexing it would add no
    ///      confidentiality-relevant information.
    /// @param claimant The address that authorized and is deduped for this claim. The transaction sender for
    ///        one implementation, but not necessarily for another that resolves an explicit claim identity
    ///        independent of who submits the transaction.
    /// @param beneficiary The address that received the claimed allocation.
    /// @param claimKey The dedup key identifying this claim.
    event Claimed(address indexed claimant, address beneficiary, bytes32 indexed claimKey); // amount NEVER
    // emitted in clear
    /// @notice Emitted when a claim amount is previewed without being consumed.
    /// @dev The preview path takes no `to`, so the claimant and the beneficiary coincide by construction —
    ///      no separate beneficiary field is carried.
    /// @param recipient The address whose allocation was previewed.
    /// @param claimKey The dedup key identifying the previewed claim.
    event ClaimPreviewed(address indexed recipient, bytes32 indexed claimKey);
    /// @notice Emitted when a claim-and-unwrap is initiated.
    /// @dev `claimant` is the dedup/authorization identity; `beneficiary` is the resolved underlying-ERC-20
    ///      destination (`to`, or `claimant` when `to` was zero). `beneficiary` is NOT indexed - already
    ///      publicly observable via the ERC-7984 unwrap event emitted in the same tx.
    /// @param claimant The address that authorized and is deduped for this claim. The transaction sender for
    ///        one implementation, but not necessarily for another that resolves an explicit claim identity
    ///        independent of who submits the transaction.
    /// @param beneficiary The address that received the claimed allocation.
    /// @param claimKey The dedup key identifying this claim.
    /// @param unwrapRequestId The identifier of the initiated unwrap request.
    event ClaimedAndUnwrapInitiated(
        address indexed claimant,
        address beneficiary,
        bytes32 indexed claimKey,
        bytes32 unwrapRequestId
    );
    /// @notice Emitted when the claim window is extended forward.
    /// @param oldEndTime The previous claim-window end time.
    /// @param newEndTime The new (later) claim-window end time.
    event ClaimWindowExtended(uint32 oldEndTime, uint32 newEndTime);
    /// @notice Emitted when an admin withdraws the confidential balance.
    /// @param by The admin that performed the withdrawal.
    /// @param recipient The address that received the confidential balance.
    event WithdrawnConfidential(address indexed by, address indexed recipient);
    /// @notice Emitted when accrued gas fees are withdrawn.
    /// @param recipient The address that received the withdrawn fees.
    /// @param amount The amount of native fees withdrawn.
    event GasFeeWithdrawn(address indexed recipient, uint256 amount);

    // Instance-side disclosure events — deliberately avoid the IERC7984.AmountDisclosed topic.
    /// @notice Emitted when an admin discloses the instance's OWN current ERC-7984 balance to a party.
    /// @dev The only airdrop-side encrypted quantity is the instance's balance, so this topic is dedicated to
    ///      it and carries no selector field. A distinct compliance topic is kept (not folded into
    ///      `HandleDisclosedToParty`) to avoid colliding with the `IERC7984.AmountDisclosed` topic. The
    ///      disclosing instance is the log's own emitting address, so it is not repeated as a field.
    /// @param discloser The address that authorized the disclosure.
    /// @param party The address granted decrypt ACL on the balance handle.
    /// @param encryptedAmount The disclosed encrypted balance handle.
    event ComplianceBalanceDisclosed(address indexed discloser, address indexed party, euint64 encryptedAmount);
    /// @notice Emitted when an arbitrary handle is disclosed to a party.
    /// @param discloser The address that authorized the disclosure.
    /// @param party The address granted access to the handle.
    /// @param encryptedAmount The disclosed encrypted handle.
    event HandleDisclosedToParty(address indexed discloser, address indexed party, euint64 encryptedAmount);

    // ──────────────────────────── errors — per-parameter init ─────────────────────────────────────
    error ZeroToken();
    error ZeroFeeCollector(); //    validates the factory-injected collector init parameter
    error ZeroComplianceManager();
    /// @notice Init `endTime` is not in the future.
    /// @param endTime The provided claim-window end time.
    /// @param currentTime The block timestamp it failed against.
    error EndTimeInPast(uint32 endTime, uint256 currentTime);
    error InvalidStartTime(); //    startTime > endTime
    /// @notice The (from, to) window pair does not span a positive duration: zero-duration at init
    ///         (`fromTime` = startTime, `toTime` = endTime), or `extendClaimWindow` not moving the end
    ///         strictly forward (`fromTime` = the current end time, `toTime` = the proposed new end time).
    /// @param fromTime The earlier bound the pair was checked from.
    /// @param toTime The provided later bound that failed `fromTime < toTime`.
    error InvalidDuration(uint32 fromTime, uint32 toTime);

    // ──────────────────────────── errors — claim / lifecycle ──────────────────────────────────────
    error ClaimsPaused();
    /// @notice The claim window has not opened yet.
    /// @param startTime The claim-window start time.
    /// @param currentTime The block timestamp that fell short of it.
    error ClaimNotStarted(uint32 startTime, uint256 currentTime);
    /// @notice The claim window is over (end is inclusive).
    /// @param endTime The claim-window end time.
    /// @param currentTime The block timestamp that exceeded it.
    error ClaimWindowFinished(uint32 endTime, uint256 currentTime);
    /// @notice `msg.value` missed the exact per-claim gas fee.
    /// @param providedFee The `msg.value` sent with the claim.
    /// @param requiredFee The instance's frozen `gasFee()` the claim must match exactly.
    error InsufficientFee(uint256 providedFee, uint256 requiredFee);
    error TokenNotUnwrappable(); //      claimAndUnwrap on a non-unwrappable campaign
    error TokenNotAWrapper(); //         init-time probe — unwrappable but not a wrapper token
    error ZeroUnwrapRequestId(); //      the wrapper returned the zero request id, which names no handle
    error ExtensionNotAllowed(); //      extendClaimWindow with canExtendClaimWindow == false

    // ──────────────────────────── errors — treasury / fees / rescue ───────────────────────────────
    error ZeroRecipient();
    error ZeroBalance(); //              withdrawGasFee with nothing accrued
    /// @notice `withdrawGasFee` asked for more than the accrued fee balance.
    /// @param requestedAmount The withdrawal amount requested.
    /// @param availableBalance The instance's actual ETH balance at the time of the call.
    error InsufficientFeeBalance(uint256 requestedAmount, uint256 availableBalance);
    error EthTransferFailed();
    error CannotRescueAirdropToken(); // rescue target == the airdrop token (dedicated, not generic)
    error LastFeeCollector(); //         revoking the SOLE FEE_COLLECTOR_ROLE member on a fee-charging campaign
    //                                    would self-administer the role to zero and permanently strand claim
    //                                    ETH (no withdrawer, and DEFAULT_ADMIN cannot re-grant a self-admin'd
    //                                    role); CONDITIONAL on gasFee() > 0 — a zero-fee campaign can never
    //                                    accrue ETH, so emptying the role there strands nothing
    error LastAdmin(); //                revoking/renouncing the SOLE DEFAULT_ADMIN_ROLE member would leave the
    //                                    contract permanently ungovernable; UNCONDITIONAL - deliberately blocks
    //                                    the renounce-admin-for-immutability pattern. Declared here and reused
    //                                    by both the instances and the factory, each on its own admin set
    error ZeroAdminGrant(); //           granting DEFAULT_ADMIN_ROLE to address(0); UNCONDITIONAL
    error ZeroFeeCollectorGrant(); //    granting FEE_COLLECTOR_ROLE to address(0) on a fee-charging campaign;
    //                                    CONDITIONAL on gasFee() > 0, mirroring LastFeeCollector

    // ──────────────────────────── errors — disclosure ──────────────────────────────────────────────
    /// @notice Gate #1 rejected the disclosure: the handle is not persistently user-decryptable in the
    ///         (caller, instance) context - EITHER leg missing reverts this, not just the caller's.
    /// @dev Carries the offending handle so a batch caller can tell WHICH element failed without bisecting.
    /// @param handle The handle whose (caller, instance) persistent user-decryption ACL is incomplete.
    error HandleNotAllowed(euint64 handle);
    error InvalidParty();
    error EmptyBatch();
}
