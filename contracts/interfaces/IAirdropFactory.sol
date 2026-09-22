// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {IConfidentialAirdropTypes} from "./IConfidentialAirdropTypes.sol";
import {IECDSAConfidentialAirdropTypes} from "./IECDSAConfidentialAirdropTypes.sol";

/**
 * @dev Per-creator fee override (declared at file scope so `AirdropFactoryStorage` can import it by
 *      name). `enabled` distinguishes a real 0-fee override from an unset entry. `gasFee` is
 *      `uint96` — the SOURCE for the instance's frozen-at-create `gasFee` config value.
 */
struct CustomFee {
    bool enabled;
    uint96 gasFee;
}

/**
 * @dev Per-deployer compliance-policy override, mirroring {CustomFee}. `overridden`
 *      distinguishes a real OFF override from an unset entry (the global default applies when unset).
 */
struct CompliancePolicy {
    bool overridden;
    bool delegateToCompliance;
}

/**
 * @dev Per-creator upgradeability-policy override, mirroring {CompliancePolicy}. `overridden`
 *      distinguishes a real allow/deny override from an unset entry (the global default applies when
 *      unset). `allowed` is whether the creator may deploy an upgradeable (UUPS) instance. The two
 *      bools pack into one slot.
 */
// Factory-governed upgradeability permission gate.
struct UpgradeabilityPolicy {
    bool overridden;
    bool allowed;
}

/**
 * @dev Constructor-time role wiring. `admin` receives `DEFAULT_ADMIN_ROLE`; every other field defaults
 *      to `admin` when left zero, so a single-admin deploy can pass the other four as `address(0)`.
 */
struct FactoryRoles {
    address admin;
    address feeManager;
    address implManager;
    address complianceWiring;
    address upgradeManager;
}

/**
 * @title IAirdropFactory
 * @author TokenOps
 * @notice External surface of the `AirdropFactory` CREATE3 singleton — per-type create/fund + per-instance
 *         compliance-manager cloning + the append-only on-chain airdrop read-list.
 * @dev Holds TWO airdrop impl addresses, the manager impl it clones per airdrop, the fee
 *      config (source of the frozen-at-create `gasFee` init param and the collector init param) and the
 *      `CompliancePolicy` (global default + per-deployer override, resolved at create, frozen forever).
 *      `create*`/`fund*` are permissionless (deployer-bound salt gives front-run protection).
 *
 *      Create params are typed per variant: a shared `CommonAirdropParams` plus `ECDSAAirdropParams` /
 *      `MerkleAirdropParams`, with per-type functions (`create{ECDSA,Merkle}…`,
 *      `predict{ECDSA,Merkle}AirdropAddress`, `get{ECDSA,Merkle}InitCodeHash`) — no dead optional
 *      fields and no in-struct discriminator.
 *
 *      `DedupMode` is referenced via the ECDSA types interface to keep the Merkle path free of ECDSA types.
 */
interface IAirdropFactory is IConfidentialAirdropTypes {
    /// @dev Create-time fields common to both variants. NO `admin` field — the factory injects
    ///      admin = msg.sender. NO `airdropType` discriminator — the variant is fixed by which typed
    ///      create function is called.
    struct CommonAirdropParams {
        address token;
        uint32 startTime;
        uint32 endTime;
        bool canExtendClaimWindow;
        bool unwrappable; // token is an ERC7984ERC20Wrapper
        // The manager clone's client admin AND client delegate. Zero ⇒ msg.sender.
        address complianceAdmin;
        // The most the creator accepts for this campaign; the factory-wide maximum is checked first.
        // A resolved fee ABOVE it reverts. 0 accepts only a zero fee; `type(uint96).max` accepts any fee.
        uint96 maxAcceptedGasFee;
    }

    /// @dev ECDSA create params: the common block + the ECDSA-only signer & dedup policy.
    struct ECDSAAirdropParams {
        CommonAirdropParams common;
        address signer;
        IECDSAConfidentialAirdropTypes.DedupMode dedupMode;
    }

    /// @dev Merkle create params: the common block + the Merkle-only root & mutability flag.
    struct MerkleAirdropParams {
        CommonAirdropParams common;
        bytes32 merkleRoot;
        bool isMerkleRootMutable;
    }

    // ───────────────────────────── events ──────────────────────────────────────────────────────────
    /// @notice Emitted when a new airdrop instance is created.
    /// @param airdrop The created instance address.
    /// @param token The underlying confidential token.
    /// @param airdropType The variant (ECDSA or Merkle).
    /// @param mode The deployment shell (clone or UUPS proxy).
    /// @param creator The deployer / instance DEFAULT_ADMIN_ROLE.
    /// @param userSalt The caller-supplied salt component.
    event ConfidentialAirdropCreated(
        address indexed airdrop,
        address indexed token,
        AirdropType airdropType,
        DeploymentMode mode,
        address indexed creator,
        bytes32 userSalt
    );
    /// @notice Emitted when the instance's own compliance-manager clone is created.
    /// @param airdrop The instance address.
    /// @param managerClone The cloned `ComplianceRoleManager` for that instance.
    /// @param complianceDelegate The platform compliance delegate, or `address(0)` ⟺ effective policy OFF.
    event ComplianceManagerCloned(
        address indexed airdrop,
        address indexed managerClone,
        address indexed complianceDelegate // == address(0) ⟺ effective policy OFF
    );
    /// @notice Emitted when an instance is funded with an encrypted amount.
    /// @param airdrop The funded instance address.
    /// @param token The underlying confidential token.
    /// @param amount The encrypted funding amount handle.
    event ConfidentialAirdropFunded(address indexed airdrop, address indexed token, euint64 amount);
    /// @notice Emitted when the fee collector is set.
    /// @param feeCollector The new fee collector address.
    event FeeCollectorSet(address indexed feeCollector);
    /// @notice Emitted when the global default gas fee is set.
    /// @param gasFee The new default gas fee (wei).
    event SetDefaultGasFee(uint256 gasFee);
    /// @notice Emitted when a per-creator custom gas fee is set.
    /// @param creator The creator the override applies to.
    /// @param gasFee The custom gas fee (wei).
    event SetCustomFee(address indexed creator, uint256 gasFee);
    /// @notice Emitted when a per-creator custom gas fee is disabled.
    /// @param creator The creator whose override was cleared.
    event CustomFeeDisabled(address indexed creator);
    /// @notice Emitted when the factory's own gas-fee maximum is set.
    /// @param maxGasFee The new maximum (wei).
    event SetMaxGasFee(uint256 maxGasFee);
    /// @notice Emitted when the ECDSA airdrop implementation is set.
    /// @param implementation The new ECDSA impl address.
    event EcdsaImplementationSet(address indexed implementation);
    /// @notice Emitted when the Merkle airdrop implementation is set.
    /// @param implementation The new Merkle impl address.
    event MerkleImplementationSet(address indexed implementation);
    /// @notice Emitted when the compliance-manager implementation is set.
    /// @param implementation The new manager impl address.
    event ComplianceManagerImplSet(address indexed implementation);
    /// @notice Emitted when the platform compliance delegate is set.
    /// @param delegate The new platform compliance delegate address.
    event ComplianceDelegateSet(address indexed delegate);
    /// @notice Emitted when the global default compliance-delegation flag is set.
    /// @param on The new global default value.
    event DefaultDelegateToComplianceSet(bool on); //                                     global default
    /// @notice Emitted when a per-deployer compliance policy override is set.
    /// @param creator The creator the override applies to.
    /// @param delegateToCompliance The override value.
    event CompliancePolicySet(address indexed creator, bool delegateToCompliance); //     per-deployer
    /// @notice Emitted when a per-deployer compliance policy override is cleared.
    /// @param creator The creator whose override was cleared.
    event CompliancePolicyCleared(address indexed creator);

    // Factory-governed upgradeability gate — managed like fees.
    /// @notice Emitted when the global default upgradeability flag is set.
    /// @param allowed The new global default (true ⇒ deployers may create UUPS instances by default).
    event DefaultUpgradeableSet(bool allowed);
    /// @notice Emitted when a per-creator upgradeability override is set.
    /// @param creator The creator the override applies to.
    /// @param allowed Whether that creator may create UUPS instances.
    event UpgradeabilityPolicySet(address indexed creator, bool allowed);
    /// @notice Emitted when a per-creator upgradeability override is cleared.
    /// @param creator The creator whose override was cleared.
    event UpgradeabilityPolicyCleared(address indexed creator);

    // ───────────────────────────── errors ──────────────────────────────────────────────────────────
    // NOTE: ZeroToken / ZeroFeeCollector / EndTimeInPast / InvalidStartTime / InvalidDuration are
    // inherited from IConfidentialAirdropTypes (reused, not re-declared). So are LastAdmin (revoking or
    // renouncing the sole DEFAULT_ADMIN_ROLE member) and ZeroAdminGrant (granting DEFAULT_ADMIN_ROLE to
    // address(0)) - the factory enforces the same two conditions on its own admin set.
    error ZeroAdmin(); //                           constructor: roles.admin == address(0)
    error ZeroImplementation(); //                  setting either airdrop impl to address(0)
    error ZeroComplianceManagerImpl(); //           setting the manager impl to address(0)
    error ZeroComplianceDelegate(); //              compliance delegate == 0 while default ON
    /// @notice `airdropAt(index)` with `index >= airdropCount()`.
    /// @param index The out-of-range index requested.
    /// @param count The current number of deployed airdrops.
    error IndexOutOfBounds(uint256 index, uint256 count);
    /// @notice create with a fee resolving above the creator-supplied `CommonAirdropParams.maxAcceptedGasFee`.
    /// @param resolvedFee The fee the factory resolved for the caller at execution time.
    /// @param maxAcceptedGasFee The maximum fee the caller declared acceptable.
    error GasFeeNotAccepted(uint96 resolvedFee, uint96 maxAcceptedGasFee);
    /// @notice A gas fee (a `setDefaultGasFee`/`setCustomFee` value, or the fee resolved at create) exceeds
    ///         the factory's own governed maximum.
    /// @param gasFee The gas fee that was rejected.
    /// @param maxGasFee The maximum it exceeded.
    error GasFeeExceedsMaximum(uint96 gasFee, uint96 maxGasFee);
    error UnknownAirdrop(); //                      fund: `airdrop` was not created by THIS factory
    error UpgradeabilityNotAllowed(); //            create UUPS while the creator's effective policy is OFF
    /// @notice create replaying an already-created (creator, mode, userSalt, variant) tuple — the predicted
    ///         instance is already recorded.
    /// @param existingAirdrop The already-deployed instance occupying the predicted address.
    error SaltAlreadyUsed(address existingAirdrop);

    // ───────────────────────────── roles ───────────────────────────────────────────────────────────
    /// @notice The fee-management role identifier.
    function FEE_MANAGER_ROLE() external view returns (bytes32);

    /// @notice The implementation-management role identifier.
    function IMPL_MANAGER_ROLE() external view returns (bytes32);

    /// @notice The compliance-wiring role identifier.
    function COMPLIANCE_WIRING_ROLE() external view returns (bytes32);

    /// @notice The upgradeability-policy-management role identifier (its own scope, mirrors FEE_MANAGER_ROLE).
    function UPGRADE_MANAGER_ROLE() external view returns (bytes32);

    // ───────────────────────────── create (per-type) ──────────────────────────────────────────────
    /// @notice Create an ECDSA airdrop of `mode`. The caller becomes the instance DEFAULT_ADMIN_ROLE.
    /// @param p The ECDSA create params.
    /// @param mode The deployment shell (clone or UUPS proxy).
    /// @param userSalt The caller-supplied salt component.
    /// @return airdrop The created instance address.
    function createECDSAConfidentialAirdrop(
        ECDSAAirdropParams calldata p,
        DeploymentMode mode,
        bytes32 userSalt
    ) external returns (address airdrop);

    /// @notice Create a Merkle airdrop of `mode`. The caller becomes the instance DEFAULT_ADMIN_ROLE.
    /// @param p The Merkle create params.
    /// @param mode The deployment shell (clone or UUPS proxy).
    /// @param userSalt The caller-supplied salt component.
    /// @return airdrop The created instance address.
    function createMerkleConfidentialAirdrop(
        MerkleAirdropParams calldata p,
        DeploymentMode mode,
        bytes32 userSalt
    ) external returns (address airdrop);

    /// @notice Create then fund an ECDSA airdrop in one tx (caller must have setOperator(factory) on the token).
    /// @param p The ECDSA create params.
    /// @param mode The deployment shell (clone or UUPS proxy).
    /// @param userSalt The caller-supplied salt component.
    /// @param encryptedAmount The encrypted funding amount.
    /// @param inputProof The input proof for `encryptedAmount`.
    /// @return airdrop The created instance address.
    function createAndFundECDSAConfidentialAirdrop(
        ECDSAAirdropParams calldata p,
        DeploymentMode mode,
        bytes32 userSalt,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external returns (address airdrop);

    /// @notice Create then fund a Merkle airdrop in one tx (caller must have setOperator(factory) on the token).
    /// @param p The Merkle create params.
    /// @param mode The deployment shell (clone or UUPS proxy).
    /// @param userSalt The caller-supplied salt component.
    /// @param encryptedAmount The encrypted funding amount.
    /// @param inputProof The input proof for `encryptedAmount`.
    /// @return airdrop The created instance address.
    function createAndFundMerkleConfidentialAirdrop(
        MerkleAirdropParams calldata p,
        DeploymentMode mode,
        bytes32 userSalt,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external returns (address airdrop);

    // ───────────────────────────── fund (already-created only) ────────────────────────────────────
    /// @notice Fund an airdrop THIS factory already created (existence-checked via `complianceManagerOf`).
    /// @dev Pre-funding a not-yet-created PREDICTED address is not supported (it would risk stuck funds).
    ///      Reverts `UnknownAirdrop()` if `airdrop` was not created here. Caller must have
    ///      setOperator(factory) on the token. The factory resolves the token + manager clone from the
    ///      instance/bookkeeping, ACLs the funding handle to BOTH clone and instance.
    /// @param airdrop The instance to fund (must have been created by this factory).
    /// @param encryptedAmount The encrypted funding amount.
    /// @param inputProof The input proof for `encryptedAmount`.
    function fundConfidentialAirdrop(
        address airdrop,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external;

    // ───────────────────────────── address prediction (per-type) ──────────────────────────────────
    /// @notice Predict an ECDSA instance address (VIEW, time-free).
    /// @param p The ECDSA create params.
    /// @param mode The deployment shell (clone or UUPS proxy).
    /// @param deployer The deployer the salt is bound to.
    /// @param userSalt The caller-supplied salt component.
    function predictECDSAAirdropAddress(
        ECDSAAirdropParams calldata p,
        DeploymentMode mode,
        address deployer,
        bytes32 userSalt
    ) external view returns (address);

    /// @notice Predict a Merkle instance address (VIEW, time-free).
    /// @param p The Merkle create params.
    /// @param mode The deployment shell (clone or UUPS proxy).
    /// @param deployer The deployer the salt is bound to.
    /// @param userSalt The caller-supplied salt component.
    function predictMerkleAirdropAddress(
        MerkleAirdropParams calldata p,
        DeploymentMode mode,
        address deployer,
        bytes32 userSalt
    ) external view returns (address);

    /// @notice Init-code hash for the ECDSA impl under `mode` (clone: the canonical EIP-1167 init code;
    ///         UUPS: the `ERC1967Proxy` init code with the impl encoded in).
    /// @param p The ECDSA create params (unused — the hash depends only on the impl and `mode`).
    /// @param mode The deployment shell (clone or UUPS proxy).
    function getECDSAInitCodeHash(ECDSAAirdropParams calldata p, DeploymentMode mode) external view returns (bytes32);

    /// @notice Init-code hash for the Merkle impl under `mode` (clone: the canonical EIP-1167 init code;
    ///         UUPS: the `ERC1967Proxy` init code with the impl encoded in).
    /// @param p The Merkle create params (unused — the hash depends only on the impl and `mode`).
    /// @param mode The deployment shell (clone or UUPS proxy).
    function getMerkleInitCodeHash(MerkleAirdropParams calldata p, DeploymentMode mode) external view returns (bytes32);

    // ───────────────────────────── airdrop enumeration ─────────────────────────────────────────────
    /// @notice The number of airdrops created by this factory.
    function airdropCount() external view returns (uint256);

    /// @notice The airdrop at `index` in creation order. Reverts IndexOutOfBounds if index >= count.
    /// @param index The position in creation order.
    /// @return airdrop The instance address at `index`.
    function airdropAt(uint256 index) external view returns (address airdrop);

    /// @notice Paginated slice in creation order; `limit` clamped to the remaining tail.
    /// @param offset The starting index in creation order.
    /// @param limit The maximum number of entries to return.
    /// @return page The slice of instance addresses.
    function airdrops(uint256 offset, uint256 limit) external view returns (address[] memory page);

    // ───────────────────────────── fee management (FEE_MANAGER_ROLE) ──────────────────────────────
    /// @notice Set the fee collector.
    /// @param feeCollector The new fee collector address.
    function setFeeCollector(address feeCollector) external;

    /// @notice Set the global default gas fee.
    /// @param gasFee The new default gas fee (wei).
    function setDefaultGasFee(uint96 gasFee) external;

    /// @notice Set a per-creator custom gas fee.
    /// @param creator The creator the override applies to.
    /// @param gasFee The custom gas fee (wei).
    function setCustomFee(address creator, uint96 gasFee) external;

    /// @notice Disable a per-creator custom gas fee.
    /// @param creator The creator whose override is cleared.
    function disableCustomFee(address creator) external;

    /// @notice The per-creator custom fee entry.
    /// @param creator The creator to look up.
    function getCustomFee(address creator) external view returns (CustomFee memory);

    /// @notice The fee collector address.
    function feeCollector() external view returns (address);

    /// @notice The global default gas fee (wei).
    function defaultGasFee() external view returns (uint256);

    // ───────────────────────────── gas-fee maximum (DEFAULT_ADMIN_ROLE) ───────────────────────────
    /// @notice Set the factory's own maximum on every gas fee `setDefaultGasFee`/`setCustomFee` may configure
    ///         and on the fee resolved at create. Gated by `DEFAULT_ADMIN_ROLE`, not `FEE_MANAGER_ROLE` -
    ///         separation of duties: the fee manager may only move fees within a bound the admin controls.
    /// @param maxGasFee The new maximum (wei). 0 admits only a zero fee.
    function setMaxGasFee(uint96 maxGasFee) external;

    /// @notice The factory's own gas-fee maximum (wei).
    function maxGasFee() external view returns (uint256);

    // ───────────────────────────── impl management (IMPL_MANAGER_ROLE) ────────────────────────────
    /// @notice Set the ECDSA airdrop implementation.
    /// @param implementation The new ECDSA impl address.
    function setEcdsaImplementation(address implementation) external;

    /// @notice Set the Merkle airdrop implementation.
    /// @param implementation The new Merkle impl address.
    function setMerkleImplementation(address implementation) external;

    /// @notice The ECDSA airdrop implementation address.
    function ecdsaImplementation() external view returns (address);

    /// @notice The Merkle airdrop implementation address.
    function merkleImplementation() external view returns (address);

    // ───────────────────────────── compliance wiring (COMPLIANCE_WIRING_ROLE) ─────────────────────
    /// @notice Set the compliance-manager implementation.
    /// @param implementation The new manager impl address.
    function setComplianceManagerImpl(address implementation) external;

    /// @notice Set the platform compliance delegate.
    /// @param delegate The new platform compliance delegate address.
    function setComplianceDelegate(address delegate) external;

    /// @notice Set the global default compliance-delegation flag.
    /// @param on The new global default value.
    function setDefaultDelegateToCompliance(bool on) external;

    /// @notice Set a per-deployer compliance policy override.
    /// @param creator The creator the override applies to.
    /// @param delegateToCompliance The override value.
    function setCompliancePolicy(address creator, bool delegateToCompliance) external;

    /// @notice Clear a per-deployer compliance policy override.
    /// @param creator The creator whose override is cleared.
    function clearCompliancePolicy(address creator) external;

    // ───────────────────────────── compliance views ───────────────────────────────────────────────
    /// @notice The compliance-manager implementation address.
    function complianceManagerImpl() external view returns (address);

    /// @notice The instance's own `ComplianceRoleManager` clone; `address(0)` ⟺ not created here.
    /// @param airdrop The instance to look up.
    function complianceManagerOf(address airdrop) external view returns (address);

    /// @notice True if THIS factory created `candidate` - the client-side genuineness check. A caller must
    ///         still address the canonical factory: nothing observable at an instance itself proves which
    ///         factory, if any, deployed it.
    /// @param candidate The address to check.
    function isAirdrop(address candidate) external view returns (bool);

    /// @notice The platform compliance delegate address.
    function complianceDelegate() external view returns (address);

    /// @notice The per-deployer compliance policy entry.
    /// @param creator The creator to look up.
    function getCompliancePolicy(address creator) external view returns (CompliancePolicy memory);

    /// @notice = per-deployer override ?? global default — resolved exactly as `create` does.
    /// @param creator The creator to resolve the policy for.
    function effectiveDelegateToCompliance(address creator) external view returns (bool);

    // ─────────────────────────── upgradeability gate (UPGRADE_MANAGER_ROLE) ───────────────────────
    /// @notice Set the global default upgradeability flag.
    /// @dev When `false` (the deploy default), every deployer is forced to `DeploymentMode.Clone` unless
    ///      a per-creator override allows them; flipping it `true` lets every deployer choose UUPS.
    /// @param allowed The new global default.
    function setDefaultUpgradeable(bool allowed) external;

    /// @notice Set a per-creator upgradeability override (wins over the global default).
    /// @param creator The creator the override applies to.
    /// @param allowed Whether that creator may create UUPS instances.
    function setUpgradeabilityPolicy(address creator, bool allowed) external;

    /// @notice Clear a per-creator upgradeability override (the creator reverts to the global default).
    /// @param creator The creator whose override is cleared.
    function clearUpgradeabilityPolicy(address creator) external;

    /// @notice The global default upgradeability flag.
    function defaultUpgradeable() external view returns (bool);

    /// @notice The per-creator upgradeability override entry.
    /// @param creator The creator to look up.
    function getUpgradeabilityPolicy(address creator) external view returns (UpgradeabilityPolicy memory);

    /// @notice = per-creator override ?? global default — resolved exactly as `create` enforces the gate.
    /// @param creator The creator to resolve the policy for.
    function effectiveUpgradeable(address creator) external view returns (bool);
}
