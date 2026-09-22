// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {FHE, euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {IERC7984} from "@openzeppelin/confidential-contracts/interfaces/IERC7984.sol";

import {AirdropERC1967Proxy} from "./AirdropERC1967Proxy.sol";
import {AirdropFactoryStorage} from "../storage/AirdropFactoryStorage.sol";
import {
    CustomFee,
    CompliancePolicy,
    UpgradeabilityPolicy,
    FactoryRoles,
    IAirdropFactory
} from "../interfaces/IAirdropFactory.sol";
import {IConfidentialAirdropBase} from "../interfaces/IConfidentialAirdropBase.sol";
import {IECDSAConfidentialAirdrop} from "../interfaces/IECDSAConfidentialAirdrop.sol";
import {IECDSAConfidentialAirdropTypes} from "../interfaces/IECDSAConfidentialAirdropTypes.sol";
import {IMerkleConfidentialAirdrop} from "../interfaces/IMerkleConfidentialAirdrop.sol";
import {IMerkleConfidentialAirdropTypes} from "../interfaces/IMerkleConfidentialAirdropTypes.sol";
import {IComplianceRoleManager} from "../interfaces/IComplianceRoleManager.sol";

/**
 * @title AirdropFactory
 * @author TokenOps
 * @notice Single factory that produces confidential airdrop instances of a chosen authorization variant
 *         (ECDSA or Merkle) and deployment shell (a minimal-proxy clone or an upgradeable UUPS proxy), and
 *         for each instance also creates and wires the instance's own per-campaign compliance manager. Every
 *         instance lands at a deterministic, front-run-protected address derived from the caller, the chosen
 *         shell and a caller-supplied salt. The factory is the single source of the fee configuration (the
 *         gas fee frozen into each instance at init and the collector seeded into it) and of the compliance
 *         policy (whether new instances delegate decryption to the platform compliance address), and it
 *         governs whether a deployer may create an upgradeable instance at all. It keeps an append-only,
 *         on-chain list of every instance it created so the full set is enumerable without an external
 *         indexer, and it can fund any instance it created with an encrypted amount in a single call.
 * @dev    A system singleton deployed once per chain at a deterministic address (its create entrypoints are
 *         permissionless — the caller-bound salt provides front-run protection). It is NOT cloned and NOT
 *         upgraded, so it uses the non-upgradeable OpenZeppelin utilities and wires the FHE coprocessor in its
 *         constructor (via `ZamaEthereumConfig`); the constructor — not an initializer — sets the admin roles
 *         and the initial impl/manager/fee wiring. Per-instance shells are OpenZeppelin CREATE2 deploys (an
 *         EIP-1167 clone via `Clones`, or an `AirdropERC1967Proxy` deployed with a salted `new`) and the
 *         per-instance manager is an OpenZeppelin `Clones` CREATE2 deploy; both are initialized atomically in
 *         the same create call. Nothing chain-specific enters any address derivation, so identical inputs
 *         yield identical instance addresses on every chain.
 */
contract AirdropFactory is IAirdropFactory, ZamaEthereumConfig, AccessControlEnumerable, AirdropFactoryStorage {
    // ───────────────────────────── roles (one per scope) ──────────────────────────────────────────
    /// @inheritdoc IAirdropFactory
    bytes32 public constant override FEE_MANAGER_ROLE = keccak256("FEE_MANAGER_ROLE");
    /// @inheritdoc IAirdropFactory
    bytes32 public constant override IMPL_MANAGER_ROLE = keccak256("IMPL_MANAGER_ROLE");
    /// @inheritdoc IAirdropFactory
    bytes32 public constant override COMPLIANCE_WIRING_ROLE = keccak256("COMPLIANCE_WIRING_ROLE");
    // Its own scope, mirroring FEE_MANAGER_ROLE; admin = DEFAULT_ADMIN_ROLE.
    /// @inheritdoc IAirdropFactory
    bytes32 public constant override UPGRADE_MANAGER_ROLE = keccak256("UPGRADE_MANAGER_ROLE");

    // ───────────────────────────────────── construction ───────────────────────────────────────────
    /**
     * @notice Deploys the factory, wiring it with the airdrop implementations it deploys, the manager
     *         implementation it clones per instance, the initial fee configuration, and the per-scope
     *         management roles.
     * @dev The constructor always runs for this singleton (it is neither a clone nor a proxy), so it both
     *      wires the FHE coprocessor (via the inherited `ZamaEthereumConfig` constructor) and sets state. The
     *      compliance policy (the platform delegate and the global delegation default) and the upgradeability
     *      default are intentionally left at their zero values — delegate `address(0)`, delegation OFF, and
     *      upgrades OFF — and are configured post-deploy via the `COMPLIANCE_WIRING_ROLE` / `UPGRADE_MANAGER_ROLE`
     *      setters; the standard deploy procedure turns the compliance delegation default ON afterwards. The
     *      gas-fee maximum, by contrast, is seeded here rather than left to default: the deployer must state
     *      the platform maximum explicitly (pass `type(uint96).max` for "unbounded"), and it is likewise
     *      movable post-deploy via `setMaxGasFee` (`DEFAULT_ADMIN_ROLE`).
     * @param roles The per-scope management addresses; any field left zero defaults to `roles.admin`.
     * @param ecdsaImplementation_ The ECDSA airdrop implementation to clone/proxy for ECDSA campaigns.
     * @param merkleImplementation_ The Merkle airdrop implementation to clone/proxy for Merkle campaigns.
     * @param complianceManagerImpl_ The compliance-manager implementation cloned once per instance.
     * @param feeCollector_ The initial fee collector seeded into every new instance.
     * @param defaultGasFee_ The initial global default per-claim gas fee (wei).
     * @param maxGasFee_ The initial factory-wide maximum every gas fee is bounded by (wei).
     */
    constructor(
        FactoryRoles memory roles,
        address ecdsaImplementation_,
        address merkleImplementation_,
        address complianceManagerImpl_,
        address feeCollector_,
        uint96 defaultGasFee_,
        uint96 maxGasFee_
    ) {
        if (roles.admin == address(0)) revert ZeroAdmin();
        if (defaultGasFee_ > maxGasFee_) revert GasFeeExceedsMaximum(defaultGasFee_, maxGasFee_);
        if (ecdsaImplementation_ == address(0) || merkleImplementation_ == address(0)) revert ZeroImplementation();
        if (complianceManagerImpl_ == address(0)) revert ZeroComplianceManagerImpl();
        if (feeCollector_ == address(0)) revert ZeroFeeCollector();

        FactoryMainStorage storage $ = _getFactoryStorage();
        $.ecdsaImplementation = ecdsaImplementation_;
        $.merkleImplementation = merkleImplementation_;
        $.complianceManagerImpl = complianceManagerImpl_;
        $.feeCollector = feeCollector_;
        $.defaultGasFee = defaultGasFee_;
        $.maxGasFee = maxGasFee_;

        // DEFAULT_ADMIN_ROLE is the admin of every management role by OZ default (no _setRoleAdmin needed).
        _grantRole(DEFAULT_ADMIN_ROLE, roles.admin);
        _grantRole(FEE_MANAGER_ROLE, roles.feeManager == address(0) ? roles.admin : roles.feeManager);
        _grantRole(IMPL_MANAGER_ROLE, roles.implManager == address(0) ? roles.admin : roles.implManager);
        _grantRole(COMPLIANCE_WIRING_ROLE, roles.complianceWiring == address(0) ? roles.admin : roles.complianceWiring);
        _grantRole(UPGRADE_MANAGER_ROLE, roles.upgradeManager == address(0) ? roles.admin : roles.upgradeManager);
    }

    // ───────────────────────────── create (per-type) ──────────────────────────────────────────────
    /// @inheritdoc IAirdropFactory
    function createECDSAConfidentialAirdrop(
        ECDSAAirdropParams calldata p,
        DeploymentMode mode,
        bytes32 userSalt
    ) public override returns (address airdrop) {
        address clone;
        BaseInitParams memory base;
        address complianceDelegateOrZero;
        (airdrop, clone, base, complianceDelegateOrZero) = _create(
            _getFactoryStorage().ecdsaImplementation,
            p.common,
            mode,
            userSalt
        );
        // Step 5 — initialize the instance atomically (same tx); the variant fields are the only difference.
        IECDSAConfidentialAirdrop(airdrop).initialize(
            IECDSAConfidentialAirdropTypes.ECDSAInitParams({base: base, signer: p.signer, dedupMode: p.dedupMode})
        );
        _record(airdrop, clone, p.common.token, AirdropType.ECDSA, mode, userSalt, complianceDelegateOrZero);
    }

    /// @inheritdoc IAirdropFactory
    function createMerkleConfidentialAirdrop(
        MerkleAirdropParams calldata p,
        DeploymentMode mode,
        bytes32 userSalt
    ) public override returns (address airdrop) {
        address clone;
        BaseInitParams memory base;
        address complianceDelegateOrZero;
        (airdrop, clone, base, complianceDelegateOrZero) = _create(
            _getFactoryStorage().merkleImplementation,
            p.common,
            mode,
            userSalt
        );
        IMerkleConfidentialAirdrop(airdrop).initialize(
            IMerkleConfidentialAirdropTypes.MerkleInitParams({
                base: base,
                merkleRoot: p.merkleRoot,
                isMerkleRootMutable: p.isMerkleRootMutable
            })
        );
        _record(airdrop, clone, p.common.token, AirdropType.Merkle, mode, userSalt, complianceDelegateOrZero);
    }

    /// @inheritdoc IAirdropFactory
    function createAndFundECDSAConfidentialAirdrop(
        ECDSAAirdropParams calldata p,
        DeploymentMode mode,
        bytes32 userSalt,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external override returns (address airdrop) {
        airdrop = createECDSAConfidentialAirdrop(p, mode, userSalt); // internal jump — msg.sender preserved
        address clone = _getFactoryStorage().complianceManagerOf[airdrop];
        _fundAirdrop(p.common.token, airdrop, clone, encryptedAmount, inputProof);
    }

    /// @inheritdoc IAirdropFactory
    function createAndFundMerkleConfidentialAirdrop(
        MerkleAirdropParams calldata p,
        DeploymentMode mode,
        bytes32 userSalt,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external override returns (address airdrop) {
        airdrop = createMerkleConfidentialAirdrop(p, mode, userSalt);
        address clone = _getFactoryStorage().complianceManagerOf[airdrop];
        _fundAirdrop(p.common.token, airdrop, clone, encryptedAmount, inputProof);
    }

    // ───────────────────────────── fund (already-created only) ────────────────────────────────────
    /// @inheritdoc IAirdropFactory
    function fundConfidentialAirdrop(
        address airdrop,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external override {
        // Existence check: only an airdrop THIS factory created has a recorded manager clone. Funding an
        // unknown address is rejected so funds can never land at an instance this factory did not deploy.
        address managerClone = _getFactoryStorage().complianceManagerOf[airdrop];
        if (managerClone == address(0)) revert UnknownAirdrop();
        _fundAirdrop(IConfidentialAirdropBase(airdrop).token(), airdrop, managerClone, encryptedAmount, inputProof);
    }

    // ───────────────────────── address prediction (per-type) ──────────────────────────────────────
    // The instance address commits ONLY to (impl-by-variant, mode) beyond (deployer, userSalt) — never to
    // the token/window/signer/root/collector/policy/fee. So these oracles consume only the implied
    // variant impl; the params struct is otherwise unused, and the gate in `_create` is NOT applied here (a
    // prediction is a pure address oracle — it answers "where would it land", even for a deployer not yet
    // allowed to deploy UUPS).
    /// @inheritdoc IAirdropFactory
    function predictECDSAAirdropAddress(
        ECDSAAirdropParams calldata,
        DeploymentMode mode,
        address deployer,
        bytes32 userSalt
    ) external view override returns (address) {
        return _predictInstance(_getFactoryStorage().ecdsaImplementation, mode, deployer, userSalt);
    }

    /// @inheritdoc IAirdropFactory
    function predictMerkleAirdropAddress(
        MerkleAirdropParams calldata,
        DeploymentMode mode,
        address deployer,
        bytes32 userSalt
    ) external view override returns (address) {
        return _predictInstance(_getFactoryStorage().merkleImplementation, mode, deployer, userSalt);
    }

    /// @inheritdoc IAirdropFactory
    function getECDSAInitCodeHash(
        ECDSAAirdropParams calldata,
        DeploymentMode mode
    ) external view override returns (bytes32) {
        return _initCodeHash(_getFactoryStorage().ecdsaImplementation, mode);
    }

    /// @inheritdoc IAirdropFactory
    function getMerkleInitCodeHash(
        MerkleAirdropParams calldata,
        DeploymentMode mode
    ) external view override returns (bytes32) {
        return _initCodeHash(_getFactoryStorage().merkleImplementation, mode);
    }

    // ───────────────────────────── airdrop enumeration ────────────────────────────────────────────
    /// @inheritdoc IAirdropFactory
    function airdropCount() external view override returns (uint256) {
        return _getFactoryStorage().deployedAirdrops.length;
    }

    /// @inheritdoc IAirdropFactory
    function airdropAt(uint256 index) external view override returns (address airdrop) {
        address[] storage list = _getFactoryStorage().deployedAirdrops;
        if (index >= list.length) revert IndexOutOfBounds(index, list.length);
        return list[index];
    }

    /// @inheritdoc IAirdropFactory
    function airdrops(uint256 offset, uint256 limit) external view override returns (address[] memory page) {
        address[] storage list = _getFactoryStorage().deployedAirdrops;
        uint256 len = list.length;
        if (offset >= len) return new address[](0); // past the tail ⇒ empty slice (no revert)
        uint256 remaining = len - offset;
        uint256 n = limit < remaining ? limit : remaining; // clamp to the tail (avoids offset+limit overflow)
        page = new address[](n);
        for (uint256 i; i < n; ++i) {
            page[i] = list[offset + i];
        }
    }

    // ───────────────────────────── fee management (FEE_MANAGER_ROLE) ──────────────────────────────
    /// @inheritdoc IAirdropFactory
    function setFeeCollector(address feeCollector_) external override onlyRole(FEE_MANAGER_ROLE) {
        if (feeCollector_ == address(0)) revert ZeroFeeCollector();
        _getFactoryStorage().feeCollector = feeCollector_;
        emit FeeCollectorSet(feeCollector_);
    }

    /// @inheritdoc IAirdropFactory
    function setDefaultGasFee(uint96 gasFee) external override onlyRole(FEE_MANAGER_ROLE) {
        FactoryMainStorage storage $ = _getFactoryStorage();
        if (gasFee > $.maxGasFee) revert GasFeeExceedsMaximum(gasFee, $.maxGasFee);
        $.defaultGasFee = gasFee;
        emit SetDefaultGasFee(gasFee);
    }

    /// @inheritdoc IAirdropFactory
    function setCustomFee(address creator, uint96 gasFee) external override onlyRole(FEE_MANAGER_ROLE) {
        FactoryMainStorage storage $ = _getFactoryStorage();
        if (gasFee > $.maxGasFee) revert GasFeeExceedsMaximum(gasFee, $.maxGasFee);
        $.customFees[creator] = CustomFee({enabled: true, gasFee: gasFee});
        emit SetCustomFee(creator, gasFee);
    }

    /// @inheritdoc IAirdropFactory
    function disableCustomFee(address creator) external override onlyRole(FEE_MANAGER_ROLE) {
        delete _getFactoryStorage().customFees[creator];
        emit CustomFeeDisabled(creator);
    }

    /// @inheritdoc IAirdropFactory
    function getCustomFee(address creator) external view override returns (CustomFee memory) {
        return _getFactoryStorage().customFees[creator];
    }

    /// @inheritdoc IAirdropFactory
    function feeCollector() external view override returns (address) {
        return _getFactoryStorage().feeCollector;
    }

    /// @inheritdoc IAirdropFactory
    function defaultGasFee() external view override returns (uint256) {
        return _getFactoryStorage().defaultGasFee;
    }

    // ───────────────────────────── gas-fee maximum (DEFAULT_ADMIN_ROLE) ───────────────────────────
    /// @inheritdoc IAirdropFactory
    function setMaxGasFee(uint96 maxGasFee_) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        // No lower bound against the current default/custom fees: lowering the maximum below them is
        // allowed, and simply blocks creates (GasFeeExceedsMaximum) until the fee manager brings the
        // offending fee back under it. Existing custom fees are never rewritten by this call.
        _getFactoryStorage().maxGasFee = maxGasFee_;
        emit SetMaxGasFee(maxGasFee_);
    }

    /// @inheritdoc IAirdropFactory
    function maxGasFee() external view override returns (uint256) {
        return _getFactoryStorage().maxGasFee;
    }

    // ───────────────────────────── impl management (IMPL_MANAGER_ROLE) ────────────────────────────
    /// @inheritdoc IAirdropFactory
    function setEcdsaImplementation(address implementation) external override onlyRole(IMPL_MANAGER_ROLE) {
        if (implementation == address(0)) revert ZeroImplementation();
        _getFactoryStorage().ecdsaImplementation = implementation;
        emit EcdsaImplementationSet(implementation);
    }

    /// @inheritdoc IAirdropFactory
    function setMerkleImplementation(address implementation) external override onlyRole(IMPL_MANAGER_ROLE) {
        if (implementation == address(0)) revert ZeroImplementation();
        _getFactoryStorage().merkleImplementation = implementation;
        emit MerkleImplementationSet(implementation);
    }

    /// @inheritdoc IAirdropFactory
    function ecdsaImplementation() external view override returns (address) {
        return _getFactoryStorage().ecdsaImplementation;
    }

    /// @inheritdoc IAirdropFactory
    function merkleImplementation() external view override returns (address) {
        return _getFactoryStorage().merkleImplementation;
    }

    // ───────────────── compliance wiring (COMPLIANCE_WIRING_ROLE) ──────────────────────────────────
    /// @inheritdoc IAirdropFactory
    function setComplianceManagerImpl(address implementation) external override onlyRole(COMPLIANCE_WIRING_ROLE) {
        if (implementation == address(0)) revert ZeroComplianceManagerImpl();
        _getFactoryStorage().complianceManagerImpl = implementation;
        emit ComplianceManagerImplSet(implementation);
    }

    /// @inheritdoc IAirdropFactory
    function setComplianceDelegate(address delegate) external override onlyRole(COMPLIANCE_WIRING_ROLE) {
        // Reject a zero delegate unconditionally: it is the single source for every policy-ON create — the
        // global default OR any per-creator override — so it must never be zero once configured. If the
        // default (or an override) is already ON when this is called, treating it as ON for any creator
        // would otherwise silently produce a manager with no compliance delegation.
        if (delegate == address(0)) revert ZeroComplianceDelegate();
        _getFactoryStorage().complianceDelegate = delegate;
        emit ComplianceDelegateSet(delegate);
    }

    /// @inheritdoc IAirdropFactory
    function setDefaultDelegateToCompliance(bool on) external override onlyRole(COMPLIANCE_WIRING_ROLE) {
        _getFactoryStorage().defaultDelegateToCompliance = on;
        emit DefaultDelegateToComplianceSet(on);
    }

    /// @inheritdoc IAirdropFactory
    function setCompliancePolicy(
        address creator,
        bool delegateToCompliance
    ) external override onlyRole(COMPLIANCE_WIRING_ROLE) {
        _getFactoryStorage().compliancePolicies[creator] = CompliancePolicy({
            overridden: true,
            delegateToCompliance: delegateToCompliance
        });
        emit CompliancePolicySet(creator, delegateToCompliance);
    }

    /// @inheritdoc IAirdropFactory
    function clearCompliancePolicy(address creator) external override onlyRole(COMPLIANCE_WIRING_ROLE) {
        delete _getFactoryStorage().compliancePolicies[creator];
        emit CompliancePolicyCleared(creator);
    }

    // ───────────────────────────── compliance views ───────────────────────────────────────────────
    /// @inheritdoc IAirdropFactory
    function complianceManagerImpl() external view override returns (address) {
        return _getFactoryStorage().complianceManagerImpl;
    }

    /// @inheritdoc IAirdropFactory
    function complianceManagerOf(address airdrop) external view override returns (address) {
        return _getFactoryStorage().complianceManagerOf[airdrop];
    }

    /// @inheritdoc IAirdropFactory
    function isAirdrop(address candidate) external view override returns (bool) {
        return _getFactoryStorage().complianceManagerOf[candidate] != address(0);
    }

    /// @inheritdoc IAirdropFactory
    function complianceDelegate() external view override returns (address) {
        return _getFactoryStorage().complianceDelegate;
    }

    /// @inheritdoc IAirdropFactory
    function getCompliancePolicy(address creator) external view override returns (CompliancePolicy memory) {
        return _getFactoryStorage().compliancePolicies[creator];
    }

    /// @inheritdoc IAirdropFactory
    function effectiveDelegateToCompliance(address creator) external view override returns (bool) {
        return _effectiveDelegateToCompliance(creator);
    }

    // ─────────────────────── upgradeability gate (UPGRADE_MANAGER_ROLE) ────────────────────────────
    /// @inheritdoc IAirdropFactory
    function setDefaultUpgradeable(bool allowed) external override onlyRole(UPGRADE_MANAGER_ROLE) {
        _getFactoryStorage().defaultUpgradeable = allowed;
        emit DefaultUpgradeableSet(allowed);
    }

    /// @inheritdoc IAirdropFactory
    function setUpgradeabilityPolicy(address creator, bool allowed) external override onlyRole(UPGRADE_MANAGER_ROLE) {
        _getFactoryStorage().upgradeabilityPolicies[creator] = UpgradeabilityPolicy({
            overridden: true,
            allowed: allowed
        });
        emit UpgradeabilityPolicySet(creator, allowed);
    }

    /// @inheritdoc IAirdropFactory
    function clearUpgradeabilityPolicy(address creator) external override onlyRole(UPGRADE_MANAGER_ROLE) {
        delete _getFactoryStorage().upgradeabilityPolicies[creator];
        emit UpgradeabilityPolicyCleared(creator);
    }

    /// @inheritdoc IAirdropFactory
    function defaultUpgradeable() external view override returns (bool) {
        return _getFactoryStorage().defaultUpgradeable;
    }

    /// @inheritdoc IAirdropFactory
    function getUpgradeabilityPolicy(address creator) external view override returns (UpgradeabilityPolicy memory) {
        return _getFactoryStorage().upgradeabilityPolicies[creator];
    }

    /// @inheritdoc IAirdropFactory
    function effectiveUpgradeable(address creator) external view override returns (bool) {
        return _effectiveUpgradeable(creator);
    }

    // ───────────────────────────── admin-role floor ───────────────────────────────────────────────
    /**
     * @notice Role-revocation hook keeping `DEFAULT_ADMIN_ROLE` at one member or more.
     * @dev `DEFAULT_ADMIN_ROLE` administers every management role AND itself, so an empty admin set would
     *      permanently freeze all future grants and revokes: a compromised or lost management key could
     *      never be rotated out, and the factory is a non-upgradeable singleton with no recovery path short
     *      of a redeploy. The floor is therefore unconditional. Both `revokeRole` and `renounceRole` funnel
     *      through here; a hand-off still works by granting the successor first (count 2) then removing the
     *      predecessor. The management roles are untouched - they stay recoverable through this one.
     * @param role The role being revoked.
     * @param account The account losing the role.
     * @return revoked True iff `account` actually held `role` and it was removed.
     */
    function _revokeRole(bytes32 role, address account) internal override returns (bool revoked) {
        if (role == DEFAULT_ADMIN_ROLE && getRoleMemberCount(DEFAULT_ADMIN_ROLE) == 1 && hasRole(role, account)) {
            revert LastAdmin();
        }
        return super._revokeRole(role, account);
    }

    /**
     * @notice Role-grant hook rejecting an `address(0)` `DEFAULT_ADMIN_ROLE` grant.
     * @dev OZ treats a zero-address grant as an ordinary one, which would let the admin set "gain" a member
     *      that can never act and never be revoked, satisfying the floor above with a phantom. Other roles
     *      keep OZ's default behavior.
     * @param role The role being granted.
     * @param account The account receiving the role.
     * @return granted True iff `account` did not already hold `role` and it was added.
     */
    function _grantRole(bytes32 role, address account) internal override returns (bool granted) {
        if (role == DEFAULT_ADMIN_ROLE && account == address(0)) revert ZeroAdminGrant();
        return super._grantRole(role, account);
    }

    // ───────────────────────────── internal: create core (steps 0–5) ──────────────────────────────
    /**
     * @notice Shared create core for both variants: runs the upgradeability gate, resolves the frozen-at-create
     *         config, computes the deterministic addresses, deploys+initializes the instance's manager clone,
     *         and deploys the instance shell. The caller then initializes the instance with its variant fields
     *         and records it.
     * @dev The manager clone is deployed and initialized BEFORE the instance shell so its delegation-tuple
     *      distinctness check fails fast — the factory is the PRIMARY owner of that invariant: it
     *      supplies the predicted instance address (which the clone alone cannot know) plus the resolved
     *      compliance admin (as both client admin and client delegate) and the resolved compliance delegate,
     *      so a colliding config (e.g. a compliance delegate equal to the predicted instance) is rejected by
     *      the clone's `initialize` with a dedicated error and reverts the whole create. The manager salt
     *      derives from the predicted instance address, which commits to the variant impl and the deployment
     *      mode beyond the instance salt — so the two addresses vary in lockstep and stay distinct by
     *      construction (the clone address hashes over a different preimage). A true replay of an
     *      already-created tuple reverts `SaltAlreadyUsed` before any deploy; note that since the instance
     *      address no longer commits to the gas fee, two creates that differ ONLY in their effective fee now
     *      land at the SAME address and the second one reverts `SaltAlreadyUsed`.
     * @param impl The variant implementation (ECDSA or Merkle) to clone/proxy.
     * @param common The common create-time fields, copied into the base init params.
     * @param mode The deployment shell.
     * @param userSalt The caller-supplied salt component.
     * @return airdrop The deployed (uninitialized) instance shell.
     * @return clone The instance's own initialized compliance-manager clone.
     * @return base The base init params for the caller's variant `initialize` call.
     * @return complianceDelegateOrZero The compliance delegate the clone was wired with (zero ⟺ effective
     *         policy OFF).
     */
    function _create(
        address impl,
        CommonAirdropParams calldata common,
        DeploymentMode mode,
        bytes32 userSalt
    ) internal returns (address airdrop, address clone, BaseInitParams memory base, address complianceDelegateOrZero) {
        FactoryMainStorage storage $ = _getFactoryStorage();

        // Step 0 — the upgradeability gate: a UUPS instance may be created only if the caller's effective
        // policy allows it. Clone mode is never gated (clones are non-upgradeable regardless).
        if (mode == DeploymentMode.UUPS && !_effectiveUpgradeable(msg.sender)) revert UpgradeabilityNotAllowed();

        // Step 1 — resolve the config frozen into this instance forever. The gasFee is an init param (no
        // longer part of the address); the policy decides the manager's delegate.
        uint96 gasFee = _resolveGasFee(msg.sender);
        // The factory's own maximum is checked FIRST, before the creator's own bound: it is the platform
        // invariant, so a maximum lowered after a stale default/custom fee was set takes effect on the very
        // next create, independent of what the creator declared acceptable.
        if (gasFee > $.maxGasFee) revert GasFeeExceedsMaximum(gasFee, $.maxGasFee);
        // The most the creator accepts for this campaign; the factory-wide maximum is checked first.
        // Checked before anything is deployed and before the salt is consumed: fee state is
        // management-controlled and resolves at execution, so a create that was quoted against one fee can
        // otherwise freeze a different one in. The bound is literal - a zero `maxAcceptedGasFee` accepts
        // only a zero fee - so leaving the field unset never means "unbounded".
        if (gasFee > common.maxAcceptedGasFee) revert GasFeeNotAccepted(gasFee, common.maxAcceptedGasFee);
        // Compliance-delegate guard (every policy-ON create must wire a real delegate): if the effective
        // policy is ON but no delegate was ever wired, `ComplianceRoleManager.initialize` silently skips the
        // compliance delegation (it no-ops on a zero delegate) yet the create still emits success —
        // permanently shipping an instance with broken compliance. `setComplianceDelegate` already rejects a
        // zero delegate, but nothing stops turning the default/override ON *before* one is set. Fail the
        // create instead of shipping a silently-non-compliant instance (the delegate is expected to be wired
        // before the policy is turned on, so the normal deploy flow is unaffected).
        bool delegateOn = _effectiveDelegateToCompliance(msg.sender);
        if (delegateOn && $.complianceDelegate == address(0)) revert ZeroComplianceDelegate();
        complianceDelegateOrZero = delegateOn ? $.complianceDelegate : address(0);

        // Step 2 — the deterministic addresses (time- and chain-free). The instance must be predicted
        // now because the manager clone is initialized with it before the instance shell is deployed, AND
        // because the manager salt derives from it: the predicted instance commits to the impl and the mode
        // beyond `salt`, so the manager address moves in lockstep with the instance address — same-(creator,
        // userSalt) creates that differ in variant or mode, or a rotated impl, land BOTH contracts at fresh
        // addresses instead of colliding on the manager clone.
        bytes32 salt = _instanceSalt(msg.sender, userSalt);
        address predictedInstance = _predictInstanceAt(impl, mode, salt);

        bytes32 managerSalt = keccak256(abi.encode(predictedInstance, "compliance"));

        // Step 2b — reject a true replay with a dedicated error carrying the occupying instance (the caller
        // would otherwise need a predict query to learn which address collided). `predictedInstance` is
        // recorded iff a previous create used the identical (creator, userSalt, variant, mode) tuple; without
        // this check the replay would surface as OZ Clones' opaque `FailedDeployment()` from the manager
        // deploy below (which runs before the instance deploy, so that error is unreachable).
        if ($.complianceManagerOf[predictedInstance] != address(0)) revert SaltAlreadyUsed(predictedInstance);

        // Step 3 — deploy + initialize the manager clone. `complianceAdmin` (zero ⇒ msg.sender) is both the
        // clone's client admin and its client delegate; the platform delegate is wired iff the effective
        // policy is ON.
        address complianceAdmin = common.complianceAdmin == address(0) ? msg.sender : common.complianceAdmin;
        clone = Clones.cloneDeterministic($.complianceManagerImpl, managerSalt);
        IComplianceRoleManager(clone).initialize(
            predictedInstance,
            complianceAdmin,
            complianceAdmin,
            complianceDelegateOrZero
        );

        // Step 4 — deploy the instance shell.
        airdrop =
            mode == DeploymentMode.UUPS
                ? address(new AirdropERC1967Proxy{salt: salt}(impl)) // ERC-1967 proxy; impl slot upgradeable
                : Clones.cloneDeterministic(impl, salt); // EIP-1167 clone; non-upgradeable
        // `airdrop == predictedInstance` by CREATE2 determinism (same impl, mode, salt, deployer).

        // Step 5's params — the caller fills in the variant fields and calls `initialize`.
        base = BaseInitParams({
            token: common.token,
            startTime: common.startTime,
            endTime: common.endTime,
            canExtendClaimWindow: common.canExtendClaimWindow,
            unwrappable: common.unwrappable,
            gasFee: gasFee, // frozen into the instance's config storage at init; never in the address
            admin: msg.sender, // the creator becomes the instance DEFAULT_ADMIN_ROLE
            complianceManager: clone, // the instance's OWN manager clone (the sole compliance grant target)
            feeCollector: $.feeCollector // seeds FEE_COLLECTOR_ROLE; never in the address
        });
    }

    /**
     * @notice Records the created instance and emits the create events.
     * @dev `complianceManagerOf` doubles as the O(1) membership index backing `fund`'s existence check and the
     *      airdrop enumeration; `deployedAirdrops` is the append-only on-chain read-list.
     * @param airdrop The created instance.
     * @param clone The instance's manager clone.
     * @param token The underlying confidential token.
     * @param airdropType_ The created variant.
     * @param mode The deployment shell.
     * @param userSalt The caller-supplied salt component.
     * @param complianceDelegateOrZero The compliance delegate the clone was wired with (zero ⟺ policy OFF).
     */
    function _record(
        address airdrop,
        address clone,
        address token,
        AirdropType airdropType_,
        DeploymentMode mode,
        bytes32 userSalt,
        address complianceDelegateOrZero
    ) internal {
        FactoryMainStorage storage $ = _getFactoryStorage();
        $.complianceManagerOf[airdrop] = clone;
        $.deployedAirdrops.push(airdrop);
        emit ConfidentialAirdropCreated(airdrop, token, airdropType_, mode, msg.sender, userSalt);
        emit ComplianceManagerCloned(airdrop, clone, complianceDelegateOrZero);
    }

    /**
     * @notice Funds an instance with an encrypted amount, granting compliance read access.
     * @dev Imports the external amount (the factory is allowed on the result this tx), grants the funded handle
     *      (the REQUEST, kept as the compliance record of intent) to BOTH the instance's manager clone AND the
     *      instance itself — the delegated-decryption check needs both ACL pairs, and the instance never
     *      `allowThis`-es a factory-created handle — then lets the token read it transiently and pulls the
     *      funds. ERC-7984 transfers never revert on insufficiency: they move an encrypted 0, so the RETURNED
     *      `moved` handle (not the requested amount) is what is emitted. The airdrop-instance leg of `moved` is
     *      free — ERC-7984 `_update` already persistently ACLs the delivered handle to the recipient (`to` =
     *      `airdrop`) — but the manager-clone leg is NOT: the factory funded the transfer, so it (not the
     *      airdrop instance) is the only party that can `FHE.allow(moved, managerClone)`. Without that grant
     *      the compliance manager clone could read the pre-funding request handle but never the actual
     *      post-funding balance the token recorded, so it is granted here explicitly before the emit. The
     *      transfer also rotates the instance's aggregate BALANCE handle, on which the factory holds no ACL
     *      at all (an `FHE.allow` from here would revert), so the instance's own permissionless
     *      `refreshComplianceBalance` is called instead, leaving the post-funding balance readable to
     *      compliance; that call closes the function, after the emit, because no factory state follows it.
     *      The funder must have called `token.setOperator(factory, …)` first.
     * @param token The underlying confidential token.
     * @param airdrop The instance to fund.
     * @param managerClone The instance's manager clone.
     * @param encryptedAmount The encrypted funding amount.
     * @param inputProof The input proof for `encryptedAmount`.
     */
    function _fundAirdrop(
        address token,
        address airdrop,
        address managerClone,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) internal {
        euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
        FHE.allow(amount, managerClone); // grant #1 → the instance's OWN manager clone
        FHE.allow(amount, airdrop); // grant #2 → the instance itself (both pairs required for compliance reads)
        FHE.allowTransient(amount, token); // the token may read the amount this tx only
        euint64 moved = IERC7984(token).confidentialTransferFrom(msg.sender, airdrop, amount);
        FHE.allow(moved, managerClone); // the airdrop leg on `moved` is free via ERC-7984 `_update`; this is not
        emit ConfidentialAirdropFunded(airdrop, token, moved); // consume the RETURNED handle, not the request
        // The transfer rotated the instance's aggregate balance handle, which only the instance can grant.
        IConfidentialAirdropBase(airdrop).refreshComplianceBalance();
    }

    // ───────────────────────────── internal: resolution & prediction helpers ──────────────────────
    /// @dev Effective per-claim gas fee for `creator`: the per-creator override iff enabled, else the default.
    function _resolveGasFee(address creator) internal view returns (uint96) {
        CustomFee storage custom = _getFactoryStorage().customFees[creator];
        return custom.enabled ? custom.gasFee : _getFactoryStorage().defaultGasFee;
    }

    /// @dev Effective compliance-delegation policy for `creator`: the per-creator override iff set, else default.
    function _effectiveDelegateToCompliance(address creator) internal view returns (bool) {
        CompliancePolicy storage policy = _getFactoryStorage().compliancePolicies[creator];
        return policy.overridden ? policy.delegateToCompliance : _getFactoryStorage().defaultDelegateToCompliance;
    }

    /// @dev Effective upgradeability policy for `creator`: the per-creator override iff set, else the default.
    function _effectiveUpgradeable(address creator) internal view returns (bool) {
        UpgradeabilityPolicy storage policy = _getFactoryStorage().upgradeabilityPolicies[creator];
        return policy.overridden ? policy.allowed : _getFactoryStorage().defaultUpgradeable;
    }

    /// @dev Predicted instance address for `(impl, mode, deployer, userSalt)`.
    function _predictInstance(
        address impl,
        DeploymentMode mode,
        address deployer,
        bytes32 userSalt
    ) internal view returns (address) {
        return _predictInstanceAt(impl, mode, _instanceSalt(deployer, userSalt));
    }

    /// @dev Predicted instance address for `(impl, mode, salt)` against THIS factory as the CREATE2 deployer.
    function _predictInstanceAt(address impl, DeploymentMode mode, bytes32 salt) internal view returns (address) {
        return
            mode == DeploymentMode.UUPS
                ? Create2.computeAddress(salt, _uupsInitCodeHash(impl), address(this))
                : Clones.predictDeterministicAddress(impl, salt, address(this));
    }

    /// @dev Init-code hash for `(impl, mode)` — the canonical EIP-1167 clone code, or the `AirdropERC1967Proxy`
    ///      init code with `impl` encoded in.
    function _initCodeHash(address impl, DeploymentMode mode) internal pure returns (bytes32) {
        return
            mode == DeploymentMode.UUPS
                ? _uupsInitCodeHash(impl)
                : keccak256(
                    abi.encodePacked(
                        hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
                        impl,
                        hex"5af43d82803e903d91602b57fd5bf3"
                    )
                );
    }

    /// @dev Init-code hash of the `AirdropERC1967Proxy` deployed for `impl` — exactly the creation code
    ///      `new AirdropERC1967Proxy(impl)` produces, so it matches what step 4 actually deploys.
    function _uupsInitCodeHash(address impl) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(type(AirdropERC1967Proxy).creationCode, abi.encode(impl)));
    }

    /**
     * @notice Front-run-protected, time- and chain-free instance salt.
     * @dev `abi.encode` (NOT `encodePacked`) for a fixed-length, collision-resistant preimage. `deployer`
     *      gives front-run protection (only that deployer lands at the predicted address). The deployment
     *      mode is NOT folded in here — a clone and a UUPS proxy of otherwise-identical params already land
     *      at different addresses because their init code differs. No block time/number, chainId, blockhash
     *      or RNG ever enters this derivation.
     * @param deployer The create caller.
     * @param userSalt The caller-supplied salt component.
     * @return The instance salt.
     */
    function _instanceSalt(address deployer, bytes32 userSalt) internal pure returns (bytes32) {
        return keccak256(abi.encode(deployer, userSalt));
    }
}
