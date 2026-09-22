// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {FHE} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// solhint-disable-next-line max-line-length
import {AccessControlEnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ComplianceManagerStorage} from "../storage/ComplianceManagerStorage.sol";
import {IComplianceRoleManager} from "../interfaces/IComplianceRoleManager.sol";

/**
 * @title ComplianceRoleManager
 * @author TokenOps
 * @notice Per-instance compliance manager CLONE. The factory deploys ONE impl per chain via CREATE3 and
 *         clones it once per airdrop, calling `initialize` atomically inside the airdrop-creation call. Each
 *         clone serves exactly ONE airdrop and works on ACCOUNT-LEVEL user-decryption DELEGATION ONLY — scoped
 *         to (delegator = this clone, contractAddress = the airdrop instance), at permanent expiry
 *         (`type(uint64).max`).
 * @dev    Two delegates at most, fixed at creation: (a) the platform compliance delegate iff the
 *         factory-resolved policy was ON — IRREVOCABLE BY CONSTRUCTION (this contract exposes no path that
 *         revokes it, ACL revoke is `msg.sender`-keyed, and the clone is non-upgradeable); and (b) the
 *         client/deployer delegate — revocable via {revokeDelegate}. A single delegation covers ALL current
 *         AND future handles the clone is granted for that airdrop — zero per-handle txs. Carries NO
 *         disclosure surface, NO reader role, NO registry (those live on the airdrop instance). The FHE
 *         coprocessor is wired in `initialize` (clones never run the impl constructor).
 */
contract ComplianceRoleManager is
    IComplianceRoleManager,
    Initializable,
    AccessControlEnumerableUpgradeable,
    ComplianceManagerStorage
{
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @inheritdoc IComplianceRoleManager
    bytes32 public constant override DELEGATION_ADMIN_ROLE = keccak256("DELEGATION_ADMIN_ROLE");

    /// @notice Locks the bare CREATE3 impl; only clones initialize.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @inheritdoc IComplianceRoleManager
    function initialize(
        address airdrop_,
        address clientAdmin,
        address clientDelegate,
        address complianceDelegate_
    ) external override initializer {
        if (airdrop_ == address(0)) revert ZeroAirdrop();
        if (clientAdmin == address(0)) revert ZeroClientAdmin();

        // DISTINCTNESS INVARIANT — DEFENCE IN DEPTH. The ACL requires the delegation tuple
        // (delegator = this clone, delegate, contractAddress = airdrop_) to be three distinct addresses, else
        // the FHE delegation calls below revert deep in the ACL and brick the create tx. The factory that
        // deploys this clone remains the primary owner of this invariant — airdrop_ is a predicted CREATE3
        // address that never collides with the configured platform/client EOAs. We additionally re-validate
        // it here so a misconfigured tuple fails with this contract's own dedicated error instead of the
        // ACL's, on both this init path and the runtime {addDelegate} path below.
        _requireDistinctDelegationTuple(airdrop_, clientDelegate, complianceDelegate_);

        // Clone wiring: the impl constructor never ran here, so the coprocessor and access-control state
        // must be wired inside this initializer instead.
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
        __AccessControl_init();

        ComplianceStorage storage $ = _getComplianceStorage();
        $.airdrop = airdrop_;

        // (a) THE PLATFORM COMPLIANCE DELEGATION — set once, here, iff the factory-resolved policy was ON.
        //     Scope: (delegator = this clone, contractAddress = airdrop_); expiry type(uint64).max
        //     (permanent). IRREVOCABLE BY CONSTRUCTION: no function in this contract ever revokes it.
        if (complianceDelegate_ != address(0)) {
            FHE.delegateUserDecryptionWithoutExpiration(complianceDelegate_, airdrop_);
            $.complianceDelegate = complianceDelegate_;
            emit ComplianceDelegateSet(complianceDelegate_);
        }

        // (b) THE CLIENT DELEGATION — same scope + permanent expiry; revocable by the client.
        //     ALIASING GUARD: if the client IS the platform delegate, skip — delegating the SAME
        //     (clone, delegate, airdrop) tuple twice in one block reverts AlreadyDelegatedOrRevokedInSameBlock
        //     and would brick the create call; the address is already covered (irrevocably) by (a).
        if (clientDelegate != address(0) && clientDelegate != complianceDelegate_) {
            _addClientDelegate($, clientDelegate);
        }

        // (c) client-side management roles — the client administers ONLY the client delegations.
        _grantRole(DEFAULT_ADMIN_ROLE, clientAdmin);
        _grantRole(DELEGATION_ADMIN_ROLE, clientAdmin);
    }

    /// @inheritdoc IComplianceRoleManager
    function addDelegate(address delegate) external override onlyRole(DELEGATION_ADMIN_ROLE) {
        if (delegate == address(0)) revert ZeroDelegate();
        ComplianceStorage storage $ = _getComplianceStorage();
        // Load-bearing guard: the platform delegation is irrevocable — never let a client touch its
        // ACL tuple (add-then-revoke would destroy it).
        if (delegate == $.complianceDelegate) revert CannotManageComplianceDelegate();
        _requireDistinctDelegationTuple($.airdrop, delegate, address(0));
        if ($.clientDelegates.contains(delegate)) revert DelegateAlreadyAdded();
        _addClientDelegate($, delegate);
    }

    /// @inheritdoc IComplianceRoleManager
    function revokeDelegate(address delegate) external override onlyRole(DELEGATION_ADMIN_ROLE) {
        if (delegate == address(0)) revert ZeroDelegate();
        ComplianceStorage storage $ = _getComplianceStorage();
        if (delegate == $.complianceDelegate) revert CannotManageComplianceDelegate();
        if (!$.clientDelegates.contains(delegate)) revert DelegateNotFound();
        // Effective on-chain immediately; off-chain delegated reads stop once the gateway observes the ACL
        // change (propagation to off-chain readers is not instantaneous).
        FHE.revokeUserDecryptionDelegation(delegate, $.airdrop);
        $.clientDelegates.remove(delegate);
        emit ClientDelegateRevoked(delegate);
    }

    /// @inheritdoc IComplianceRoleManager
    function airdrop() external view override returns (address) {
        return _getComplianceStorage().airdrop;
    }

    /// @inheritdoc IComplianceRoleManager
    function complianceDelegate() external view override returns (address) {
        return _getComplianceStorage().complianceDelegate;
    }

    /// @inheritdoc IComplianceRoleManager
    function clientDelegates() external view override returns (address[] memory) {
        return _getComplianceStorage().clientDelegates.values();
    }

    /// @inheritdoc IComplianceRoleManager
    function isActiveDelegate(address delegate) external view override returns (bool) {
        ComplianceStorage storage $ = _getComplianceStorage();
        // AUTHORITATIVE: read the ACL expiry, not the EnumerableSet mirror. A permanent delegation
        // stores type(uint64).max, which is always > block.timestamp.
        return FHE.getDelegatedUserDecryptionExpirationDate(address(this), delegate, $.airdrop) > block.timestamp;
    }

    /**
     * @notice Defence-in-depth check that the delegation tuple addresses are mutually distinct.
     * @dev The ACL requires (delegator = this clone, delegate, contractAddress = the airdrop) to be three
     *      distinct addresses; this re-validates that up front so a misconfigured tuple fails closed with a
     *      dedicated error instead of a deeper ACL revert. Shared by {initialize} (both delegates checked at
     *      once) and {addDelegate} (called with `complianceDelegate_ = address(0)` - a runtime delegate has no
     *      compliance-delegate leg to check). Reverts `AirdropAndManagerAreSameAddress` /
     *      `DelegateAndManagerAreSameAddress` / `DelegateAndAirdropAreSameAddress`.
     * @param airdrop_ The airdrop instance this clone serves.
     * @param clientDelegate The client/deployer delegate, or the runtime `addDelegate` candidate (may be zero).
     * @param complianceDelegate_ The platform compliance delegate (zero iff the policy was OFF, or when called
     *        from {addDelegate}).
     */
    function _requireDistinctDelegationTuple(
        address airdrop_,
        address clientDelegate,
        address complianceDelegate_
    ) private view {
        // Each error carries the offending address, so a caller wiring BOTH delegates can tell which
        // of the two collided (the bare conditions are otherwise indistinguishable from the selector).
        if (airdrop_ == address(this)) revert AirdropAndManagerAreSameAddress(airdrop_);
        if (complianceDelegate_ == address(this)) revert DelegateAndManagerAreSameAddress(complianceDelegate_);
        if (complianceDelegate_ == airdrop_) revert DelegateAndAirdropAreSameAddress(complianceDelegate_);
        if (clientDelegate == address(this)) revert DelegateAndManagerAreSameAddress(clientDelegate);
        if (clientDelegate == airdrop_) revert DelegateAndAirdropAreSameAddress(clientDelegate);
    }

    /**
     * @notice Perform a client-side delegation and record it in the mirror.
     * @dev Shared by {initialize} (the init-time client leg) and {addDelegate}, so both emit
     *      `ClientDelegateAdded` and keep the EnumerableSet mirror in lockstep with the ACL.
     * @param cs The compliance storage pointer.
     * @param delegate The client delegate to add.
     */
    function _addClientDelegate(ComplianceStorage storage cs, address delegate) private {
        FHE.delegateUserDecryptionWithoutExpiration(delegate, cs.airdrop);
        cs.clientDelegates.add(delegate);
        emit ClientDelegateAdded(delegate);
    }
}
