// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

/**
 * @title IComplianceRoleManager
 * @author TokenOps
 * @notice External surface of the per-instance `ComplianceRoleManager` CLONE.
 * @dev The factory clones this impl once per airdrop and calls `initialize` atomically. The clone
 *      performs ADDRESS-DELEGATION ONLY: account-level user-decryption delegation scoped to
 *      (delegator = the clone, contractAddress = the airdrop instance), at permanent expiry. It carries
 *      NO disclosure surface, NO reader role, NO registry. The platform compliance delegation (if set at
 *      init) is irrevocable by construction.
 */
interface IComplianceRoleManager {
    // ───────────────────────────── events ─────────────────────────────────────────────────
    /// @notice Emitted once, at init, iff policy ON, when the platform compliance delegate is set.
    /// @param delegate The factory-designated platform compliance delegate.
    event ComplianceDelegateSet(address indexed delegate); // once, at init, iff policy ON
    /// @notice Emitted when a client delegate is added.
    /// @param delegate The client delegate that was added.
    event ClientDelegateAdded(address indexed delegate);
    /// @notice Emitted when a client delegate is revoked.
    /// @param delegate The client delegate that was revoked.
    event ClientDelegateRevoked(address indexed delegate);

    // ───────────────────────────── errors ────────────────────────────────────────────
    error ZeroAirdrop(); //                 initialize: airdrop_ == 0
    error ZeroClientAdmin(); //             initialize: clientAdmin == 0
    /// @notice initialize: `airdrop_ == address(this)` (delegator == contractAddress).
    /// @param airdrop The colliding airdrop address (== this manager clone).
    error AirdropAndManagerAreSameAddress(address airdrop);
    /// @notice initialize: a delegate == address(this) (delegate == delegator).
    /// @param delegate The colliding delegate — tells the caller WHICH of the client/compliance delegates hit.
    error DelegateAndManagerAreSameAddress(address delegate);
    /// @notice initialize: a delegate == airdrop_ (delegate == contractAddress).
    /// @param delegate The colliding delegate — tells the caller WHICH of the client/compliance delegates hit.
    error DelegateAndAirdropAreSameAddress(address delegate);
    error ZeroDelegate(); //                add/revokeDelegate: delegate == 0
    error DelegateAlreadyAdded(); //        addDelegate: already an active client delegate
    error DelegateNotFound(); //            revokeDelegate: not an active client delegate
    error CannotManageComplianceDelegate(); // add/revokeDelegate targeting the factory-designated delegate

    // ───────────────────────────── roles ──────────────────────────────────────────────────
    /// @notice The role authorized to add/revoke client delegations.
    function DELEGATION_ADMIN_ROLE() external view returns (bytes32);

    // ───────────────────────────── lifecycle ──────────────────────────────────────────────
    /// @notice Factory-called clone init: wires the coprocessor, performs the scoped permanent compliance
    ///         delegation (iff complianceDelegate_ != 0) and the client delegation, and grants the client
    ///         DEFAULT_ADMIN_ROLE + DELEGATION_ADMIN_ROLE.
    /// @param airdrop_ The (predicted, deterministic) airdrop instance this clone serves.
    /// @param clientAdmin The createAirdrop caller — master admin of this clone.
    /// @param clientDelegate The client/deployer delegate (normally == clientAdmin).
    /// @param complianceDelegate_ The factory's platform compliance delegate iff policy ON, else address(0).
    function initialize(
        address airdrop_,
        address clientAdmin,
        address clientDelegate,
        address complianceDelegate_
    ) external;

    // ───────────────────────────── client delegation mgmt ─────────────────────────────────
    /// @notice Delegate user decryption for THIS clone's airdrop to `delegate` (client-side, permanent
    ///         expiry, revocable). Reverts CannotManageComplianceDelegate for the platform delegate.
    /// @param delegate The client delegate to add.
    function addDelegate(address delegate) external;

    /// @notice Revoke a CLIENT delegation. Reverts CannotManageComplianceDelegate / DelegateNotFound.
    /// @param delegate The client delegate to revoke.
    function revokeDelegate(address delegate) external;

    // ───────────────────────────── views ──────────────────────────────────────────────────
    /// @notice The ONE airdrop instance this clone serves.
    function airdrop() external view returns (address); //          the ONE instance this clone serves
    /// @notice The platform compliance delegate; address(0) iff policy was OFF.
    function complianceDelegate() external view returns (address); //  address(0) iff policy was OFF
    /// @notice The current set of active client delegates.
    function clientDelegates() external view returns (address[] memory);

    /// @notice Authoritative active-delegate check — reads the ACL expiry, not the mirror.
    /// @param delegate The address to check.
    function isActiveDelegate(address delegate) external view returns (bool);
}
