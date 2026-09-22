// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {FHE, euint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

// solhint-disable-next-line max-line-length
import {AccessControlEnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IERC7984} from "@openzeppelin/confidential-contracts/interfaces/IERC7984.sol";

import {ConfidentialAirdropConfigStorage} from "../storage/ConfidentialAirdropConfigStorage.sol";
import {IConfidentialAirdropBase} from "../interfaces/IConfidentialAirdropBase.sol";
// Single wrapper-interface import. `IERC7984ERC20Wrapper` is our local extension, which adds the no-proof
// `unwrap(address,address,euint64)` overload `_unwrapTo` calls (OZ omits it from their published interface).
// `IERC7984ERC20WrapperUpstream` is OZ's canonical interface, re-exported through that file: its interfaceId
// — NOT the local extended one (the extra overload changes the id) — is what a genuine wrapper advertises via
// ERC-165, so the deploy-time probe checks against it.
import {IERC7984ERC20Wrapper, IERC7984ERC20WrapperUpstream} from "../interfaces/IERC7984ERC20Wrapper.sol";
import {IArbSys} from "../interfaces/IArbSys.sol";

/**
 * @title ConfidentialAirdropBase
 * @author TokenOps
 * @notice Abstract base shared by the ECDSA- and Merkle-based confidential airdrop implementations. It holds
 *         everything common to both: the claim-window lifecycle and admin controls; the fee accessor
 *         (`gasFee()`, resolved by the factory and frozen into config storage at init — the fee collectors are
 *         plain `FEE_COLLECTOR_ROLE` membership, enumerable via OZ `AccessControlEnumerable.getRoleMembers`);
 *         the instance-side disclosure surface and admin encrypted-balance getters; the compliance grant that
 *         authorizes this instance's own compliance-manager clone to read a handle (kept current after every
 *         balance-changing flow, not just at disclosure time); and the unwrap helper, guarded by a mandatory
 *         deploy-time check that the token really is an ERC-7984 wrapper (reverts `TokenNotAWrapper`).
 * @dev    Deployable either as a minimal-proxy clone or as a UUPS proxy. It has no claim entrypoint, no
 *         EIP-712 domain, no replay/dedup storage and no claimed-amount accounting, and it stores no `euint64`
 *         of its own — the live confidential balance is read directly from the token. The FHE coprocessor is
 *         wired in the initializer rather than the constructor, because clones and proxies never run the
 *         implementation's constructor.
 */
abstract contract ConfidentialAirdropBase is
    IConfidentialAirdropBase,
    ConfidentialAirdropConfigStorage,
    AccessControlEnumerableUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardTransient
{
    using SafeERC20 for IERC20;

    // ───────────────────────────── roles (one per admin scope) ─────────────────────────────
    /// @inheritdoc IConfidentialAirdropBase
    bytes32 public constant override PAUSER_ROLE = keccak256("PAUSER_ROLE");
    /// @inheritdoc IConfidentialAirdropBase
    bytes32 public constant override WINDOW_ADMIN_ROLE = keccak256("WINDOW_ADMIN_ROLE");
    /// @inheritdoc IConfidentialAirdropBase
    bytes32 public constant override TREASURY_ROLE = keccak256("TREASURY_ROLE");
    /// @inheritdoc IConfidentialAirdropBase
    bytes32 public constant override RESCUER_ROLE = keccak256("RESCUER_ROLE");
    /// @inheritdoc IConfidentialAirdropBase
    bytes32 public constant override FEE_COLLECTOR_ROLE = keccak256("FEE_COLLECTOR_ROLE");
    /// @inheritdoc IConfidentialAirdropBase
    bytes32 public constant override UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    /// @inheritdoc IConfidentialAirdropBase
    bytes32 public constant override DISCLOSURE_ADMIN_ROLE = keccak256("DISCLOSURE_ADMIN_ROLE");

    /// @dev Arbitrum's ArbSys precompile address (0x64); used only for the informational deploy block.
    address private constant ARB_SYS_ADDRESS = 0x0000000000000000000000000000000000000064;

    // ───────────────────────────────────── construction / init ────────────────────────────────────
    /// @notice Locks the bare implementation; clones/proxies have fresh storage and initialize instead.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Shared initializer; each concrete implementation's external `initialize` calls this.
     * @dev `onlyInitializing` — runs inside the implementation initializer. `admin` is the factory-injected
     *      airdrop creator (never zero, so no `ZeroAdmin` check); `complianceManager` is the instance's OWN
     *      manager clone; `feeCollector` seeds the self-administered `FEE_COLLECTOR_ROLE` with exactly one
     *      member; `gasFee` is the factory-resolved per-claim gas fee, written into config storage here and
     *      frozen for the lifetime of this instance.
     * @param p Shared base init params (factory-built).
     */
    function __ConfidentialAirdropBase_init(BaseInitParams calldata p) internal onlyInitializing {
        // (0) per-parameter validation — one dedicated error per condition
        if (p.token == address(0)) revert ZeroToken();
        if (p.feeCollector == address(0)) revert ZeroFeeCollector();
        if (p.complianceManager == address(0)) revert ZeroComplianceManager();
        if (p.endTime <= block.timestamp) revert EndTimeInPast(p.endTime, block.timestamp);
        if (p.startTime > p.endTime) revert InvalidStartTime();
        // startTime > endTime already reverted above, so equality (not underflow) is the only remaining
        // zero-duration case.
        if (p.startTime == p.endTime) revert InvalidDuration(p.startTime, p.endTime);
        // Mandatory: a campaign declared unwrappable MUST be backed by a real wrapper, so a
        // misconfiguration fails at DEPLOY, never at a user's first claimAndUnwrap.
        if (p.unwrappable && !_isWrapperToken(p.token)) revert TokenNotAWrapper();

        // (1) FHE coprocessor wiring — REQUIRED here (the impl constructor did not run for a clone/proxy).
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());

        // (2) OZ mixin inits (no __EIP712_init — ECDSA impl only; __AccessControlEnumerable has no init).
        //     OZ v5 UUPSUpgradeable has NO __UUPSUpgradeable_init (no storage) — nothing to wire here.
        __AccessControl_init();
        __Pausable_init();

        // (3) write config storage as ONE whole-struct, named-parameter assignment — a single SSTORE per
        //     packed slot instead of a read-mask-write per field (the fee collector is role state, not
        //     config storage). This MUST precede (4): the `_grantRole`/`_revokeRole` overrides below read
        //     `gasFee()` from this same config storage, and they must see the real frozen fee, not the
        //     zero default, while granting the initial roles.
        uint256 deploymentBlockNumber = _getBlockNumberish(); // post-init informational; never in salt/address
        _setConfigStorage(
            ConfigStorage({
                token: p.token,
                startTime: p.startTime,
                endTime: p.endTime,
                canExtendClaimWindow: p.canExtendClaimWindow,
                unwrappable: p.unwrappable,
                // the instance's own compliance-manager clone, the sole target of `_grantCompliance`
                complianceManager: p.complianceManager,
                gasFee: p.gasFee,
                deploymentBlockNumber: deploymentBlockNumber
            })
        );

        // (4) shared role grants to the createAirdrop caller (least privilege). `p.admin` is factory-injected
        //     and never zero, and `p.feeCollector` was validated non-zero in (0), so neither grant can hit the
        //     `_grantRole` override's zero checks.
        _grantRole(DEFAULT_ADMIN_ROLE, p.admin);
        _grantRole(PAUSER_ROLE, p.admin);
        _grantRole(WINDOW_ADMIN_ROLE, p.admin);
        _grantRole(TREASURY_ROLE, p.admin);
        _grantRole(RESCUER_ROLE, p.admin);
        _grantRole(DISCLOSURE_ADMIN_ROLE, p.admin);
        _grantRole(UPGRADER_ROLE, p.admin); // inert in clone mode (upgrades revert at the proxy layer)
        _setRoleAdmin(FEE_COLLECTOR_ROLE, FEE_COLLECTOR_ROLE); // self-administered
        _grantRole(FEE_COLLECTOR_ROLE, p.feeCollector); // ONE seed member; may grow to many

        // `airdropType()` is `pure` (a compile-time constant per concrete implementation), so calling it
        // during init is safe and needs no extra storage read.
        emit AirdropInitialized(p.token, airdropType(), p.admin, p.feeCollector, deploymentBlockNumber, p.gasFee);
    }

    // ───────────────────────────── admin / lifecycle ───────────────────────────────────────
    /// @inheritdoc IConfidentialAirdropBase
    function pause() external override onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @inheritdoc IConfidentialAirdropBase
    function unpause() external override onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @inheritdoc IConfidentialAirdropBase
    function extendClaimWindow(uint32 newEndTime) external override onlyRole(WINDOW_ADMIN_ROLE) {
        ConfigStorage storage $ = _getConfigStorage();
        if (!$.canExtendClaimWindow) revert ExtensionNotAllowed();
        uint32 oldEndTime = $.endTime; // cache: read storage endTime once
        // Forward-only: never moves the end backward. The error's (from, to) pair is
        // (current end, proposed end) so the caller sees how far short the proposal fell.
        if (newEndTime <= oldEndTime) revert InvalidDuration(oldEndTime, newEndTime);
        $.endTime = newEndTime;
        emit ClaimWindowExtended(oldEndTime, newEndTime);
    }

    /// @inheritdoc IConfidentialAirdropBase
    function withdrawConfidential(address recipient) external override onlyRole(TREASURY_ROLE) nonReentrant {
        if (recipient == address(0)) revert ZeroRecipient();
        IERC7984 airdropToken = IERC7984(_getConfigStorage().token); // not `token` — would shadow the token() getter
        euint64 balance = airdropToken.confidentialBalanceOf(address(this));
        emit WithdrawnConfidential(msg.sender, recipient);
        // The (trusted, own) token already controls its balance handle (ACL'd to the holder on _update),
        // so no FHE.allowTransient is needed; consuming the returned moved handle is unnecessary here
        // (full-balance clawback — nothing else is accounted against it).
        airdropToken.confidentialTransfer(recipient, balance);
        // The clawback changes this instance's balance to a freshly initialized encrypted-0 handle; keep
        // compliance current on it (one extra staticcall + one ACL write, mirroring the other
        // balance-changing flows).
        euint64 newBalance = airdropToken.confidentialBalanceOf(address(this));
        _grantCompliance(newBalance);
    }

    /// @inheritdoc IConfidentialAirdropBase
    function withdrawGasFee(
        address recipient,
        uint256 amount
    ) external override onlyRole(FEE_COLLECTOR_ROLE) nonReentrant {
        if (recipient == address(0)) revert ZeroRecipient();
        uint256 balance = address(this).balance;
        if (balance == 0) revert ZeroBalance();
        uint256 withdrawAmount = amount == 0 ? balance : amount; // amount == 0 ⇒ withdraw all
        if (withdrawAmount > balance) revert InsufficientFeeBalance(withdrawAmount, balance);
        emit GasFeeWithdrawn(recipient, withdrawAmount);
        (bool ok, ) = recipient.call{value: withdrawAmount}("");
        if (!ok) revert EthTransferFailed();
    }

    /// @inheritdoc IConfidentialAirdropBase
    function rescueERC20(address token_, address recipient) external override onlyRole(RESCUER_ROLE) nonReentrant {
        if (token_ == _getConfigStorage().token) revert CannotRescueAirdropToken();
        if (recipient == address(0)) revert ZeroRecipient();
        IERC20 erc20 = IERC20(token_);
        erc20.safeTransfer(recipient, erc20.balanceOf(address(this)));
    }

    /// @inheritdoc IConfidentialAirdropBase
    function rescueOtherConfidentialToken(
        address token_,
        address recipient
    ) external override onlyRole(RESCUER_ROLE) nonReentrant {
        if (token_ == _getConfigStorage().token) revert CannotRescueAirdropToken();
        if (recipient == address(0)) revert ZeroRecipient();
        IERC7984 other = IERC7984(token_);
        euint64 bal = other.confidentialBalanceOf(address(this));
        // No FHE.allowTransient to a (foreign, untrusted) token — minimal-permissions; it already controls
        // its own balance handle.
        other.confidentialTransfer(recipient, bal);
    }

    /**
     * @notice Authorizes a UUPS implementation upgrade (UUPS deployments only).
     * @dev Gated by `UPGRADER_ROLE`; reverts at the proxy layer in clone mode (no ERC-1967 impl slot).
     * @param newImplementation The proposed new implementation (unused — authorization is purely role-based).
     */
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @notice Role-revocation hook enforcing two "never empty" floors, one conditional and one unconditional.
     * @dev `FEE_COLLECTOR_ROLE` is self-administered: `DEFAULT_ADMIN_ROLE` cannot grant it, so if the last
     *      member is revoked or renounces, the role reaches zero members permanently and `withdrawGasFee` has
     *      no authorized caller. That only matters when the campaign actually charges a fee — a zero-`gasFee`
     *      campaign can never accrue ETH, so the floor is CONDITIONAL on `gasFee() > 0`. `DEFAULT_ADMIN_ROLE`
     *      is the opposite: it is administered by itself (OZ default), so emptying it is always reachable and
     *      would leave the instance permanently ungovernable (no role admin can re-grant it) — that floor is
     *      UNCONDITIONAL, deliberately forbidding the renounce-admin-for-immutability pattern on instances.
     *      Both `revokeRole` and `renounceRole` funnel through `_revokeRole`; a hand-off still works by
     *      granting the successor first (count 2) then revoking the predecessor. All other roles are
     *      unaffected.
     * @param role The role being revoked.
     * @param account The account losing the role.
     * @return revoked True iff `account` actually held `role` and it was removed.
     */
    function _revokeRole(bytes32 role, address account) internal override returns (bool revoked) {
        if (
            role == FEE_COLLECTOR_ROLE &&
            gasFee() > 0 &&
            getRoleMemberCount(FEE_COLLECTOR_ROLE) == 1 &&
            hasRole(role, account)
        ) {
            revert LastFeeCollector();
        }
        if (role == DEFAULT_ADMIN_ROLE && getRoleMemberCount(DEFAULT_ADMIN_ROLE) == 1 && hasRole(role, account)) {
            revert LastAdmin();
        }
        return super._revokeRole(role, account);
    }

    /**
     * @notice Role-grant hook rejecting `address(0)` grants that would otherwise silently no-op the two
     *         "never empty" floors above.
     * @dev OZ's default `_grantRole` treats granting to `address(0)` as a normal (harmless-looking) grant,
     *      which would let `DEFAULT_ADMIN_ROLE` or a fee-charging campaign's `FEE_COLLECTOR_ROLE` "gain" a
     *      member that can never act and can never be meaningfully revoked — defeating the `_revokeRole`
     *      floors' intent. `DEFAULT_ADMIN_ROLE` is rejected UNCONDITIONALLY (mirroring `LastAdmin`'s
     *      unconditional floor); `FEE_COLLECTOR_ROLE` is rejected only when `gasFee() > 0` (mirroring
     *      `LastFeeCollector`'s conditional floor). All other roles keep OZ's default zero-grant behavior.
     * @param role The role being granted.
     * @param account The account receiving the role.
     * @return granted True iff `account` did not already hold `role` and it was added.
     */
    function _grantRole(bytes32 role, address account) internal override returns (bool granted) {
        if (role == DEFAULT_ADMIN_ROLE && account == address(0)) revert ZeroAdminGrant();
        if (role == FEE_COLLECTOR_ROLE && account == address(0) && gasFee() > 0) revert ZeroFeeCollectorGrant();
        return super._grantRole(role, account);
    }

    // ───────────────────────────── fee accessors ────────────────────────────────────
    /// @inheritdoc IConfidentialAirdropBase
    function gasFee() public view override returns (uint256 fee) {
        // gasFee is resolved by the factory at create time and written into config storage by
        // __ConfidentialAirdropBase_init; it never changes afterward. The external ABI stays `uint256`
        // even though it is stored packed as `uint96`.
        fee = uint256(_getConfigStorage().gasFee);
    }
    // NOTE: no `feeCollectors()` view here — use OZ `AccessControlEnumerable(Upgradeable).getRoleMembers`
    // (already inherited) with `FEE_COLLECTOR_ROLE` to enumerate the live membership.

    // ───────────────────────────── instance getters ────────────────────────────────────────
    /// @inheritdoc IConfidentialAirdropBase
    function token() external view override returns (address) {
        return _getConfigStorage().token;
    }

    /// @inheritdoc IConfidentialAirdropBase
    /// @dev Left abstract here — the `AirdropType` is fixed at compile time per concrete implementation, so
    ///      each one implements this as a `pure` constant instead of a storage read (`pure` is a valid,
    ///      stricter override of the interface's `view`).
    function airdropType() public view virtual override returns (uint8);

    /// @inheritdoc IConfidentialAirdropBase
    function startTime() external view override returns (uint32) {
        return _getConfigStorage().startTime;
    }

    /// @inheritdoc IConfidentialAirdropBase
    function endTime() external view override returns (uint32) {
        return _getConfigStorage().endTime;
    }

    /// @inheritdoc IConfidentialAirdropBase
    function unwrappable() external view override returns (bool) {
        return _getConfigStorage().unwrappable;
    }

    /// @inheritdoc IConfidentialAirdropBase
    function complianceManager() external view override returns (address) {
        return _getConfigStorage().complianceManager;
    }

    /// @inheritdoc IConfidentialAirdropBase
    function isClaimWindowActive() external view override returns (bool) {
        ConfigStorage storage $ = _getConfigStorage();
        return block.timestamp >= $.startTime && block.timestamp <= $.endTime && !paused();
    }

    /// @inheritdoc IConfidentialAirdropBase
    function hasClaimStarted() external view override returns (bool) {
        return block.timestamp >= _getConfigStorage().startTime;
    }

    /// @inheritdoc IConfidentialAirdropBase
    function hasClaimEnded() external view override returns (bool) {
        return block.timestamp > _getConfigStorage().endTime;
    }

    // ───────────────────────────── disclosure — instance-side ───────────────────────────────
    // Two layers: (1) the BALANCE layer below — direct, untyped reads of the instance's OWN ERC-7984 balance,
    // the single airdrop-side encrypted quantity, read directly. (2) the GENERIC two-gate raw-handle layer
    // (`discloseHandleToParty` / `batchDiscloseHandlesToParty` → `_batchDiscloseHandles`) — a reusable
    // user-disclosure mechanism for arbitrary handles. On a FUNDED instance no `FHE.allowThis` is needed on
    // the resolved balance handle: ERC-7984 `_update` already grants the holder (this instance) persistent
    // ACL on its own balance handle, so `FHE.allow(balance, …)` succeeds without it. On a never-funded
    // instance the refresh below substitutes a fresh, already-`allowThis`-ed zero handle instead. The three
    // balance functions resolve the balance through `_refreshComplianceBalance`, so every admin read also
    // re-grants the manager clone on the handle it hands out: the token rotates the balance handle on
    // transfers no airdrop code runs for, and the clone's grant does not follow the rotation by itself.
    /// @inheritdoc IConfidentialAirdropBase
    function refreshComplianceBalance() external override returns (euint64 balance) {
        balance = _refreshComplianceBalance();
    }

    /// @inheritdoc IConfidentialAirdropBase
    function adminGetCurrentBalance() external override onlyRole(DISCLOSURE_ADMIN_ROLE) returns (euint64 balance) {
        balance = _refreshComplianceBalance();
        FHE.allow(balance, msg.sender);
    }

    /// @inheritdoc IConfidentialAirdropBase
    function adminDiscloseBalanceToParty(
        address party
    ) external override onlyRole(DISCLOSURE_ADMIN_ROLE) returns (euint64 balance) {
        if (party == address(0)) revert InvalidParty();
        balance = _refreshComplianceBalance();
        FHE.allow(balance, party); // gate #2 holds: the instance owns its own balance handle
        emit ComplianceBalanceDisclosed(msg.sender, party, balance);
    }

    /// @inheritdoc IConfidentialAirdropBase
    function adminBatchDiscloseBalanceToParties(
        address[] calldata parties
    ) external override onlyRole(DISCLOSURE_ADMIN_ROLE) returns (euint64 balance) {
        if (parties.length == 0) revert EmptyBatch();
        balance = _refreshComplianceBalance(); // read ONCE, fan out
        for (uint256 i; i < parties.length; ++i) {
            if (parties[i] == address(0)) revert InvalidParty();
            FHE.allow(balance, parties[i]);
            emit ComplianceBalanceDisclosed(msg.sender, parties[i], balance);
        }
    }

    /// @inheritdoc IConfidentialAirdropBase
    function discloseHandleToParty(euint64 handle, address party) external override {
        // Inlined two-gate check for the single handle — same gates, same event, same errors as the batch
        // path (`EmptyBatch` is obviously N/A here); avoids building a throwaway 1-element array just to
        // reuse the batch helper.
        if (party == address(0)) revert InvalidParty();
        bool isAdmin = hasRole(DISCLOSURE_ADMIN_ROLE, msg.sender);
        // gate #1 - persistent-only, so a caller holding nothing but a transient allowance lent to it
        // earlier in this same transaction cannot turn that into a permanent grant for a third party
        if (!isAdmin && !FHE.isUserDecryptable(euint64.unwrap(handle), msg.sender, address(this))) {
            revert HandleNotAllowed(handle);
        }
        FHE.allow(handle, party); // gate #2 (reverts if THIS instance isn't allowed)
        emit HandleDisclosedToParty(msg.sender, party, handle);
    }

    /// @inheritdoc IConfidentialAirdropBase
    function batchDiscloseHandlesToParty(euint64[] calldata handles, address party) external override {
        _batchDiscloseHandles(handles, party);
    }

    // ───────────────────────────── internal helpers (shared with the impls) ────────────────────────
    /**
     * @notice Two-gate raw-handle disclosure, instance-side only.
     * @dev Gate #1 (anti-theft): non-admins must already hold PERSISTENT user-decryption ACL on each handle,
     *      for themselves AND for this instance; `DISCLOSURE_ADMIN_ROLE` bypasses gate #1 ONLY. A transient
     *      allowance does not qualify: a disclosure writes a persistent, unrevokable grant, so a caller lent
     *      a handle for the duration of one call must not be able to make that grant. Gate #2 (anti-oracle):
     *      `FHE.allow` reverts unless THIS instance is allowed on the handle - this binds admins too.
     * @param handles The handles to disclose.
     * @param party The address granted decrypt ACL on each handle.
     */
    function _batchDiscloseHandles(euint64[] calldata handles, address party) internal {
        if (party == address(0)) revert InvalidParty();
        if (handles.length == 0) revert EmptyBatch();
        bool isAdmin = hasRole(DISCLOSURE_ADMIN_ROLE, msg.sender);
        for (uint256 i; i < handles.length; ++i) {
            // gate #1 — the error carries the offending handle so the batch caller knows WHICH element failed
            if (!isAdmin && !FHE.isUserDecryptable(euint64.unwrap(handles[i]), msg.sender, address(this))) {
                revert HandleNotAllowed(handles[i]);
            }
            FHE.allow(handles[i], party); // gate #2 (reverts if THIS instance isn't allowed)
            emit HandleDisclosedToParty(msg.sender, party, handles[i]);
        }
    }

    /**
     * @notice Compliance grant: grant the handle to the instance's OWN manager clone ONLY.
     * @dev ONE `FHE.allow` — never a shared manager, never a raw delegate. The instance is already
     *      persistently allowed on every handle passed here — claim/funding handles are `allowThis`-ed at
     *      their source, and the instance's own ERC-7984 balance is ACL'd to the holder by `_update` — so
     *      the double-ACL pair (instance + clone) that delegated reads require holds.
     * @param handle The handle to grant to the compliance manager clone.
     * @return granted The handle the grant was actually written against: `handle` itself, or the trivially
     *         encrypted zero `FHE.allow` substitutes for an uninitialized one. Callers holding an
     *         initialized handle may ignore it.
     */
    function _grantCompliance(euint64 handle) internal returns (euint64 granted) {
        granted = FHE.allow(handle, _getConfigStorage().complianceManager);
    }

    /**
     * @notice Re-read the instance's own ERC-7984 balance and grant the compliance manager clone on it.
     * @dev One staticcall plus one ACL write on a funded instance; the token's `_update` already grants the
     *      holder persistent ACL on its own balance handle, so no `FHE.allowThis` is needed for it. Before
     *      the first transfer in, the token holds no balance handle at all and the read returns the
     *      uninitialized sentinel: a trivially encrypted zero stands in for it, and that substitute needs the
     *      instance's own persistent leg written here because it did not come from the token.
     * @return balance The handle the compliance grant was written against, always safe to hand out.
     */
    function _refreshComplianceBalance() internal returns (euint64 balance) {
        balance = IERC7984(_getConfigStorage().token).confidentialBalanceOf(address(this));
        if (!FHE.isInitialized(balance)) balance = FHE.allowThis(FHE.asEuint64(0));
        balance = _grantCompliance(balance);
    }

    /**
     * @notice Transfer an already-verified `euint64` amount to `beneficiary` via the airdrop token, then
     *         grant the compliance manager clone on the DELIVERED handle.
     * @dev Shared by the concrete implementations' plain-claim paths (both named `claim`) — the payout
     *      counterpart of `_unwrapTo`. The requested `amount` gets a transient-only token grant (the token
     *      reads it within this tx; never a persistent grant). Under the ERC-7984 all-or-nothing clamp the
     *      token may deliver encrypted-0 instead of `amount`, so the compliance grant is issued on
     *      the transfer's RETURNED handle — compliance reads what actually MOVED, not merely what was
     *      requested. No `allowThis` is needed: ERC-7984 `_update`
     *      persistently ACLs the delivered handle to `from` (this instance) — and to `to`, so the beneficiary
     *      can already read their true delivery without a further grant. The callers' pre-transfer grants on
     *      the requested handle (the recipient grant and the compliance grant on the requested amount) are
     *      KEPT — ACL is append-only and the requested handle remains the compliance-readable record of
     *      intent. NOT used by the unwrap paths: `_unwrapTo`
     *      returns a request id, not a moved-amount handle, so their pre-transfer requested-handle grant
     *      remains their compliance record.
     * @param beneficiary The payout destination (resolved by the caller: `to`, or `msg.sender` when zero).
     * @param amount The already-verified encrypted amount to transfer.
     * @return moved The token-returned delivered-amount handle (`amount` in value, or encrypted-0 on a
     *         clamp), ACL'd to the instance + beneficiary by the token and to the manager clone here.
     */
    function _transferTo(address beneficiary, euint64 amount) internal returns (euint64 moved) {
        address tkn = _getConfigStorage().token;
        FHE.allowTransient(amount, tkn); // token reads the requested amount within this tx only
        moved = IERC7984(tkn).confidentialTransfer(beneficiary, amount);
        _grantCompliance(moved); // compliance reads the DELIVERED amount, not merely the requested one
        // The transfer just changed this instance's own balance; keep compliance current on the LIVE
        // balance too (one extra staticcall + one ACL write — the entire extra cost on the claim hot path).
        // No `allowThis` needed: ERC-7984 `_update` already ACLs the resolved handle to the holder (`this`).
        euint64 balance = IERC7984(tkn).confidentialBalanceOf(address(this));
        _grantCompliance(balance);
    }

    /**
     * @notice Unwrap an already-held `euint64` amount to `to` via the airdrop's wrapper token.
     * @dev Transient-only ACL (`FHE.allowTransient`) — the token reads `amount` within this tx; NEVER a
     *      persistent grant for the unwrap read, which would leave the handle decryptable beyond the tx. The
     *      underlying ERC-20 is released in a later permissionless `finalizeUnwrap` tx. The wrapper burns this
     *      instance's confidential balance in THIS tx (verified against OZ 0.5.1 `_unwrap` → `_burn(from,
     *      amount)`), so — mirroring `_transferTo` — the fresh post-burn balance is granted to compliance here
     *      too (one extra staticcall + one ACL write); no `allowThis` needed for the same `_update` reason.
     *
     *      A zero request id names no handle: every FHE op would silently substitute a trivial encrypted-0
     *      for it and record a zero delivery instead of failing. Rejecting it here fails closed for every caller.
     * @param to The beneficiary of the underlying ERC-20.
     * @param amount The already-held encrypted amount to unwrap.
     * @return reqId The unwrap request id returned by the wrapper (never zero).
     */
    function _unwrapTo(address to, euint64 amount) internal returns (bytes32 reqId) {
        address tkn = _getConfigStorage().token;
        FHE.allowTransient(amount, tkn);
        reqId = IERC7984ERC20Wrapper(tkn).unwrap(address(this), to, amount);
        if (reqId == bytes32(0)) revert ZeroUnwrapRequestId();
        euint64 balance = IERC7984(tkn).confidentialBalanceOf(address(this));
        _grantCompliance(balance);
    }

    /**
     * @notice Deploy-time check that `token_` is an ERC7984ERC20Wrapper.
     * @dev PRIMARY leg: ERC-165 `supportsInterface` against the CANONICAL upstream wrapper interfaceId —
     *      the OZ `ERC7984ERC20Wrapper` advertises exactly this (verified against the
     *      OZ confidential-contracts 0.5.1 implementation).
     *      We deliberately probe the upstream id, NOT our local extended `IERC7984ERC20Wrapper` (which adds
     *      the no-proof `unwrap` overload and therefore has a different interfaceId no real wrapper claims).
     *      FALLBACK leg: a `underlying()` staticcall returning a non-zero address — catches non-165 wrappers.
     *      Both `_isWrapperToken` AND the runtime `unwrap` fail closed, so this is defense in depth.
     *      REENTRANCY-SAFE: both external legs are `view` → STATICCALL, which cannot mutate
     *      state; the probe runs under `initialize`'s `initializer` guard and BEFORE any storage write (CEI),
     *      and this function is itself `view` — a hostile `token_` cannot reenter to any effect, so no
     *      `nonReentrant` is needed here.
     * @param token_ The candidate token.
     * @return True iff `token_` looks like a genuine wrapper.
     */
    function _isWrapperToken(address token_) internal view returns (bool) {
        // An EOA / codeless address is never a wrapper. This guard also avoids the case where a CALL to a
        // codeless address "succeeds" with empty returndata and the subsequent ABI decode (which try/catch
        // does NOT catch) reverts the probe.
        if (token_.code.length == 0) return false;
        try IERC165(token_).supportsInterface(type(IERC7984ERC20WrapperUpstream).interfaceId) returns (bool ok) {
            if (ok) return true;
            // not 165-advertised (or it reverted) — fall through to the underlying() fallback
            // solhint-disable-next-line no-empty-blocks
        } catch {}
        try IERC7984ERC20Wrapper(token_).underlying() returns (address underlyingAddr) {
            return underlyingAddr != address(0);
        } catch {
            return false;
        }
    }

    /**
     * @notice Shared claim-window gate for the concrete implementations' claim paths.
     * @dev Reverts `ClaimsPaused` / `ClaimNotStarted` / `ClaimWindowFinished`. End is INCLUSIVE
     *      (a claim AT `endTime` is valid).
     */
    function _requireClaimWindowActive() internal view {
        ConfigStorage storage $ = _getConfigStorage();
        if (paused()) revert ClaimsPaused();
        if (block.timestamp < $.startTime) revert ClaimNotStarted($.startTime, block.timestamp);
        if (block.timestamp > $.endTime) revert ClaimWindowFinished($.endTime, block.timestamp);
    }

    /**
     * @notice Current block number, ArbSys-aware (Arbitrum's `block.number` is the L1 approximation).
     * @dev Code-presence-gated staticcall to ArbSys `0x64` (selector 0xa3b1b31d) with `block.number`
     *      fallback. Result is used ONLY for the informational `deploymentBlockNumber` — never in any
     *      salt or address.
     * @return The current chain block number.
     */
    function _getBlockNumberish() internal view returns (uint256) {
        if (ARB_SYS_ADDRESS.code.length > 0) {
            // solhint-disable-next-line avoid-low-level-calls
            (bool success, bytes memory data) = ARB_SYS_ADDRESS.staticcall(
                abi.encodeWithSelector(IArbSys.arbBlockNumber.selector)
            );
            if (success && data.length >= 32) {
                return abi.decode(data, (uint256));
            }
        }
        return block.number;
    }
}
