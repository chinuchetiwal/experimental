// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {euint64} from "@fhevm/solidity/lib/FHE.sol";
import {IConfidentialAirdropTypes} from "./IConfidentialAirdropTypes.sol";

/**
 * @title IConfidentialAirdropBase
 * @author TokenOps
 * @notice The external surface shared by BOTH airdrop impls — `ConfidentialAirdropBase`.
 * @dev Factors the shared admin/lifecycle, disclosure and getter surface so `IECDSAConfidentialAirdrop`
 *      and `IMerkleConfidentialAirdrop` extend it instead of duplicating it. Role-constant getters are
 *      included so the role matrix is externally verifiable.
 */
interface IConfidentialAirdropBase is IConfidentialAirdropTypes {
    // ───────────────────────────── shared roles — public-constant getters ─────────────────────────
    /// @notice The pause/unpause role identifier.
    function PAUSER_ROLE() external view returns (bytes32);

    /// @notice The claim-window admin role identifier.
    function WINDOW_ADMIN_ROLE() external view returns (bytes32);

    /// @notice The treasury (confidential clawback) role identifier.
    function TREASURY_ROLE() external view returns (bytes32);

    /// @notice The stray-token rescue role identifier.
    function RESCUER_ROLE() external view returns (bytes32);

    /// @notice The gas-fee collector role identifier.
    function FEE_COLLECTOR_ROLE() external view returns (bytes32);

    /// @notice The UUPS upgrade role identifier.
    function UPGRADER_ROLE() external view returns (bytes32);

    /// @notice The disclosure admin role identifier.
    function DISCLOSURE_ADMIN_ROLE() external view returns (bytes32);

    // ───────────────────────────── admin / lifecycle ───────────────────────────────────────────────
    /// @notice Pause the instance (halts claims).
    function pause() external;

    /// @notice Unpause the instance.
    function unpause() external;

    /// @notice Push the claim window end forward only; requires canExtendClaimWindow.
    /// @param newEndTime The new window end timestamp; must be later than the current end.
    function extendClaimWindow(uint32 newEndTime) external;

    /// @notice Move the ENTIRE encrypted token balance out (clawback). Allowed any time.
    /// @param recipient The address receiving the encrypted balance.
    function withdrawConfidential(address recipient) external;

    /// @notice Withdraw native ETH gas fees. amount==0 => all.
    /// @param recipient The address receiving the ETH.
    /// @param amount The wei to withdraw; 0 means the full balance.
    function withdrawGasFee(address recipient, uint256 amount) external;

    /// @notice Rescue a non-airdrop ERC-20 (SafeERC20). Reverts CannotRescueAirdropToken() for the
    ///         configured airdrop token itself.
    /// @param token_ The ERC-20 token to rescue.
    /// @param recipient The address receiving the rescued tokens.
    function rescueERC20(address token_, address recipient) external;

    /// @notice Rescue a confidential (ERC-7984) token OTHER than the airdrop token — the name makes the
    ///         scope explicit. Reverts CannotRescueAirdropToken() for the configured airdrop token itself.
    /// @param token_ The foreign ERC-7984 token to rescue.
    /// @param recipient The address receiving the rescued tokens.
    function rescueOtherConfidentialToken(address token_, address recipient) external;

    // ───────────────────────────── fee accessors ───────────────────────────────────────────────────
    /// @notice Exact wei required per claim (resolved by the factory and frozen at create time).
    function gasFee() external view returns (uint256);
    // NOTE: there is no dedicated `feeCollectors()` view here — callers enumerate FEE_COLLECTOR_ROLE
    // membership via OZ `AccessControlEnumerable(Upgradeable).getRoleMembers(FEE_COLLECTOR_ROLE)`,
    // which every instance already exposes.

    // ───────────────────────────── instance getters ────────────────────────────────────────────────
    /// @notice The ERC-7984 airdrop token address.
    function token() external view returns (address);

    /// @notice The airdrop type discriminator (ECDSA vs Merkle).
    function airdropType() external view returns (uint8);

    /// @notice The claim window start timestamp.
    function startTime() external view returns (uint32);

    /// @notice The claim window end timestamp.
    function endTime() external view returns (uint32);

    /// @notice Whether claimed tokens may be unwrapped.
    function unwrappable() external view returns (bool);

    /// @notice The instance's compliance manager clone address.
    function complianceManager() external view returns (address);

    /// @notice Whether the claim window is currently open.
    function isClaimWindowActive() external view returns (bool);

    /// @notice Whether the claim window has started.
    function hasClaimStarted() external view returns (bool);

    /// @notice Whether the claim window has ended.
    function hasClaimEnded() external view returns (bool);

    // ───────────────────────────── disclosure ──────────────────────────────────────────────────────
    // All perform FHE ACL writes (NOT view) — they resolve the instance's OWN ERC-7984 balance, the single
    // airdrop-side encrypted quantity. Balance disclosure is direct and untyped: there is no stored
    // running-total handle and no disclosure-type selector to choose between.

    /// @notice Re-read the instance's OWN current ERC-7984 balance and grant the compliance manager clone
    ///         on the resulting handle.
    /// @dev Permissionless: there is no argument to abuse, the only handle read is `address(this)`'s own
    ///      balance, and the only grantee is the manager clone wired at initialization. The token rotates
    ///      the instance's balance handle on every incoming transfer (including one no airdrop code sees,
    ///      such as a direct transfer from a third party) and grants the fresh handle to the token and the
    ///      holder only. This is therefore the normative way to obtain a readable live-balance handle:
    ///      call it, then decrypt the handle it returns. Grants are append-only, so a later rotation can
    ///      never take that read away. Before anything is ever transferred in, the token holds no balance
    ///      handle for the instance and a trivially encrypted zero stands in for it, so what comes back is
    ///      always a handle the grant was actually written against.
    /// @return balance The instance's current encrypted balance handle, granted to the manager clone.
    function refreshComplianceBalance() external returns (euint64 balance);

    /// @notice Admin reads the instance's OWN current ERC-7984 balance (reads address(this)).
    /// @dev Also re-grants the compliance manager clone on the handle it returns.
    /// @return balance The instance's current encrypted balance handle.
    function adminGetCurrentBalance() external returns (euint64 balance);

    /// @notice Admin discloses the instance's OWN current ERC-7984 balance to `party`.
    /// @dev DISCLOSURE_ADMIN_ROLE-gated; reverts `InvalidParty()` on a zero party. Emits
    ///      `ComplianceBalanceDisclosed`. Gate #2 holds intrinsically — the instance owns its balance handle.
    ///      Also re-grants the compliance manager clone on the handle it returns.
    /// @param party The address the balance handle is disclosed to.
    /// @return balance The disclosed encrypted balance handle.
    function adminDiscloseBalanceToParty(address party) external returns (euint64 balance);

    /// @notice Admin batch balance disclosure: read the instance's OWN balance ONCE and `FHE.allow` it to
    ///         EVERY address in `parties` (compliance fan-out to several regulators/delegates in one tx).
    /// @dev DISCLOSURE_ADMIN_ROLE-gated; reverts `EmptyBatch()` on an empty list, `InvalidParty()` on a zero
    ///      party. Emits one `ComplianceBalanceDisclosed` per party. The balance is the instance's own, so
    ///      gate #2 holds intrinsically; there is no caller handle and thus no gate #1. Also re-grants the
    ///      compliance manager clone on the handle it returns.
    /// @param parties The addresses the balance handle is disclosed to.
    /// @return balance The disclosed encrypted balance handle.
    function adminBatchDiscloseBalanceToParties(address[] calldata parties) external returns (euint64 balance);

    /// @notice Caller discloses a raw handle to `party` — explicit, per-handle, no expiry, no delegation.
    /// @dev Gate #1: a non-admin caller must hold PERSISTENT user-decryption ACL on the handle - both the
    ///      caller leg and this instance's leg - which a transient allowance never satisfies;
    ///      `DISCLOSURE_ADMIN_ROLE` bypasses gate #1. Gate #2: `FHE.allow` reverts unless THIS instance is
    ///      allowed on the handle, which binds admins too. Reverts `HandleNotAllowed(handle)` at gate #1 and
    ///      `InvalidParty()` on a zero party.
    /// @param handle The encrypted handle to disclose.
    /// @param party The address the handle is disclosed to.
    function discloseHandleToParty(euint64 handle, address party) external;

    /// @notice Caller discloses several raw handles to `party` in one tx — explicit, per-handle.
    /// @dev Same two gates as the single-handle form, applied per element, so one handle the caller lacks
    ///      persistent user-decryption ACL on reverts the whole batch. Also reverts `EmptyBatch()` on [].
    /// @param handles The encrypted handles to disclose.
    /// @param party The address the handles are disclosed to.
    function batchDiscloseHandlesToParty(euint64[] calldata handles, address party) external;
}
