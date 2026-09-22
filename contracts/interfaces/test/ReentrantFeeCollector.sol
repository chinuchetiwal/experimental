// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/// @title IWithdrawGasFee
/// @author TokenOps
/// @notice Minimal view of the base's value-bearing fee path (`ConfidentialAirdropBase.withdrawGasFee`).
interface IWithdrawGasFee {
    /// @notice Withdraw accrued gas-fee ETH to `recipient`.
    /// @param recipient Destination for the withdrawn ETH.
    /// @param amount Amount to withdraw (0 ⇒ full balance).
    function withdrawGasFee(address recipient, uint256 amount) external;
}

/// @title ReentrantFeeCollector
/// @author TokenOps
/// @notice Test-only FEE_COLLECTOR that attempts to re-enter `withdrawGasFee` from its `receive()`
///         hook while the outer withdrawal is still in flight. Used to confirm that `withdrawGasFee`
///         is guarded by `nonReentrant` (ReentrancyGuardTransient) and blocks the nested re-entrant call.
/// @dev The airdrop must first grant this contract `FEE_COLLECTOR_ROLE` (self-administered). The outer
///      withdrawal should SUCCEED while the single re-entrant attempt is blocked; the test asserts
///      `innerSucceeded() == false` and that instance ETH is not double-spent.
contract ReentrantFeeCollector {
    /// @notice The airdrop instance under attack (set for the duration of an `attack` call).
    /// @dev Named `victim`, NOT `target` — a public `target()` getter collides with ethers v6
    ///      `BaseContract.target` in the typechain output and breaks `pnpm build:ts`.
    IWithdrawGasFee public victim;

    /// @notice True iff the re-entrant `withdrawGasFee` call inside `receive()` did NOT revert.
    /// @dev Expected to stay `false` — the guard must block the nested call.
    bool public innerSucceeded;

    /// @notice True once `receive()` has fired for the current attack (so we re-enter exactly once).
    bool private _reentered;

    /// @notice Drive the outer withdrawal that triggers the re-entrant `receive()` callback.
    /// @param airdrop The airdrop instance exposing `withdrawGasFee`.
    /// @param amount The outer withdrawal amount (forwarded to this contract, firing `receive()`).
    function attack(address airdrop, uint256 amount) external {
        victim = IWithdrawGasFee(airdrop);
        _reentered = false;
        innerSucceeded = false;
        victim.withdrawGasFee(address(this), amount);
    }

    /// @notice Receives the outer withdrawal and re-enters `withdrawGasFee` exactly once.
    /// @dev The nested call is expected to revert (`ReentrancyGuardReentrantCall`); we swallow the
    ///      revert so the outer withdrawal still completes and record whether the nested call succeeded.
    receive() external payable {
        if (!_reentered) {
            _reentered = true;
            // solhint-disable-next-line no-empty-blocks
            try victim.withdrawGasFee(address(this), 1) {
                innerSucceeded = true;
            } catch {
                innerSucceeded = false;
            }
        }
    }
}
