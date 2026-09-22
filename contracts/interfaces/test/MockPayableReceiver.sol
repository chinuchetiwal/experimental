// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/// @title MockPayableReceiver
/// @author TokenOps
/// @notice Trivial test-only contract with a `payable` constructor, used to exercise the ONLY
///         ETH-bearing deployer path (`CREATE3Deployer.deployWithValue`). The forwarded value is
///         retained in the child's balance so the test can assert it landed at the predicted address.
/// @dev Kept minimal on purpose — the deployer itself is immutable and must not change; this helper
///      only provides a payable-constructor target for it.
contract MockPayableReceiver {
    /// @notice Accepts any ETH forwarded at construction (CREATE3 value path).
    // solhint-disable-next-line no-empty-blocks
    constructor() payable {}
}
