// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/// @title EthRejecter
/// @author TokenOps
/// @notice Test-only contract that rejects every incoming ETH transfer, used to drive
///         `ConfidentialAirdropBase.withdrawGasFee`'s `EthTransferFailed()` branch.
contract EthRejecter {
    /// @notice Reverts any plain ETH transfer so `recipient.call{value:..}("")` fails.
    receive() external payable {
        revert("EthRejecter: ETH rejected");
    }
}
