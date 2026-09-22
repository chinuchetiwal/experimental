// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {IArbSys} from "../interfaces/IArbSys.sol";

/// @title MockArbSys
/// @notice Mock implementation of Arbitrum's ArbSys precompile for testing
/// @dev Deploy normally, then inject bytecode at 0x64 via hardhat_setCode
contract MockArbSys is IArbSys {
    uint256 private _arbBlockNumber;

    constructor(uint256 initialBlockNumber) {
        _arbBlockNumber = initialBlockNumber;
    }

    /// @inheritdoc IArbSys
    function arbBlockNumber() external view override returns (uint256) {
        return _arbBlockNumber;
    }

    /// @notice Set the mock block number (for testing)
    function setArbBlockNumber(uint256 newBlockNumber) external {
        _arbBlockNumber = newBlockNumber;
    }
}
