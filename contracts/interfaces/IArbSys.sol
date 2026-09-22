// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/**
 * @title IArbSys
 * @author Arbitrum
 * @notice Provides access to Arbitrum L2 block numbers via the ArbSys precompile.
 * @dev Interface for Arbitrum's ArbSys precompile, available at address `0x64` on Arbitrum chains.
 *
 * On Arbitrum, `block.number` returns the L1 (Ethereum mainnet) block number approximation.
 * This precompile provides access to the actual Arbitrum L2 block number.
 *
 * See https://docs.arbitrum.io/build-decentralized-apps/arbitrum-vs-ethereum/block-numbers-and-time
 */
interface IArbSys {
    /**
     * @notice Returns the current Arbitrum L2 block number.
     * @dev Returns the current Arbitrum L2 block number.
     * @return The current L2 block number on Arbitrum.
     */
    function arbBlockNumber() external view returns (uint256);
}
