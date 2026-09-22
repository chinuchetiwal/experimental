// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {FHE, euint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title MockERC7984Token
/// @notice Test-only ERC7984 token with public mint
/// @dev Used across the airdrop claim and compliance test suites. Inherits full ERC7984 behavior:
///      - setOperator() for transfer authorization (time-based, not amount-based)
///      - confidentialTransferFrom() with operator checks
///      - _update() returns encrypted 0 on failure (does not revert)
///      - 6 decimals (ERC7984 default)
contract MockERC7984Token is ERC7984 {
    constructor(string memory name_, string memory symbol_) ERC7984(name_, symbol_, "") {
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
    }

    /// @notice Mint plaintext amount as encrypted balance
    /// @param to Recipient address
    /// @param amount Plaintext amount (max type(uint64).max)
    function mint(address to, uint64 amount) external {
        _mint(to, FHE.asEuint64(amount));
    }

    /// @notice Mint encrypted amount directly
    /// @param to Recipient address
    /// @param amount Encrypted amount
    function mintEncrypted(address to, euint64 amount) external {
        _mint(to, amount);
    }

    /// @notice Test-only: burn plaintext amount from any holder.
    /// @dev Used to simulate insufficient-balance scenarios, such as an airdrop pool whose
    /// funded balance has fallen out of sync with its outstanding fee reserve. Bypasses
    /// authorization — do not deploy to production.
    /// @param holder Address whose balance to reduce.
    /// @param amount Plaintext amount to burn.
    function testBurn(address holder, uint64 amount) external {
        _burn(holder, FHE.asEuint64(amount));
    }
}
