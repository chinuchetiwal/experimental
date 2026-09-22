// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
// solhint-disable-next-line max-line-length
import {ERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ERC20Wrapper.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {FHE, euint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title TestERC7984ERC20Wrapper
/// @author TokenOps
/// @notice Concrete, deployable subclass of OpenZeppelin's abstract `ERC7984ERC20Wrapper`, used as the
///         genuine wrapper token in the airdrop test suite. It carries the real wrapper behavior:
///         `underlying()`, the canonical wrapper interfaceId advertised via ERC-165, the genuine no-proof
///         `unwrap(address,address,euint64)` overload, and the rest of the upstream wrapper surface
///         (`wrap`, the proof-based unwrap, `finalizeUnwrap`, `rate`, `unwrapAmount`).
/// @dev The abstract upstream contract has no constructor body beyond wiring the underlying ERC-20 and the
///      ERC7984 metadata, so this subclass only wires the Zama coprocessor config (required for the mock
///      coprocessor) and exposes a plaintext `mint` helper for funding test instances directly.
contract TestERC7984ERC20Wrapper is ERC7984ERC20Wrapper {
    /// @param name_ Token name.
    /// @param symbol_ Token symbol.
    /// @param underlying_ The wrapped ERC-20 token.
    constructor(
        string memory name_,
        string memory symbol_,
        IERC20 underlying_
    ) ERC7984(name_, symbol_, "") ERC7984ERC20Wrapper(underlying_) {
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
    }

    /// @notice Mint a plaintext amount as an encrypted balance, for funding test instances directly.
    /// @param to Recipient address.
    /// @param amount Plaintext amount (max type(uint64).max).
    function mint(address to, uint64 amount) external {
        _mint(to, FHE.asEuint64(amount));
    }
}
