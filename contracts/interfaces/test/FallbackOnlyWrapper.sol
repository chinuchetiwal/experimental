// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {FHE} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title FallbackOnlyWrapper
/// @author TokenOps
/// @notice Test-only ERC-7984 that answers `underlying()` but deliberately does NOT advertise the canonical
///         wrapper interfaceId via ERC-165. It exists solely to exercise the wrapper probe's FALLBACK leg —
///         the `underlying()` staticcall path that detects wrappers which do not implement ERC-165 detection
///         for the wrapper interface. The genuine wrapper used everywhere else always advertises ERC-165, so
///         only this helper can reach that fallback branch.
/// @dev Implements only the minimal surface the fallback probe touches; it is not a full wrapper (no `wrap`,
///      no `unwrap`, no `finalizeUnwrap`, no `rate`). ERC-7984 `_update` clamps an uninitialized balance to
///      encrypted zero rather than reverting, so this contract's fail-closed role in the unwrap-rollback tests
///      comes from the ABSENT `unwrap()` selector (a generic unrecognized-selector revert), never from
///      `_update`.
contract FallbackOnlyWrapper is ERC7984 {
    /// @notice The wrapped ERC-20 token address (non-zero so the `underlying()` probe leg succeeds).
    address public immutable underlyingToken;

    /// @param name_ Token name.
    /// @param symbol_ Token symbol.
    /// @param underlying_ The wrapped ERC-20 (non-zero for the `underlying()` probe leg).
    constructor(string memory name_, string memory symbol_, address underlying_) ERC7984(name_, symbol_, "") {
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
        underlyingToken = underlying_;
    }

    /// @notice The wrapped ERC-20 token — the probe's fallback wrapper signal.
    /// @return The underlying ERC-20 address.
    function underlying() external view returns (address) {
        return underlyingToken;
    }
}
