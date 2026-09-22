// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {FHE, euint64} from "@fhevm/solidity/lib/FHE.sol";

import {TestERC7984ERC20Wrapper} from "./TestERC7984ERC20Wrapper.sol";

/// @title HookedERC7984ERC20Wrapper
/// @author TokenOps
/// @notice The genuine test wrapper, plus two switchable departures from stock behavior: `_unwrap` can
///         credit the unwrapped holder inside the burn, and it can return an unwrap request id that is not
///         the handle of the amount it burned. Used to exercise the airdrop unwrap accounting against a
///         wrapper that does not behave like the stock OpenZeppelin one.
/// @dev Both behaviors are off by default, so an unconfigured instance behaves exactly like its base. The
///      burn itself is always real: `super._unwrap` runs first and the rebate is minted afterwards, so the
///      holder's balance can end up higher after the call than before it.
contract HookedERC7984ERC20Wrapper is TestERC7984ERC20Wrapper {
    /// @notice Plaintext amount minted back to the unwrapped holder inside `_unwrap`; zero disables it.
    uint64 public rebate;

    /// @notice Which request id `_unwrap` returns. 0 the real one; 1 a non-handle `bytes32`; 2 a fresh
    ///         handle only this wrapper is allowed on; 3 the zero word; 4 a fresh encrypted-0 handle this
    ///         wrapper has granted to `forgedGrantee`.
    uint8 public forgedRequestIdMode;

    /// @notice The address mode 4 grants its forged handle to (set it to the airdrop instance under test).
    address public forgedGrantee;

    /// @param name_ Token name.
    /// @param symbol_ Token symbol.
    /// @param underlying_ The wrapped ERC-20 token.
    constructor(
        string memory name_,
        string memory symbol_,
        IERC20 underlying_
    ) TestERC7984ERC20Wrapper(name_, symbol_, underlying_) {}

    /// @notice Set the plaintext amount credited back to the holder inside every later `_unwrap`.
    /// @param rebate_ The amount, or zero to disable.
    function setRebate(uint64 rebate_) external {
        rebate = rebate_;
    }

    /// @notice Select which request id every later `_unwrap` returns.
    /// @param mode 0 real, 1 a non-handle `bytes32`, 2 a handle only this wrapper may use, 3 the zero word,
    ///        4 a fresh encrypted-0 handle granted to `forgedGrantee`.
    function setForgedRequestId(uint8 mode) external {
        forgedRequestIdMode = mode;
    }

    /// @notice Set the address mode 4 grants its forged handle to.
    /// @param grantee The grantee, normally the airdrop instance that will read the request id back.
    function setForgedGrantee(address grantee) external {
        forgedGrantee = grantee;
    }

    /// @dev Real burn first, then the optional rebate, then the real or forged request id.
    function _unwrap(address from, address to, euint64 amount) internal override returns (bytes32) {
        bytes32 requestId = super._unwrap(from, to, amount);
        if (rebate > 0) _mint(from, FHE.asEuint64(rebate));
        if (forgedRequestIdMode == 1) return keccak256(abi.encode(requestId));
        if (forgedRequestIdMode == 2) return euint64.unwrap(FHE.allowThis(FHE.asEuint64(1)));
        if (forgedRequestIdMode == 3) return bytes32(0);
        if (forgedRequestIdMode == 4) {
            euint64 zero = FHE.asEuint64(0);
            FHE.allowThis(zero);
            FHE.allow(zero, forgedGrantee);
            return euint64.unwrap(zero);
        }
        return requestId;
    }
}
