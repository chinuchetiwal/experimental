// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {AirdropERC1967Proxy} from "../factory/AirdropERC1967Proxy.sol";

/// @title CloneDeployer
/// @author TokenOps
/// @notice Test helper that deploys airdrop instances the way the factory does: a plain EIP-1167 clone
///         (`Clones.clone`) or an `AirdropERC1967Proxy` — neither carries immutable args, since `gasFee` is
///         now an `initialize`-time param frozen into config storage rather than a deploy-time argument. The
///         clone address is emitted (`Clones.clone` uses CREATE, so it cannot be predicted via staticCall).
contract CloneDeployer {
    /// @notice Emitted with the address of a freshly deployed clone/proxy.
    /// @param instance The deployed instance address.
    event Deployed(address indexed instance);

    /// @notice Deploy a plain EIP-1167 clone of `impl` (also used for the compliance manager, which shares
    ///         this same no-args shape).
    /// @param impl The implementation to clone.
    /// @return clone The deployed clone (initialize it next).
    function cloneOf(address impl) external returns (address clone) {
        clone = Clones.clone(impl);
        emit Deployed(clone);
    }

    /// @notice Deploy an `AirdropERC1967Proxy` of `impl` (initialize it next).
    /// @param impl The implementation behind the proxy.
    /// @return proxy The deployed ERC-1967 proxy.
    function deployUUPS(address impl) external returns (address proxy) {
        proxy = address(new AirdropERC1967Proxy(impl));
        emit Deployed(proxy);
    }
}
