// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title AirdropERC1967Proxy
 * @author TokenOps
 * @notice The UUPS deployment shell for a confidential airdrop instance: a minimal `ERC1967Proxy` that takes
 *         only the implementation address, with no init calldata.
 * @dev OZ's `ERC1967Proxy` reverts `ERC1967ProxyUninitialized()` when constructed with empty `_data`, guarding
 *      against a proxy that is deployed and left uninitialized for anyone to front-run. That guard does not
 *      fit this deployment: the factory deploys this proxy via CREATE2 and calls the instance's `initialize`
 *      in the very same transaction, so there is no window in which an uninitialized proxy exists at a known
 *      address. `_unsafeAllowUninitialized` is the override OZ ships for exactly this same-transaction-init
 *      pattern, so this contract opts into it and constructs the base proxy with empty data. Taking only
 *      `implementation` (never `_data`) keeps this contract's init code fixed to `creationCode ++
 *      abi.encode(implementation)`, so nothing beyond the implementation address can ever enter its address
 *      derivation.
 *
 *      This contract carries no access control of its own: anyone may deploy a proxy over a public
 *      implementation and initialize it themselves. That is benign on the funding side - the airdrop
 *      implementations lock themselves with `_disableInitializers()`, and a proxy not deployed by the factory
 *      is absent from the factory registry, so it can never be funded through the factory.
 *
 *      It is not benign on the claim side by itself: a self-initialized proxy exposes the same ABI, the same
 *      `airdropType()`/`token()`, and can point at a self-paired compliance-manager clone of its own, so
 *      nothing observable at the instance distinguishes it from a genuine one. The registry membership that
 *      protects funding is the same discriminator a claimant or funder must consult before trusting any
 *      instance: only the factory that deployed an instance ever records it, so calling `isAirdrop` there
 *      (rather than trusting anything the instance itself reports) is what actually proves genuineness.
 */
contract AirdropERC1967Proxy is ERC1967Proxy {
    constructor(address implementation) ERC1967Proxy(implementation, "") {}

    /// @dev Opts out of OZ's uninitialized-proxy guard; see the contract-level NatSpec for why that is safe here.
    function _unsafeAllowUninitialized() internal pure override returns (bool) {
        return true;
    }
}
