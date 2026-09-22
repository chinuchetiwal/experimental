// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title ComplianceManagerStorage
 * @author TokenOps
 * @notice ERC-7201 namespaced storage for the per-instance `ComplianceRoleManager` clone.
 * @dev Namespace `tokenops.storage.airdrop.compliance.v2.main`. The manager is cloned and initialized
 *      per airdrop, so it follows the same upgradeable-style ERC-7201 discipline as the airdrop
 *      instances (fresh storage per clone; the CREATE3 impl is locked by `_disableInitializers()`).
 *
 *      The struct is named `ComplianceStorage` rather than `ComplianceManagerStorage` to avoid colliding
 *      with the enclosing abstract-contract name, matching the contract-vs-struct naming used elsewhere
 *      (`ConfidentialAirdropConfigStorage` → `ConfigStorage`). The accessor is `_getComplianceStorage()`.
 */
abstract contract ComplianceManagerStorage {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @custom:storage-location erc7201:tokenops.storage.airdrop.compliance.v2.main
    struct ComplianceStorage {
        address airdrop; //          slot 0 — the ONE airdrop instance this clone serves (set at init;
        //                                    there is no separate registry — the clone↔instance pairing
        //                                    IS the bookkeeping)
        address complianceDelegate; // slot 1 — the factory-designated platform compliance delegate this clone
        //                                    delegated to at init (address(0) iff the effective policy was
        //                                    OFF). Recorded for transparency; there is NO code path that
        //                                    revokes this delegation (irrevocable by construction).
        EnumerableSet.AddressSet clientDelegates; // mirror of the client-side ACL delegations this clone
        //                                            has performed (incl. the init-time client delegate);
        //                                            authoritative state lives in the fhEVM ACL.
    }

    // keccak256(abi.encode(uint256(keccak256("tokenops.storage.airdrop.compliance.v2.main")) - 1)) & ~0xff
    bytes32 internal constant COMPLIANCE_MAIN_STORAGE_LOCATION =
        0x57d58fc4a85939b039f9d93f9be48d3244e9820d76cc62240e73bb85e64f7900;

    function _getComplianceStorage() internal pure returns (ComplianceStorage storage $) {
        assembly ("memory-safe") {
            $.slot := COMPLIANCE_MAIN_STORAGE_LOCATION
        }
    }
}
