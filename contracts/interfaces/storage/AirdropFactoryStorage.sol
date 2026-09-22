// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {CustomFee, CompliancePolicy, UpgradeabilityPolicy} from "../interfaces/IAirdropFactory.sol";

/**
 * @title AirdropFactoryStorage
 * @author TokenOps
 * @notice ERC-7201 namespaced storage for the `AirdropFactory` CREATE3 singleton.
 * @dev Namespace `tokenops.storage.airdrop.factory.v2.main`. Holds the two airdrop impl addresses,
 *      the manager impl it clones per airdrop, the fee config (source of the frozen-at-create
 *      `gasFee` init param and the collector init param), the admin-governed maximum on that fee, the
 *      `CompliancePolicy` (global default plus per-deployer override), and the append-only on-chain
 *      read-list of created airdrops.
 */
abstract contract AirdropFactoryStorage {
    /// @custom:storage-location erc7201:tokenops.storage.airdrop.factory.v2.main
    struct FactoryMainStorage {
        address ecdsaImplementation; //         ECDSAConfidentialAirdrop  (CREATE3 singleton)
        address merkleImplementation; //        MerkleConfidentialAirdrop (CREATE3 singleton)
        address complianceManagerImpl; //       ComplianceRoleManager IMPL the factory CLONES per airdrop
        address complianceDelegate; //          the platform compliance address new manager clones delegate
        //                                      to (iff the effective policy is ON; set from the factory)
        address feeCollector; //           ┐    collector injected as an init param at create;
        uint96 defaultGasFee; //           ┘    default per-claim gas fee (source of the init param);
        //                                      20 + 12 = 32 bytes, one full slot with feeCollector
        bool defaultDelegateToCompliance; // ┐  global policy default — ON for every address
        bool defaultUpgradeable; //          ┘  global upgradeability default — FALSE (no UUPS) out of the
        //                                      box. Create-time-only; NOT part of any deployed address
        //                                      (the predicted address and init code hash are unaffected).
        mapping(address creator => CustomFee) customFees;
        mapping(address creator => CompliancePolicy) compliancePolicies; //   per-deployer override
        mapping(address creator => UpgradeabilityPolicy) upgradeabilityPolicies; // per-creator override
        mapping(address airdrop => address managerClone) complianceManagerOf; // factory-level bookkeeping —
        //                                                        the sole registry; the manager clone keeps none
        address[] deployedAirdrops; //          append-only enumeration of every airdrop THIS factory
        //                                      created, in creation order (no external indexer needed; backs
        //                                      the airdropCount/airdropAt/airdrops views). Membership is
        //                                      already O(1) via `complianceManagerOf[a] != address(0)` — so
        //                                      no separate index/membership mapping is needed.
        uint96 maxGasFee; //                    admin-governed maximum on `defaultGasFee`/`customFees` and on
        //                                      the fee resolved at create; seeded by the constructor;
        //                                      append-only member (the factory is not upgradeable, but
        //                                      layout hygiene is kept anyway).
    }

    // keccak256(abi.encode(uint256(keccak256("tokenops.storage.airdrop.factory.v2.main")) - 1)) & ~0xff
    bytes32 internal constant FACTORY_MAIN_STORAGE_LOCATION =
        0x585eb631fcaa48e3a654a3fd1bcd5a46d3e13e3125feca9a5822e18424654800;

    function _getFactoryStorage() internal pure returns (FactoryMainStorage storage $) {
        assembly ("memory-safe") {
            $.slot := FACTORY_MAIN_STORAGE_LOCATION
        }
    }
}
