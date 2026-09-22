// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

/**
 * @title ConfidentialAirdropConfigStorage
 * @author TokenOps
 * @notice ERC-7201 namespaced storage for the airdrop instance's hot-path lifecycle config.
 * @dev Namespace `tokenops.storage.airdrop.instance.v2.config`. Inherited by `ConfidentialAirdropBase`.
 *
 *      All fields read on every claim live in slot 0 (packed to 30/32 bytes) so the claim path touches
 *      one cold SLOAD for the whole config. `gasFee` lives in slot 1, packed with `complianceManager` —
 *      that slot is already read on every claim by `_grantCompliance`, so `gasFee` costs zero extra cold
 *      SLOADs. The fee collector is NOT here — it is `FEE_COLLECTOR_ROLE` membership in AccessControl's
 *      own namespace. The `AirdropType` discriminator is NOT stored here either — each concrete
 *      implementation returns its own constant `airdropType()` as a `pure` function, so a value fixed at
 *      compile time never occupies a storage slot.
 *
 *      Slot formula (EIP-7201):
 *      location = keccak256(abi.encode(uint256(keccak256(<id>)) - 1)) & ~bytes32(uint256(0xff))
 */
abstract contract ConfidentialAirdropConfigStorage {
    /// @custom:storage-location erc7201:tokenops.storage.airdrop.instance.v2.config
    struct ConfigStorage {
        // HOT PATH — read on every claim → all in slot 0 (30/32 bytes)
        address token; //                20  ERC-7984 token
        uint32 startTime; //              4  claim window start (unix)
        uint32 endTime; //                4  claim window end (unix)
        bool canExtendClaimWindow; //     1
        bool unwrappable; //              1  true when token is an ERC7984ERC20Wrapper → claimAndUnwrap allowed
        // slot 1 — read on every claim by _grantCompliance, which grants compliance access to this address
        address complianceManager; //    20  the instance's OWN ComplianceRoleManager CLONE
        uint96 gasFee; //                 12  per-claim gas fee, resolved by the factory and frozen at init;
        //                                    packs with complianceManager into the same already-hot slot
        // slot 2
        uint256 deploymentBlockNumber; // POST-INIT informational ONLY (never in salt/address)
        // pause state lives in PausableUpgradeable's own namespace; EIP712 domain in EIP712Upgradeable's;
        // the collector is FEE_COLLECTOR_ROLE membership.
    }

    /// @dev Wrapper around the config struct enabling a WHOLE-STRUCT memory→storage copy: Solidity forbids
    ///      assigning a memory struct to a bare local storage POINTER (that would rebind the pointer), but
    ///      allows it to a struct MEMBER. `config` is the wrapper's only member, so it occupies exactly the
    ///      same slots as `ConfigStorage` at the namespace location — the storage layout is unchanged.
    struct ConfigStorageSlot {
        ConfigStorage config;
    }

    // keccak256(abi.encode(uint256(keccak256("tokenops.storage.airdrop.instance.v2.config")) - 1)) & ~0xff
    bytes32 internal constant AIRDROP_CONFIG_STORAGE_LOCATION =
        0xe358d2f5dc9f121d881806aecf2dd7584bd8216246f5902f9b093a79de46fb00;

    function _getConfigStorage() internal pure returns (ConfigStorage storage $) {
        assembly ("memory-safe") {
            $.slot := AIRDROP_CONFIG_STORAGE_LOCATION
        }
    }

    /// @notice Write the whole config in ONE assignment, so the compiler emits one SSTORE per packed slot
    ///         (a field-by-field write re-reads and re-masks the packed slot 0 for every field).
    /// @param c The fully-populated config (a named-parameter struct literal at the call site).
    function _setConfigStorage(ConfigStorage memory c) internal {
        ConfigStorageSlot storage $;
        assembly ("memory-safe") {
            $.slot := AIRDROP_CONFIG_STORAGE_LOCATION
        }
        $.config = c;
    }
}
