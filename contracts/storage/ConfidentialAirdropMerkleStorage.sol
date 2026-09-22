// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {euint64} from "@fhevm/solidity/lib/FHE.sol";

/**
 * @title ConfidentialAirdropMerkleStorage
 * @author TokenOps
 * @notice ERC-7201 namespaced storage for the Merkle implementation's root and per-account cumulative
 *         claimed accounting.
 * @dev Namespace `tokenops.storage.airdrop.instance.v2.merkle`. Inherited by `MerkleConfidentialAirdrop`
 *      only, keeping each implementation's storage isolated.
 *
 *      `claimedAmount` is keyed by account and holds the encrypted running total DELIVERED to that account
 *      so far. Leaves commit each account's cumulative total allocation, and a claim pays out only the
 *      outstanding difference, so rotating the root (in mutable mode) can never re-open value that was
 *      already paid — there is no per-leaf consumption to track.
 */
abstract contract ConfidentialAirdropMerkleStorage {
    /// @custom:storage-location erc7201:tokenops.storage.airdrop.instance.v2.merkle
    struct MerkleStorage {
        bytes32 merkleRoot; //                          commitment root
        bool isMerkleRootMutable; //                    when true, setMerkleRoot is allowed ANY time, ANY number
        //                                              of times, incl. mid-campaign (default false = immutable)
        mapping(address account => euint64 amount) claimedAmount; // cumulative DELIVERED per account (encrypted;
        //                                              zero-handle before the account's first settled claim)
    }

    // keccak256(abi.encode(uint256(keccak256("tokenops.storage.airdrop.instance.v2.merkle")) - 1)) & ~0xff
    bytes32 internal constant AIRDROP_MERKLE_STORAGE_LOCATION =
        0x415da4d7d0107e9264b601debc2ae55ad7ba40221919132fb1432ef61115e800;

    function _getMerkleStorage() internal pure returns (MerkleStorage storage $) {
        assembly ("memory-safe") {
            $.slot := AIRDROP_MERKLE_STORAGE_LOCATION
        }
    }
}
