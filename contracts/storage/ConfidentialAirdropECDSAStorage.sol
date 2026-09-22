// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {IECDSAConfidentialAirdropTypes} from "../interfaces/IECDSAConfidentialAirdropTypes.sol";

/**
 * @title ConfidentialAirdropECDSAStorage
 * @author TokenOps
 * @notice ERC-7201 namespaced storage for the ECDSA implementation's replay state only.
 * @dev Namespace `tokenops.storage.airdrop.instance.v2.ecdsa`. Inherited by `ECDSAConfidentialAirdrop`
 *      only — the Merkle implementation never carries these fields.
 *
 *      Primary replay protection is dedup keyed on the recipient address and/or the `dedupId` (per the
 *      deploy-time `DedupMode`), not on the EIP-712 struct hash. This enforces that the same address or the
 *      same `dedupId` cannot claim twice. The `dedupId` is bound into the signed struct regardless of mode.
 *      Under `DedupMode.None` neither map is consumed at all — replay protection for that mode rests
 *      entirely on `usedClaimDigest` below.
 *
 *      As defense in depth (or, under `DedupMode.None`, as the PRIMARY guard), `usedClaimDigest`
 *      additionally consumes the EIP-712 claim DIGEST (`_hashTypedDataV4(structHash)`) — the digest, not
 *      raw signature bytes, so `s`/`v` malleations of one signature collapse to the same key. It is marked
 *      consumed before the external transfer/unwrap (checks-effects-interactions) on the stateful
 *      `claim`/`claimAndUnwrap` paths only; the non-consuming preview (`getClaimAmount`) validates the
 *      signature but never sets it. Under `PerAddress`/`PerDedupId`/`Both` this guard is intentionally
 *      conservative: address/dedupId dedup plus the EIP-712 domain and `deadline` already block meaningful
 *      replay.
 */
abstract contract ConfidentialAirdropECDSAStorage {
    /// @custom:storage-location erc7201:tokenops.storage.airdrop.instance.v2.ecdsa
    struct ECDSADedupStorage {
        IECDSAConfidentialAirdropTypes.DedupMode dedupMode; //    PerAddress | PerDedupId | Both | None (init)
        mapping(address recipient => bool) claimedByAddress; //   consumed iff PerAddress/Both
        mapping(bytes32 dedupId => bool) claimedByDedupId; //     consumed iff PerDedupId/Both
        mapping(bytes32 claimDigest => bool) usedClaimDigest; //  digest consumed — primary guard under None,
        //                                                        defense-in-depth otherwise
    }

    // keccak256(abi.encode(uint256(keccak256("tokenops.storage.airdrop.instance.v2.ecdsa")) - 1)) & ~0xff
    bytes32 internal constant AIRDROP_ECDSA_STORAGE_LOCATION =
        0x9584838a5a7fa802f36de14a20c8a084783067e65c7f04cde0aef94a45a32700;

    function _getECDSAStorage() internal pure returns (ECDSADedupStorage storage $) {
        assembly ("memory-safe") {
            $.slot := AIRDROP_ECDSA_STORAGE_LOCATION
        }
    }
}
