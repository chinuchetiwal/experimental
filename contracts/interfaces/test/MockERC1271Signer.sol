// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title MockERC1271Signer
 * @author TokenOps
 * @notice Minimal ERC-1271 smart-account stand-in used to exercise the smart-account (ERC-1271) branch of
 *         `ECDSAConfidentialAirdrop`'s single signer-explicit claim path (where `signer` is this contract).
 *         It validates a signature by recovering an EOA `owner` over the supplied hash: a signature is valid
 *         iff it was produced by `owner`. The airdrop verifies it via OZ
 *         `SignatureChecker.isValidSignatureNow(signer, digest, signature)`, which staticcalls this
 *         contract's `isValidSignature` because `signer` (this address) has code.
 * @dev TEST-ONLY. Uses OZ `ECDSA.tryRecover` so a malformed signature yields the non-magic `bytes4(0)`
 *      rather than reverting — mirroring a well-behaved wallet and keeping the airdrop's view-path check
 *      (`isSignatureValid`, which staticcalls here) revert-free. No bespoke crypto.
 */
contract MockERC1271Signer is IERC1271 {
    /// @notice The EOA whose EIP-712 signature this smart account accepts.
    address public immutable owner;

    /// @notice ERC-1271 magic value returned for a valid signature (`bytes4(keccak256("isValidSignature(bytes32,bytes)"))`).
    bytes4 private constant MAGIC_VALUE = 0x1626ba7e;

    /// @param owner_ The EOA that authorizes claims on behalf of this smart account.
    constructor(address owner_) {
        owner = owner_;
    }

    /// @inheritdoc IERC1271
    /// @dev Returns the ERC-1271 magic value iff `ECDSA.recover(hash, signature) == owner`; otherwise
    ///      returns `bytes4(0)`. A malformed signature recovers to the zero address (never `owner`), so it
    ///      too yields the non-magic value without reverting.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) return MAGIC_VALUE;
        return bytes4(0);
    }
}
