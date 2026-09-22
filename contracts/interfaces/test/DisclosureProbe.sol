// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity 0.8.34;

import {FHE, euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

import {IMerkleConfidentialAirdrop} from "../interfaces/IMerkleConfidentialAirdrop.sol";
import {IConfidentialAirdropBase} from "../interfaces/IConfidentialAirdropBase.sol";

/// @title IACLReader
/// @author TokenOps
/// @notice The subset of the host ACL this probe reads and writes directly.
interface IACLReader {
    /// @notice Whether `handle` has been marked publicly decryptable.
    function isAllowedForDecryption(bytes32 handle) external view returns (bool);

    /// @notice Whether `account` holds a PERSISTENT allowance on `handle`.
    function persistAllowed(bytes32 handle, address account) external view returns (bool);

    /// @notice Whether `account` holds a transient OR persistent allowance on `handle`.
    function isAllowed(bytes32 handle, address account) external view returns (bool);
}

/**
 * @title DisclosureProbe
 * @author TokenOps
 * @notice TEST-ONLY attacker contract used to probe whether a transaction submitter can obtain an ACL
 *         foothold on an encrypted allocation handle it does not own. It is not part of the system and is
 *         never deployed outside tests.
 * @dev The capability it probes for: verifying an encrypted input grants the VERIFYING FRAME'S CALLER a
 *      transient ACL allowance on the resulting handle, and both `ACL.allow` and `ACL.allowForDecryption`
 *      accept a transient allowance as authority to write a PERSISTENT grant. A submitter that holds such a
 *      transient allowance on another account's committed total could therefore make that total permanently
 *      readable, or publicly decryptable, and persistent grants cannot be revoked.
 *
 *      Each route performs the verification and the laundering attempt in ONE transaction, which is why
 *      only a contract can attempt it: an externally owned account cannot make two calls atomically.
 *
 *      Two shapes of each laundering route are provided. The plain routes let the ACL's own revert bubble
 *      out so a test can assert the exact error. The `…Recording` routes capture the failure instead of
 *      bubbling it, so a test can prove in a single transaction that the airdrop call SUCCEEDED and only
 *      the laundering step failed - otherwise a bubbled revert is indistinguishable from an attack that
 *      never got off the ground.
 */
contract DisclosureProbe {
    /// @notice The host ACL address this probe reads and writes.
    address public immutable acl;

    /// @notice Selector captured from the most recent recorded laundering attempt (0x0 if it succeeded).
    bytes4 public lastLaunderSelector;

    /// @notice Raw revert data captured from the most recent recorded laundering attempt.
    bytes public lastLaunderData;

    /// @notice The outstanding-amount handle the airdrop most recently returned to this probe.
    euint64 public lastOutstanding;

    constructor() {
        FHE.setCoprocessor(ZamaConfig.getEthereumCoprocessorConfig());
        acl = ZamaConfig.getEthereumCoprocessorConfig().ACLAddress;
    }

    // ───────────────────────────── baseline: the attack surface is live ─────────────────────────────

    /// @notice Run the fee-free preview for `account` as a CONTRACT submitter and keep the returned handle.
    /// @param airdrop The Merkle airdrop instance.
    /// @param account The claim identity being previewed (need not be this probe).
    /// @param inputAmount The external encrypted cumulative-total handle.
    /// @param inputProof The input proof for `inputAmount`.
    /// @param merkleProof The Merkle proof path for `account`'s leaf.
    function previewOnly(
        address airdrop,
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external {
        lastOutstanding = IMerkleConfidentialAirdrop(airdrop).getClaimAmount(
            account,
            inputAmount,
            inputProof,
            merkleProof
        );
    }

    /// @notice Submit a full third-party claim for `account` as a CONTRACT submitter.
    /// @param airdrop The Merkle airdrop instance.
    /// @param account The claim identity.
    /// @param to Redirect-only payout destination (0 defaults to `account`).
    /// @param inputAmount The external encrypted cumulative-total handle.
    /// @param inputProof The input proof for `inputAmount`.
    /// @param merkleProof The Merkle proof path for `account`'s leaf.
    function submitClaimFor(
        address airdrop,
        address account,
        address to,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external payable {
        IMerkleConfidentialAirdrop(airdrop).claim{value: msg.value}(account, to, inputAmount, inputProof, merkleProof);
    }

    // ───────────────────────────── laundering routes (bubbling) ────────────────────────────────────

    /// @notice Route 1: verify via the fee-free preview, then persist a private read grant to `grantee`.
    /// @param airdrop The Merkle airdrop instance.
    /// @param account The claim identity being previewed.
    /// @param inputAmount The external encrypted cumulative-total handle (the handle under attack).
    /// @param inputProof The input proof for `inputAmount`.
    /// @param merkleProof The Merkle proof path for `account`'s leaf.
    /// @param grantee The address the probe tries to make a permanent reader of the raw total.
    function routePrivateRead(
        address airdrop,
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof,
        address grantee
    ) external {
        IMerkleConfidentialAirdrop(airdrop).getClaimAmount(account, inputAmount, inputProof, merkleProof);
        euint64 raw = euint64.wrap(bytes32(externalEuint64.unwrap(inputAmount)));
        FHE.allowThis(raw);
        FHE.allow(raw, grantee);
    }

    /// @notice Route 2: verify via the fee-free preview, then mark the raw total publicly decryptable.
    /// @param airdrop The Merkle airdrop instance.
    /// @param account The claim identity being previewed.
    /// @param inputAmount The external encrypted cumulative-total handle (the handle under attack).
    /// @param inputProof The input proof for `inputAmount`.
    /// @param merkleProof The Merkle proof path for `account`'s leaf.
    function routePublicDisclosure(
        address airdrop,
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external {
        IMerkleConfidentialAirdrop(airdrop).getClaimAmount(account, inputAmount, inputProof, merkleProof);
        FHE.makePubliclyDecryptable(euint64.wrap(bytes32(externalEuint64.unwrap(inputAmount))));
    }

    /// @notice Route 3: verify, then launder through the airdrop's OWN two-gate disclosure surface.
    /// @dev Gate 1 is a PERSISTENT user-decryption ACL on the handle - measured against THIS probe AND the
    ///      airdrop instance, so a transient allowance never passes it - and gate 2 requires the airdrop
    ///      instance to be allowed on the handle.
    /// @param airdrop The Merkle airdrop instance.
    /// @param account The claim identity being previewed.
    /// @param inputAmount The external encrypted cumulative-total handle (the handle under attack).
    /// @param inputProof The input proof for `inputAmount`.
    /// @param merkleProof The Merkle proof path for `account`'s leaf.
    /// @param party The address the probe asks the airdrop to grant.
    function routeViaAirdropDisclosure(
        address airdrop,
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof,
        address party
    ) external {
        IMerkleConfidentialAirdrop(airdrop).getClaimAmount(account, inputAmount, inputProof, merkleProof);
        IConfidentialAirdropBase(airdrop).discloseHandleToParty(
            euint64.wrap(bytes32(externalEuint64.unwrap(inputAmount))),
            party
        );
    }

    /// @notice Route 3, batch form: verify, then launder through the airdrop's BATCH disclosure surface.
    /// @dev Same two gates as the single-handle form, reached through a different entrypoint, so the batch
    ///      surface is probed rather than assumed to behave like its sibling.
    /// @param airdrop The Merkle airdrop instance.
    /// @param account The claim identity being previewed.
    /// @param inputAmount The external encrypted cumulative-total handle (the handle under attack).
    /// @param inputProof The input proof for `inputAmount`.
    /// @param merkleProof The Merkle proof path for `account`'s leaf.
    /// @param party The address the probe asks the airdrop to grant.
    function routeViaAirdropBatchDisclosure(
        address airdrop,
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof,
        address party
    ) external {
        IMerkleConfidentialAirdrop(airdrop).getClaimAmount(account, inputAmount, inputProof, merkleProof);
        euint64[] memory handles = new euint64[](1);
        handles[0] = euint64.wrap(bytes32(externalEuint64.unwrap(inputAmount)));
        IConfidentialAirdropBase(airdrop).batchDiscloseHandlesToParty(handles, party);
    }

    /// @notice Batch amplification: one shared input proof covering many recipients, all in one transaction.
    /// @param airdrop The Merkle airdrop instance.
    /// @param accounts The claim identities being previewed.
    /// @param inputAmounts One external encrypted cumulative-total handle per account.
    /// @param inputProof The single input proof covering every handle.
    /// @param merkleProofs One Merkle proof path per account.
    function routeBatchPublic(
        address airdrop,
        address[] calldata accounts,
        externalEuint64[] calldata inputAmounts,
        bytes calldata inputProof,
        bytes32[][] calldata merkleProofs
    ) external {
        for (uint256 i = 0; i < accounts.length; i++) {
            IMerkleConfidentialAirdrop(airdrop).getClaimAmount(
                accounts[i],
                inputAmounts[i],
                inputProof,
                merkleProofs[i]
            );
            FHE.makePubliclyDecryptable(euint64.wrap(bytes32(externalEuint64.unwrap(inputAmounts[i]))));
        }
    }

    // ───────────────────────────── laundering routes (recording) ───────────────────────────────────

    /// @notice Route 1, recording: preview, then record whether the private-read grant was accepted.
    /// @param airdrop The Merkle airdrop instance.
    /// @param account The claim identity being previewed.
    /// @param inputAmount The external encrypted cumulative-total handle (the handle under attack).
    /// @param inputProof The input proof for `inputAmount`.
    /// @param merkleProof The Merkle proof path for `account`'s leaf.
    /// @param grantee The address the probe tries to make a permanent reader of the raw total.
    function routePrivateReadRecording(
        address airdrop,
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof,
        address grantee
    ) external {
        lastOutstanding = IMerkleConfidentialAirdrop(airdrop).getClaimAmount(
            account,
            inputAmount,
            inputProof,
            merkleProof
        );
        _recordAllow(bytes32(externalEuint64.unwrap(inputAmount)), grantee);
    }

    /// @notice Route 2, recording: preview, then record whether public decryption was accepted.
    /// @param airdrop The Merkle airdrop instance.
    /// @param account The claim identity being previewed.
    /// @param inputAmount The external encrypted cumulative-total handle (the handle under attack).
    /// @param inputProof The input proof for `inputAmount`.
    /// @param merkleProof The Merkle proof path for `account`'s leaf.
    function routePublicDisclosureRecording(
        address airdrop,
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof
    ) external {
        lastOutstanding = IMerkleConfidentialAirdrop(airdrop).getClaimAmount(
            account,
            inputAmount,
            inputProof,
            merkleProof
        );
        _recordAllowForDecryption(bytes32(externalEuint64.unwrap(inputAmount)));
    }

    /// @notice Full third-party claim, then record whether the raw total can be laundered afterwards.
    /// @param airdrop The Merkle airdrop instance.
    /// @param account The claim identity.
    /// @param inputAmount The external encrypted cumulative-total handle (the handle under attack).
    /// @param inputProof The input proof for `inputAmount`.
    /// @param merkleProof The Merkle proof path for `account`'s leaf.
    /// @param grantee The address the probe tries to make a permanent reader of the raw total.
    function claimThenLaunderRecording(
        address airdrop,
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof,
        address grantee
    ) external payable {
        IMerkleConfidentialAirdrop(airdrop).claim{value: msg.value}(
            account,
            address(0),
            inputAmount,
            inputProof,
            merkleProof
        );
        _recordAllow(bytes32(externalEuint64.unwrap(inputAmount)), grantee);
    }

    // ───────────────────────────── privileged-caller route ─────────────────────────────────────────

    /**
     * @notice Preview, then ask the airdrop to disclose the raw total to each of `parties` in the SAME
     *         transaction. Only useful when this probe holds `DISCLOSURE_ADMIN_ROLE`, which bypasses the
     *         disclosure surface's first gate.
     * @dev Passing the airdrop's own address among `parties` writes the CONTRACT leg of a user decryption,
     *      which the instance otherwise only holds transiently on a verified input; pairing it with an
     *      account address writes the USER leg. Whether both together yield a readable plaintext is exactly
     *      what the accompanying test measures.
     * @param airdrop The Merkle airdrop instance.
     * @param account The claim identity being previewed.
     * @param inputAmount The external encrypted cumulative-total handle (the handle under attack).
     * @param inputProof The input proof for `inputAmount`.
     * @param merkleProof The Merkle proof path for `account`'s leaf.
     * @param parties Every address to be granted, in order.
     */
    function routeAdminDisclose(
        address airdrop,
        address account,
        externalEuint64 inputAmount,
        bytes calldata inputProof,
        bytes32[] calldata merkleProof,
        address[] calldata parties
    ) external {
        IMerkleConfidentialAirdrop(airdrop).getClaimAmount(account, inputAmount, inputProof, merkleProof);
        euint64 raw = euint64.wrap(bytes32(externalEuint64.unwrap(inputAmount)));
        for (uint256 i = 0; i < parties.length; i++) {
            IConfidentialAirdropBase(airdrop).discloseHandleToParty(raw, parties[i]);
        }
    }

    /// @notice Ask the airdrop to disclose `handle` to `party` with NO verification in this transaction.
    /// @param airdrop The Merkle airdrop instance.
    /// @param handle The handle to attempt to disclose.
    /// @param party The address to be granted.
    function discloseDirect(address airdrop, euint64 handle, address party) external {
        IConfidentialAirdropBase(airdrop).discloseHandleToParty(handle, party);
    }

    // ───────────────────────────── readers ─────────────────────────────────────────────────────────

    /// @notice Whether `handle` is publicly decryptable.
    /// @param handle The handle to check.
    /// @return Whether the ACL marks it decryptable by anyone.
    function publiclyDecryptable(bytes32 handle) external view returns (bool) {
        return IACLReader(acl).isAllowedForDecryption(handle);
    }

    /// @notice Whether `who` holds a PERSISTENT allowance on `handle`.
    /// @param handle The handle to check.
    /// @param who The account to check.
    /// @return Whether the persistent pair exists.
    function persistedTo(bytes32 handle, address who) external view returns (bool) {
        return IACLReader(acl).persistAllowed(handle, who);
    }

    /// @notice Whether `who` is allowed on `handle` at all (transient or persistent) right now.
    /// @param handle The handle to check.
    /// @param who The account to check.
    /// @return Whether any allowance exists.
    function allowedNow(bytes32 handle, address who) external view returns (bool) {
        return IACLReader(acl).isAllowed(handle, who);
    }

    /// @notice The outstanding handle from the most recent preview or claim, as raw bytes32.
    /// @return The stored handle.
    function lastOutstandingHandle() external view returns (bytes32) {
        return euint64.unwrap(lastOutstanding);
    }

    // ───────────────────────────── internals ───────────────────────────────────────────────────────

    /// @dev Mirrors what `FHE.allow` does (a plain `ACL.allow` call) but keeps the failure instead of
    ///      bubbling it, so the caller can observe that everything BEFORE it succeeded.
    /// @param handle The handle to grant.
    /// @param account The account to grant it to.
    function _recordAllow(bytes32 handle, address account) private {
        (bool ok, bytes memory ret) = acl.call(abi.encodeWithSignature("allow(bytes32,address)", handle, account));
        _record(ok, ret);
    }

    /// @dev Mirrors what `FHE.makePubliclyDecryptable` does, recording rather than bubbling the failure.
    /// @param handle The handle to mark publicly decryptable.
    function _recordAllowForDecryption(bytes32 handle) private {
        bytes32[] memory list = new bytes32[](1);
        list[0] = handle;
        (bool ok, bytes memory ret) = acl.call(abi.encodeWithSignature("allowForDecryption(bytes32[])", list));
        _record(ok, ret);
    }

    /// @dev Store the outcome of a recorded laundering attempt.
    /// @param ok Whether the call succeeded.
    /// @param ret The raw return or revert data.
    function _record(bool ok, bytes memory ret) private {
        lastLaunderData = ret;
        if (ok) {
            lastLaunderSelector = bytes4(0);
            return;
        }
        bytes4 sel;
        if (ret.length >= 4) {
            assembly ("memory-safe") {
                sel := mload(add(ret, 0x20))
            }
        }
        lastLaunderSelector = sel;
    }
}
