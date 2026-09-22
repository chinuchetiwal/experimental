// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {euint64} from "@fhevm/solidity/lib/FHE.sol";
// Prettier joins this import onto one line; the upstream package path pushes it past max-line-length 120.
// solhint-disable-next-line max-line-length
import {IERC7984ERC20Wrapper as IERC7984ERC20WrapperUpstream} from "@openzeppelin/confidential-contracts/interfaces/IERC7984ERC20Wrapper.sol";

/// @title IERC7984ERC20Wrapper
/// @author TokenOps
/// @notice OpenZeppelin's {IERC7984ERC20Wrapper} (confidential-contracts 0.5.1) extended with the
///         no-proof `unwrap(address,address,euint64)` overload used by the airdrop unwrap path.
/// @dev This interface inherits OpenZeppelin's published `IERC7984ERC20Wrapper` verbatim — the full wrapper
///      surface (`wrap`, the proof-based `unwrap`, `underlying`, `finalizeUnwrap`, `rate`, `unwrapAmount`, the
///      unwrap events) comes from the upstream package. The only local addition is the single no-proof overload
///      below, which is declared here deliberately because:
///      (1) OpenZeppelin omits it from their published interface even though the concrete
///          `ERC7984ERC20Wrapper` (token/ERC7984/extensions, 0.5.1) declares it `public virtual`; and
///      (2) it is the only unwrap path a holding contract can drive — an airdrop holds an internal `euint64`
///          claim handle and cannot synthesize an `externalEuint64`+`inputProof` on-chain (those are
///          KMS-signed off-chain).
///      This is the overload `ConfidentialAirdropBase._unwrapTo` calls.
interface IERC7984ERC20Wrapper is IERC7984ERC20WrapperUpstream {
    /**
     * @notice Unwrap an ALREADY-HELD `euint64` handle and send the underlying ERC-20 to `to`.
     * @dev Unwraps an ALREADY-HELD `euint64` handle from `from` and sends the underlying tokens to `to`.
     * The caller must be `from` or an approved operator for `from`, and must hold ACL allowance on
     * `amount` (`FHE.isAllowed(amount, msg.sender)`). Returns the unwrap request id.
     *
     * NOTE: The returned unwrap request id must never be zero.
     * @param from The holder whose confidential balance is unwrapped (the caller or its operator).
     * @param to The beneficiary that receives the underlying ERC-20 after `finalizeUnwrap`.
     * @param amount The already-held encrypted amount handle to unwrap.
     * @return The unwrap request id (never zero).
     */
    function unwrap(address from, address to, euint64 amount) external returns (bytes32);
}
