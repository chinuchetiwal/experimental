// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/// @title CallForwarder
/// @author TokenOps
/// @notice Test-only contract that forwards arbitrary calldata and value to a target set at
///         construction, bubbling the target's revert data back verbatim. Used to reach an entrypoint
///         from a caller that has code, so a self-only guard can be exercised against a contract caller
///         as well as an EOA one, and so a claim can be submitted by a contract.
contract CallForwarder {
    /// @notice Reports the outcome of a `probeGas` forward, including the gas the forwarded call consumed.
    /// @param ok Whether the forwarded call succeeded.
    /// @param gasUsed Gas the forwarded call itself consumed, excluding this contract's own overhead.
    /// @param returned The call's return data, or its revert data when `ok` is false.
    event Probe(bool ok, uint256 gasUsed, bytes returned);

    /// @notice The address every forwarded call is sent to.
    address public immutable forwardTarget;

    /// @param target_ The contract to forward calls to.
    constructor(address target_) {
        forwardTarget = target_;
    }

    /// @notice Forward `data` and any attached value to `target`, bubbling its revert data verbatim so the
    ///         caller can assert on the target's own named error.
    /// @param data The raw calldata to forward.
    /// @return The target's return data.
    function forward(bytes calldata data) external payable returns (bytes memory) {
        // Plain low-level call rather than a library helper: the raw revert data must survive intact.
        (bool ok, bytes memory returned) = forwardTarget.call{value: msg.value}(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(returned, 0x20), mload(returned))
            }
        }
        return returned;
    }

    /// @notice Forward `data` and any attached value to `target` WITHOUT bubbling a revert, reporting the
    ///         outcome and the gas the forwarded call consumed through the `Probe` event.
    /// @dev Lets a test measure how far into an entrypoint a rejected call actually got: a guard that fires
    ///      before the expensive work costs a small fraction of what the accepted call costs. The
    ///      measurement has to happen inside the EVM because a reverting transaction leaves no receipt to
    ///      read the figure off. The revert data is reported rather than bubbled, so the outer transaction
    ///      succeeds and the event survives.
    /// @param data The raw calldata to forward.
    function probeGas(bytes calldata data) external payable {
        uint256 gasBefore = gasleft();
        (bool ok, bytes memory returned) = forwardTarget.call{value: msg.value}(data);
        emit Probe(ok, gasBefore - gasleft(), returned);
    }
}
