// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {CREATE3} from "solady/src/utils/CREATE3.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title CREATE3Deployer
 * @author TokenOps
 * @notice Deterministic cross-chain contract deployer using CREATE3.
 * @dev Deployer contract for deterministic cross-chain deployment using solady's {CREATE3} library.
 *
 * The deployed address depends ONLY on this deployer contract's address and the salt — NOT on the
 * bytecode. This enables identical addresses across all EVM chains, even with different constructor
 * arguments or compiler versions.
 *
 * Used to deploy the {ConfidentialVestingManager} implementation and {ConfidentialVestingFactory}
 * at deterministic addresses.
 *
 * @custom:security-contact security@zama.ai
 */
contract CREATE3Deployer is AccessControl {
    // ============================================================
    //                           ROLES
    // ============================================================

    /// @notice Role identifier for deployment operations.
    /// @dev Role identifier for addresses authorized to deploy contracts via CREATE3.
    bytes32 public constant DEPLOYER_ROLE = keccak256("DEPLOYER_ROLE");

    // ============================================================
    //                           ERRORS
    // ============================================================

    /**
     * @notice Thrown when a salt has already been used for deployment.
     * @dev The `salt` has already been used for a previous deployment.
     */
    error AlreadyDeployed();

    /**
     * @notice Thrown when the zero address is provided.
     * @dev The provided address is the zero address.
     */
    error InvalidAddress();

    // ============================================================
    //                           EVENTS
    // ============================================================

    /**
     * @notice Emitted when a contract is deployed using CREATE3.
     * @dev Emitted when a contract is deployed using CREATE3.
     * @param deployed The address of the newly deployed contract.
     * @param salt The salt used for deterministic address generation.
     * @param label A descriptive label identifying the deployment.
     */
    event ContractDeployed(address indexed deployed, bytes32 indexed salt, string label);

    // ============================================================
    //                           STATE
    // ============================================================

    /// @notice Mapping from deployment salt to the deployed contract address.
    /// @dev Tracks which salts have been used and their deployed addresses.
    mapping(bytes32 salt => address deployed) public deployedContracts;

    // ============================================================
    //                         CONSTRUCTOR
    // ============================================================

    /**
     * @notice Initializes the deployer and grants admin and deployer roles.
     * @dev Initializes the deployer with `admin` as the initial admin and deployer.
     *
     * Requirements:
     *
     * - `admin` cannot be the zero address.
     *
     * @param admin The address that receives `DEFAULT_ADMIN_ROLE` and `DEPLOYER_ROLE`.
     */
    constructor(address admin) {
        if (admin == address(0)) revert InvalidAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(DEPLOYER_ROLE, admin);
    }

    // ============================================================
    //                    DEPLOYMENT FUNCTIONS
    // ============================================================

    /**
     * @notice Deploys a contract at a deterministic address derived from the salt.
     * @dev Deploys a contract at a deterministic address using CREATE3.
     *
     * The deployed address is determined solely by this contract's address and the `salt`.
     * The `initCode` (bytecode + constructor arguments) does NOT affect the address.
     *
     * Requirements:
     *
     * - The caller must have the `DEPLOYER_ROLE`.
     * - The `salt` must not have been previously used.
     *
     * Emits a {ContractDeployed} event.
     *
     * @param salt The salt for deterministic address generation.
     * @param initCode The contract creation bytecode (including constructor arguments).
     * @param label A descriptive label for the deployment (e.g., "Implementation", "Factory").
     * @return deployed The address of the deployed contract.
     */
    function deploy(
        bytes32 salt,
        bytes memory initCode,
        string calldata label
    ) external onlyRole(DEPLOYER_ROLE) returns (address deployed) {
        if (deployedContracts[salt] != address(0)) revert AlreadyDeployed();

        deployed = CREATE3.deployDeterministic(initCode, salt);

        deployedContracts[salt] = deployed;

        emit ContractDeployed(deployed, salt, label);

        return deployed;
    }

    /**
     * @notice Deploys a contract with ETH value at a deterministic address derived from the salt.
     * @dev Deploys a contract with ETH value at a deterministic address using CREATE3.
     *
     * Forwards `msg.value` to the deployed contract's constructor.
     *
     * Requirements:
     *
     * - The caller must have the `DEPLOYER_ROLE`.
     * - The `salt` must not have been previously used.
     *
     * Emits a {ContractDeployed} event.
     *
     * @param salt The salt for deterministic address generation.
     * @param initCode The contract creation bytecode (including constructor arguments).
     * @param label A descriptive label for the deployment.
     * @return deployed The address of the deployed contract.
     */
    function deployWithValue(
        bytes32 salt,
        bytes memory initCode,
        string calldata label
    ) external payable onlyRole(DEPLOYER_ROLE) returns (address deployed) {
        if (deployedContracts[salt] != address(0)) revert AlreadyDeployed();

        deployed = CREATE3.deployDeterministic(msg.value, initCode, salt);

        deployedContracts[salt] = deployed;

        emit ContractDeployed(deployed, salt, label);

        return deployed;
    }

    // ============================================================
    //                       VIEW FUNCTIONS
    // ============================================================

    /**
     * @notice Returns the predicted address for a given salt before deployment.
     * @dev Returns the predicted address of a contract before deployment.
     *
     * The address depends ONLY on this deployer's address and the `salt`. It is identical
     * across all chains where this deployer exists at the same address.
     *
     * @param salt The salt that will be used for deployment.
     * @return predicted The predicted deterministic address.
     */
    function predictAddress(bytes32 salt) external view returns (address predicted) {
        return CREATE3.predictDeterministicAddress(salt, address(this));
    }

    /**
     * @notice Checks whether a salt has already been used for deployment.
     * @dev Returns whether a `salt` has already been used for deployment.
     *
     * @param salt The salt to check.
     * @return True if the salt has been used for a deployment, false otherwise.
     */
    function isDeployed(bytes32 salt) external view returns (bool) {
        return deployedContracts[salt] != address(0);
    }

    /**
     * @notice Returns the deployed contract address for a given salt.
     * @dev Returns the deployed contract address for a given `salt`, or `address(0)` if
     * the salt has not been used.
     *
     * @param salt The salt used for deployment.
     * @return The deployed contract address, or `address(0)` if not deployed.
     */
    function getDeployed(bytes32 salt) external view returns (address) {
        return deployedContracts[salt];
    }
}
