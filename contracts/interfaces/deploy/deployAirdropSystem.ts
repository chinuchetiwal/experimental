import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { ethers } from "ethers";
import * as fs from "fs";
import * as path from "path";
import { CREATE3Deployer as CREATE3DeployerContract } from "../types";
import {
  isLocalNetworkName,
  parseDefaultGasFee,
  parseMaxGasFee,
  validateGasFeeOrderingPreflight,
  validateLiveDeploymentAccessPreflight,
} from "../tasks/lib/preflight";

/**
 * Deployment script for the Confidential Airdrop system (SPECS §16, chunk 10).
 *
 * Deployment order:
 * 1. CREATE3Deployer    — singleton, CREATE2 via hardhat-deploy deterministic deployment
 * 2. ECDSAConfidentialAirdrop impl  — via CREATE3 (SALT_IMPL_ECDSA)
 * 3. MerkleConfidentialAirdrop impl — via CREATE3 (SALT_IMPL_MERKLE)
 * 4. ComplianceRoleManager impl     — via CREATE3 (SALT_COMPLIANCE_IMPL)
 * 5. AirdropFactory                 — via CREATE3 (SALT_FACTORY)
 * 6. Post-deploy compliance wiring  — setComplianceDelegate + setDefaultDelegateToCompliance(true) (D-c)
 * 7. IACL version probe             — log-only (SPECS §1.4), never branches on result
 * 8. Verification                   — assert factory getter values match deployed addresses
 * 9. Write deployments/<network>/addresses.json
 *
 * Cross-chain deployment:
 * - The SALTS are the §13.5 canonical scheme keccak256(abi.encode("tokenops-fhe-airdrop-v2","2.0.2","<Label>"))
 *   — identical on every chain, and ONE label set shared by this script and the tests (see the SALTS block).
 *   The version is "2.0.2": "2.0.0" is already consumed on Sepolia and `deployViaCreate3` returns a consumed
 *   salt's existing address without comparing codehashes, so redeploying the changed factory bytecode at
 *   "2.0.0" would silently report the OLD implementation set as success; "2.0.1" is reserved by another
 *   branch's staging deployment.
 * - The CREATE3 addresses depend ONLY on the deployer contract's address and the salt, not the bytecode.
 * - Deploy CREATE3Deployer at the same address on each chain (same deployer + same nonce, or hardhat-deploy
 *   deterministic), then run this script: all four contracts land at identical addresses cross-chain.
 *
 * Dry-run mode:
 * - Set DRY_RUN=true to simulate deployments without executing transactions.
 * - Shows gas estimates and predicted addresses; no state is written.
 *
 * Compliance wiring (D-c):
 * - COMPLIANCE_DELEGATE env var is required on live networks.
 * - On hardhat/localhost the wiring is skipped gracefully in DRY_RUN; on live networks it throws if unset.
 * - ORDER MATTERS: setComplianceDelegate must be called BEFORE setDefaultDelegateToCompliance(true)
 *   because the factory guard reverts ZeroComplianceDelegate if the default is turned ON with no
 *   delegate set.
 *
 * Live-network credential preflight (see `tasks/lib/preflight.ts`):
 * - DEFAULT_GAS_FEE and MAX_GAS_FEE are both required for every deployment (each parsed as a uint96 wei
 *   value); there is no code-level fallback for either. DEFAULT_GAS_FEE > MAX_GAS_FEE is also rejected in
 *   this preflight block, before any provider/signer use - the constructor would revert the same condition,
 *   but failing here avoids spending gas to discover it on-chain.
 * - A live deployment (sepolia/mainnet) also requires an explicit PRIVATE_KEY or non-public MNEMONIC and an
 *   RPC URL/provider key, validated before any named account, signer, or provider is resolved.
 */

// ─────────────────────────── Phase 0: preamble constants ────────────────────────────────────────

const DRY_RUN = process.env.DRY_RUN === "true";

// Canonical §13.5 salt scheme (time-free). ONE canonical label set used by BOTH the deploy script and the
// tests — this fixes the v1/vesting-v2 `.audited`-vs-`.v1` mismatch where tests and prod computed DIFFERENT
// CREATE3 addresses. The salts are keccak256(abi.encode(project, version, contractLabel)); the compliance
// label is `ComplianceRoleManagerImpl` (D7: the singleton is the manager IMPLEMENTATION; per-instance clones
// use the factory's CREATE2 managerSalt derivation, never this CREATE3 label). SPECS §13.5.
const SALT_PROJECT = "tokenops-fhe-airdrop-v2";
const SALT_VERSION = "2.0.2";

/** Derive a §13.5 canonical singleton salt: keccak256(abi.encode(project, version, contractLabel)). */
function canonicalSalt(contractLabel: string): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["string", "string", "string"],
      [SALT_PROJECT, SALT_VERSION, contractLabel],
    ),
  );
}

// Exported so the WP-09 parity test and any other tool share ONE definition and cannot drift again (§13.5).
export const SALTS = {
  IMPL_ECDSA: canonicalSalt("ECDSAConfidentialAirdrop"),
  IMPL_MERKLE: canonicalSalt("MerkleConfidentialAirdrop"),
  IMPL_COMPLIANCE: canonicalSalt("ComplianceRoleManagerImpl"),
  FACTORY: canonicalSalt("AirdropFactory"),
} as const;

// Gas estimate table (populated in DRY_RUN mode).
interface GasEstimate {
  step: string;
  gas: bigint;
}
const gasEstimates: GasEstimate[] = [];

/** Format a gas bigint with comma separators for readability. */
function formatGas(gas: bigint): string {
  return gas.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Pre-flight compliance-delegate validation (D-c). Runs BEFORE any phase and BEFORE any dry-run shortcut,
 * so a DRY_RUN against a live network fails on exactly the misconfigurations the real run would hit (a dry
 * run that prints a full success plan and then the real run aborts at Phase 6 is worse than useless).
 * Local networks skip the requirement (the wiring phase skips gracefully there). Exported so the
 * regression tests can drive the live-network arms directly — same logic, not a fork.
 */
export function validateComplianceDelegatePreflight(networkName: string, complianceDelegate: string | undefined): void {
  if (isLocalNetworkName(networkName)) return;
  if (!complianceDelegate) {
    throw new Error(
      "COMPLIANCE_DELEGATE env var is required for live-network deployment (D-c compliance wiring). " +
        "Set it to the platform compliance delegate address and re-run (applies to DRY_RUN too).",
    );
  }
  if (!ethers.isAddress(complianceDelegate) || complianceDelegate === ethers.ZeroAddress) {
    throw new Error(`COMPLIANCE_DELEGATE is not a valid non-zero address: ${complianceDelegate}`);
  }
}

// ─────────────────────────────────────── deploy function ────────────────────────────────────────

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const networkName = hre.network.name;
  const COMPLIANCE_DELEGATE = process.env.COMPLIANCE_DELEGATE;
  const DEFAULT_GAS_FEE = parseDefaultGasFee(process.env.DEFAULT_GAS_FEE);
  const MAX_GAS_FEE = parseMaxGasFee(process.env.MAX_GAS_FEE);

  // Validate the environment before touching any named account, signer, or provider: no live deployment may
  // fall through to test credentials, an implicit fee, or an unbounded default silently exceeding the
  // maximum the deployer just stated.
  validateComplianceDelegatePreflight(networkName, COMPLIANCE_DELEGATE);
  validateLiveDeploymentAccessPreflight(networkName, process.env);
  validateGasFeeOrderingPreflight(DEFAULT_GAS_FEE, MAX_GAS_FEE);

  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;
  const signer = await hre.ethers.getSigner(deployer);
  const network = await hre.ethers.provider.getNetwork();
  const isLocalNetwork = isLocalNetworkName(networkName);

  // ── Phase 0: preamble ───────────────────────────────────────────────────────────────────────

  if (DRY_RUN) {
    console.log("\n╔═══════════════════════════════════════════════════════════╗");
    console.log("║      [DRY RUN] Airdrop System Deployment Simulation       ║");
    console.log("╚═══════════════════════════════════════════════════════════╝");
  } else {
    console.log("\n=== Confidential Airdrop System Deployment ===");
  }
  console.log(`Deployer:        ${deployer}`);
  console.log(`Network:         ${hre.network.name} (chainId: ${network.chainId})`);
  console.log(`Default Gas Fee: ${ethers.formatEther(DEFAULT_GAS_FEE)} ETH`);
  console.log(`Max Gas Fee:     ${ethers.formatEther(MAX_GAS_FEE)} ETH`);
  if (COMPLIANCE_DELEGATE) {
    console.log(`Compliance Delegate: ${COMPLIANCE_DELEGATE}`);
  } else {
    console.log(`Compliance Delegate: <NOT SET> (COMPLIANCE_DELEGATE env var)`);
  }

  // ── Phase 1: CREATE3Deployer via hardhat-deploy deterministic deployment ────────────────────

  console.log(`\n--- Phase 1: CREATE3Deployer ${DRY_RUN ? "[DRY RUN]" : ""} ---`);

  let create3DeployerAddress: string;

  if (DRY_RUN) {
    const CREATE3DeployerFactory = await hre.ethers.getContractFactory("CREATE3Deployer");
    const deployTx = await CREATE3DeployerFactory.getDeployTransaction(deployer);
    const gasEstimate = await hre.ethers.provider.estimateGas({
      from: deployer,
      data: deployTx.data,
    });
    gasEstimates.push({ step: "Deploy CREATE3Deployer", gas: gasEstimate });
    console.log(`  [DRY RUN] Gas estimate: ${formatGas(gasEstimate)}`);

    const existingDeployment = await hre.deployments.getOrNull("CREATE3Deployer");
    if (existingDeployment) {
      create3DeployerAddress = existingDeployment.address;
      console.log(`  [DRY RUN] Would reuse existing deployment at: ${create3DeployerAddress}`);
    } else {
      create3DeployerAddress = "0x" + "0".repeat(40);
      console.log(`  [DRY RUN] Would deploy CREATE3Deployer (hardhat-deploy deterministic)`);
    }
  } else {
    const create3DeployerResult = await deploy("CREATE3Deployer", {
      from: deployer,
      args: [deployer],
      log: true,
      deterministicDeployment: true, // CREATE2 for deterministic address (A18)
    });
    create3DeployerAddress = create3DeployerResult.address;
    console.log(`CREATE3Deployer: ${create3DeployerAddress}`);
  }

  // Obtain a live contract handle (skip in DRY_RUN if the deployer isn't yet on-chain).
  let create3Contract: CREATE3DeployerContract | null = null;
  const existingCreate3Deployment = await hre.deployments.getOrNull("CREATE3Deployer");

  if (existingCreate3Deployment || !DRY_RUN) {
    create3Contract = await hre.ethers.getContractAt(
      "CREATE3Deployer",
      existingCreate3Deployment?.address || create3DeployerAddress,
      signer,
    );
  }

  // ─────────── helper: idempotent CREATE3 deploy for a single contract ────────────────────────

  /**
   * Deploy (or reuse) one contract via CREATE3.
   *
   * @param salt          Canonical salt (keccak256 of label string).
   * @param initCode      Full init bytecode including constructor arguments.
   * @param label         Human-readable label used in logs and the ContractDeployed event.
   * @returns             The deployed address (predicted in DRY_RUN, actual otherwise).
   */
  async function deployViaCreate3(salt: string, initCode: string, label: string): Promise<string> {
    let predicted: string | null = null;
    let alreadyDeployed = false;

    if (create3Contract) {
      predicted = await create3Contract.predictAddress(salt);
      alreadyDeployed = await create3Contract.isDeployed(salt);
    }

    if (alreadyDeployed && create3Contract) {
      const addr = await create3Contract.getDeployed(salt);
      console.log(`${label} already deployed at: ${addr}`);
      return addr;
    }

    if (DRY_RUN) {
      if (create3Contract) {
        const gas = await create3Contract.deploy.estimateGas(salt, initCode, label);
        gasEstimates.push({ step: `Deploy ${label} via CREATE3`, gas });
        console.log(`  [DRY RUN] ${label}: predicted=${predicted}, gas=${formatGas(gas)}`);
      } else {
        // No CREATE3 layer on-chain yet (fresh network). A raw estimateGas of the init code reverts for a
        // contract whose constructor validates dependency addresses that are not yet available in this
        // simulation (e.g. the factory's ZeroImplementation guard, since the impls were not deployed in
        // DRY_RUN). Degrade gracefully so the dry-run still completes end-to-end; on a real network the
        // shared CREATE3 layer already exists and every phase estimates against real predicted addresses.
        try {
          const gas = await hre.ethers.provider.estimateGas({ from: deployer, data: initCode });
          gasEstimates.push({ step: `Deploy ${label} (estimated)`, gas });
          console.log(`  [DRY RUN] ${label}: gas=${formatGas(gas)} (CREATE3Deployer not yet on-chain)`);
        } catch {
          console.log(
            `  [DRY RUN] ${label}: gas estimate unavailable (depends on the not-yet-deployed CREATE3 layer / impls)`,
          );
        }
      }
      return predicted ?? "0x" + "0".repeat(40);
    }

    // Live deployment.
    console.log(`Deploying ${label}… (predicted: ${predicted})`);
    const tx = await create3Contract!.deploy(salt, initCode, label);
    await tx.wait();

    const addr = await create3Contract!.getDeployed(salt);
    console.log(`${label} deployed at: ${addr}`);

    if (addr.toLowerCase() !== predicted!.toLowerCase()) {
      throw new Error(`${label} address mismatch: got ${addr}, expected ${predicted}`);
    }
    return addr;
  }

  // ── Phase 2: ECDSAConfidentialAirdrop implementation ────────────────────────────────────────

  console.log(`\n--- Phase 2: ECDSAConfidentialAirdrop impl ${DRY_RUN ? "[DRY RUN]" : ""} ---`);

  const ECDSAFactory = await hre.ethers.getContractFactory("ECDSAConfidentialAirdrop");
  const ecdsaInitCode = ECDSAFactory.bytecode; // constructor calls _disableInitializers — no args

  const ecdsaImplAddress = await deployViaCreate3(SALTS.IMPL_ECDSA, ecdsaInitCode, "ECDSAConfidentialAirdrop impl");

  // ── Phase 3: MerkleConfidentialAirdrop implementation ───────────────────────────────────────

  console.log(`\n--- Phase 3: MerkleConfidentialAirdrop impl ${DRY_RUN ? "[DRY RUN]" : ""} ---`);

  const MerkleFactory = await hre.ethers.getContractFactory("MerkleConfidentialAirdrop");
  const merkleInitCode = MerkleFactory.bytecode; // constructor calls _disableInitializers — no args

  const merkleImplAddress = await deployViaCreate3(SALTS.IMPL_MERKLE, merkleInitCode, "MerkleConfidentialAirdrop impl");

  // ── Phase 4: ComplianceRoleManager implementation ───────────────────────────────────────────

  console.log(`\n--- Phase 4: ComplianceRoleManager impl ${DRY_RUN ? "[DRY RUN]" : ""} ---`);

  const ComplianceFactory = await hre.ethers.getContractFactory("ComplianceRoleManager");
  const complianceInitCode = ComplianceFactory.bytecode; // constructor calls _disableInitializers — no args

  const complianceImplAddress = await deployViaCreate3(
    SALTS.IMPL_COMPLIANCE,
    complianceInitCode,
    "ComplianceRoleManager impl",
  );

  // ── Phase 5: AirdropFactory ──────────────────────────────────────────────────────────────────

  console.log(`\n--- Phase 5: AirdropFactory ${DRY_RUN ? "[DRY RUN]" : ""} ---`);

  // Constructor arg order:
  //   roles (FactoryRoles), ecdsaImplementation_, merkleImplementation_, complianceManagerImpl_,
  //   feeCollector_, defaultGasFee_, maxGasFee_
  // roles.admin receives DEFAULT_ADMIN_ROLE; every other role field defaults to admin when left zero.
  const AirdropFactoryContractFactory = await hre.ethers.getContractFactory("AirdropFactory");
  const factoryRoles = {
    admin: deployer,
    feeManager: ethers.ZeroAddress,
    implManager: ethers.ZeroAddress,
    complianceWiring: ethers.ZeroAddress,
    upgradeManager: ethers.ZeroAddress,
  };
  const factoryDeployTx = await AirdropFactoryContractFactory.getDeployTransaction(
    factoryRoles,
    ecdsaImplAddress,
    merkleImplAddress,
    complianceImplAddress,
    deployer, // feeCollector_ — seeded into every new instance; can be changed later via FEE_MANAGER_ROLE
    DEFAULT_GAS_FEE,
    MAX_GAS_FEE,
  );

  if (!factoryDeployTx.data) {
    throw new Error("Failed to generate AirdropFactory init code");
  }

  const factoryAddress = await deployViaCreate3(SALTS.FACTORY, factoryDeployTx.data, "AirdropFactory");

  // ── Phase 6: Post-deploy compliance wiring (D-c, MANDATORY) ────────────────────────────────

  console.log(`\n--- Phase 6: Compliance wiring (D-c) ${DRY_RUN ? "[DRY RUN]" : ""} ---`);

  // ORDER MATTERS: the factory guard ZeroComplianceDelegate reverts if setDefaultDelegateToCompliance(true)
  // is called while complianceDelegate == address(0). Always call the delegate setter FIRST.
  if (!DRY_RUN && COMPLIANCE_DELEGATE) {
    const Factory = await hre.ethers.getContractAt("AirdropFactory", factoryAddress, signer);

    const tx1 = await Factory.setComplianceDelegate(COMPLIANCE_DELEGATE);
    await tx1.wait();
    console.log(`setComplianceDelegate(${COMPLIANCE_DELEGATE}) tx: ${tx1.hash}`);

    const tx2 = await Factory.setDefaultDelegateToCompliance(true);
    await tx2.wait();
    console.log(`setDefaultDelegateToCompliance(true) tx: ${tx2.hash}`);
  } else if (DRY_RUN) {
    console.log(`  [DRY RUN] Would call setComplianceDelegate(${COMPLIANCE_DELEGATE ?? "<NOT SET>"})`);
    console.log(`  [DRY RUN] Would call setDefaultDelegateToCompliance(true)`);
  } else if (!isLocalNetwork && !COMPLIANCE_DELEGATE) {
    // Live network, no DRY_RUN, no delegate set — this is a misconfiguration.
    throw new Error(
      "COMPLIANCE_DELEGATE env var is required for live deployment (D-c). " +
        "Set it to the platform compliance delegate address and re-run.",
    );
  } else {
    // Local/hardhat network, no delegate set — skip gracefully.
    console.log(`  COMPLIANCE_DELEGATE not set — skipping compliance wiring (local network).`);
  }

  // ── Phase 7: IACL version probe (SPECS §1.4) — LOG ONLY, never branches on result ───────────

  console.log(`\n--- Phase 7: IACL version probe ---`);

  if (!DRY_RUN) {
    try {
      // The ACL address is network-specific; ZamaConfig.getEthereumCoprocessorConfig().ACLAddress
      // is the canonical source. We fetch it via a minimal ABI — getVersion() is a pure view.
      const aclAbi = ["function getVersion() external pure returns (string memory)"];
      // Resolve the ACL address best-effort from the hardhat-fhevm plugin; if the network does not expose
      // the ACL or the call reverts, we log and continue (log-only, never branches on the result — SPECS §1.4).
      // We intentionally do not import ZamaConfig here (avoid optional dep) — the try/catch handles any failure.
      const aclAddress: string | undefined = (hre as HardhatRuntimeEnvironment & { fhevm?: { aclAddress?: string } })
        .fhevm?.aclAddress;
      if (aclAddress) {
        const acl = new hre.ethers.Contract(aclAddress, aclAbi, signer);
        const ver = await acl.getVersion();
        console.log(`ACL fhevm version: ${ver}`);
      } else {
        console.log(`ACL version probe: ACL address not available in this environment — skipping.`);
      }
    } catch (e) {
      // Log-only — never block deployment (SPECS §1.4).
      console.log(`ACL version probe failed (non-fatal): ${(e as Error).message ?? e}`);
    }
  } else {
    console.log(`  [DRY RUN] Would probe IACL.getVersion() (log-only, SPECS §1.4)`);
  }

  // ── Phase 8: Verification ────────────────────────────────────────────────────────────────────

  if (!DRY_RUN) {
    console.log("\n--- Phase 8: Verification ---");

    const Factory = await hre.ethers.getContractAt("AirdropFactory", factoryAddress, signer);

    const gotEcdsa = await Factory.ecdsaImplementation();
    const gotMerkle = await Factory.merkleImplementation();
    const gotCompliance = await Factory.complianceManagerImpl();
    const gotComplianceDelegate = await Factory.complianceDelegate();

    console.log(`factory.ecdsaImplementation():  ${gotEcdsa}`);
    console.log(`factory.merkleImplementation():  ${gotMerkle}`);
    console.log(`factory.complianceManagerImpl(): ${gotCompliance}`);
    console.log(`factory.complianceDelegate(): ${gotComplianceDelegate}`);

    if (gotEcdsa.toLowerCase() !== ecdsaImplAddress.toLowerCase()) {
      throw new Error(`ecdsaImplementation mismatch: got ${gotEcdsa}, expected ${ecdsaImplAddress}`);
    }
    if (gotMerkle.toLowerCase() !== merkleImplAddress.toLowerCase()) {
      throw new Error(`merkleImplementation mismatch: got ${gotMerkle}, expected ${merkleImplAddress}`);
    }
    if (gotCompliance.toLowerCase() !== complianceImplAddress.toLowerCase()) {
      throw new Error(`complianceManagerImpl mismatch: got ${gotCompliance}, expected ${complianceImplAddress}`);
    }

    // Verify compliance wiring only when the delegate was configured.
    if (COMPLIANCE_DELEGATE) {
      const gotDelegateOn = await Factory.effectiveDelegateToCompliance(deployer);
      if (!gotDelegateOn) {
        throw new Error(
          "effectiveDelegateToCompliance(deployer) should be true after setDefaultDelegateToCompliance(true)",
        );
      }
      if (gotComplianceDelegate.toLowerCase() !== COMPLIANCE_DELEGATE.toLowerCase()) {
        throw new Error(`complianceDelegate mismatch: got ${gotComplianceDelegate}, expected ${COMPLIANCE_DELEGATE}`);
      }
      console.log(`Compliance wiring verified: delegate=${gotComplianceDelegate}, defaultDelegateToCompliance=true`);
    }

    console.log("All verification checks passed.");

    // ── Phase 9: Write addresses.json ──────────────────────────────────────────────────────────

    console.log("\n--- Phase 9: Writing addresses.json ---");

    const deploymentsDir = path.join(__dirname, "..", "deployments", hre.network.name);
    if (!fs.existsSync(deploymentsDir)) {
      fs.mkdirSync(deploymentsDir, { recursive: true });
    }

    const addressesPath = path.join(deploymentsDir, "addresses.json");
    const addresses = {
      create3Deployer: create3DeployerAddress,
      ecdsaImpl: ecdsaImplAddress,
      merkleImpl: merkleImplAddress,
      complianceImpl: complianceImplAddress,
      factory: factoryAddress,
      deployer: deployer,
      defaultGasFee: DEFAULT_GAS_FEE.toString(),
      complianceDelegate: COMPLIANCE_DELEGATE ?? null,
      network: hre.network.name,
      chainId: network.chainId.toString(),
      salts: {
        IMPL_ECDSA: SALTS.IMPL_ECDSA,
        IMPL_MERKLE: SALTS.IMPL_MERKLE,
        IMPL_COMPLIANCE: SALTS.IMPL_COMPLIANCE,
        FACTORY: SALTS.FACTORY,
      },
    };
    fs.writeFileSync(addressesPath, JSON.stringify(addresses, null, 2));
    console.log(`Addresses written to: ${addressesPath}`);
  }

  // ── Phase 10: Summary ────────────────────────────────────────────────────────────────────────

  if (DRY_RUN) {
    const totalGas = gasEstimates.reduce((sum, e) => sum + e.gas, 0n);
    const feeData = await hre.ethers.provider.getFeeData();
    const gasPrice = feeData.gasPrice ?? ethers.parseUnits("30", "gwei");

    console.log("\n╔═══════════════════════════════════════════════════════════╗");
    console.log("║           [DRY RUN] Simulation Summary                    ║");
    console.log("╚═══════════════════════════════════════════════════════════╝");

    console.log("\nGas Estimates by Step:");
    console.log("─".repeat(60));
    for (const estimate of gasEstimates) {
      console.log(`  ${estimate.step.padEnd(44)} ${formatGas(estimate.gas).padStart(13)}`);
    }
    console.log("─".repeat(60));
    console.log(`  ${"TOTAL".padEnd(44)} ${formatGas(totalGas).padStart(13)}`);

    const estimatedCost = totalGas * gasPrice;
    console.log(
      `\nEstimated Cost at ${ethers.formatUnits(gasPrice, "gwei")} gwei: ${ethers.formatEther(estimatedCost)} ETH`,
    );

    console.log("\nPredicted Addresses:");
    console.log(`  CREATE3Deployer:              ${create3DeployerAddress}`);
    console.log(`  ECDSAConfidentialAirdrop impl: ${ecdsaImplAddress}`);
    console.log(`  MerkleConfidentialAirdrop impl:${merkleImplAddress}`);
    console.log(`  ComplianceRoleManager impl:    ${complianceImplAddress}`);
    console.log(`  AirdropFactory:                ${factoryAddress}`);

    console.log("\nConfiguration:");
    console.log(`  Admin / Fee Collector (initial): ${deployer}`);
    console.log(`  Default Gas Fee:                 ${ethers.formatEther(DEFAULT_GAS_FEE)} ETH`);
    console.log(`  Compliance Delegate:             ${COMPLIANCE_DELEGATE ?? "<NOT SET>"}`);

    console.log("\nSalts:");
    console.log(`  IMPL_ECDSA:      ${SALTS.IMPL_ECDSA}`);
    console.log(`  IMPL_MERKLE:     ${SALTS.IMPL_MERKLE}`);
    console.log(`  IMPL_COMPLIANCE: ${SALTS.IMPL_COMPLIANCE}`);
    console.log(`  FACTORY:         ${SALTS.FACTORY}`);

    console.log("\n  No transactions were executed. Run without DRY_RUN=true to deploy.");
  } else {
    console.log("\n=== Deployment Summary ===");
    console.log(`CREATE3Deployer:               ${create3DeployerAddress}`);
    console.log(`ECDSAConfidentialAirdrop impl:  ${ecdsaImplAddress}`);
    console.log(`MerkleConfidentialAirdrop impl: ${merkleImplAddress}`);
    console.log(`ComplianceRoleManager impl:     ${complianceImplAddress}`);
    console.log(`AirdropFactory:                 ${factoryAddress}`);
    console.log(`Admin / Fee Collector (initial):${deployer}`);
    console.log(`Default Gas Fee:                ${ethers.formatEther(DEFAULT_GAS_FEE)} ETH`);

    console.log("\n=== Salts Used ===");
    console.log(`IMPL_ECDSA:      ${SALTS.IMPL_ECDSA}`);
    console.log(`IMPL_MERKLE:     ${SALTS.IMPL_MERKLE}`);
    console.log(`IMPL_COMPLIANCE: ${SALTS.IMPL_COMPLIANCE}`);
    console.log(`FACTORY:         ${SALTS.FACTORY}`);

    console.log("\n=== Cross-Chain Deployment ===");
    console.log("To deploy at the same addresses on another chain:");
    console.log("1. Deploy CREATE3Deployer at the same address (same deployer nonce or hardhat-deploy deterministic)");
    console.log("2. Use the same salts shown above");
    console.log("3. ECDSAConfidentialAirdrop, MerkleConfidentialAirdrop, ComplianceRoleManager and AirdropFactory");
    console.log("   will be at the same addresses on every chain");
  }
};

export default func;
func.id = "deploy_airdrop_system";
func.tags = [
  "AirdropSystem",
  "CREATE3Deployer",
  "ECDSAConfidentialAirdrop",
  "MerkleConfidentialAirdrop",
  "ComplianceRoleManager",
  "AirdropFactory",
];
