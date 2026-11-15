const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "../.env") });

const ABI = [
  "function admin() view returns (address)",
  "function registerNode(bytes32 nodeId, bytes32 publicKeyHash, bool isGateway, address nodeAddress)",
  "function nodes(bytes32) view returns (bytes32 publicKeyHash, bool authorized, bool exists)"
];

async function main() {
  const { RPC_URL, GATEWAY_PRIVATE_KEY, CONTRACT_ADDRESS } = process.env;

  if (!RPC_URL || !GATEWAY_PRIVATE_KEY || !CONTRACT_ADDRESS) {
    throw new Error("Missing RPC_URL, GATEWAY_PRIVATE_KEY or CONTRACT_ADDRESS in .env");
  }

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(GATEWAY_PRIVATE_KEY.trim(), provider);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, wallet);

  const admin = await contract.admin();

  if (admin.toLowerCase() !== wallet.address.toLowerCase()) {
    throw new Error("Your wallet is not the contract admin.");
  }

  console.log("Admin wallet:", wallet.address);

  async function register(nodeId, publicKeyHash, isGateway, nodeAddress) {
    const id = ethers.encodeBytes32String(nodeId);
    const existing = await contract.nodes(id);

    if (existing.exists) {
      if (
        existing.authorized &&
        existing.publicKeyHash.toLowerCase() === publicKeyHash.toLowerCase()
      ) {
        console.log(`${nodeId} already registered and authorized. Skipping.`);
        return;
      }
      throw new Error(`${nodeId} already exists but is not correctly authorized. Check contract state.`);
    }

    console.log(`Registering ${nodeId}...`);

    const tx = await contract.registerNode(
      id,
      publicKeyHash,
      isGateway,
      nodeAddress
    );

    console.log("Transaction:", tx.hash);
    await tx.wait();
    console.log(`${nodeId} registered successfully.`);
  }

  // Register the gateway wallet
  const gatewayHash = ethers.keccak256(ethers.getBytes(wallet.address));

  await register(
    "GATEWAY",
    gatewayHash,
    true,
    wallet.address
  );

  // Read sensor-node information locally
  const registry = JSON.parse(
    fs.readFileSync(path.join(__dirname, "node-registry.json"), "utf8")
  );

  // Register N1, N2 and N3
  for (const node of registry) {
    await register(
      node.nodeId,
      node.publicKeyHash,
      false,
      ethers.ZeroAddress
    );
  }

  console.log("\nChecking registrations...");

  const allNodes = ["GATEWAY", ...registry.map(n => n.nodeId)];

  for (const name of allNodes) {
    const id = ethers.encodeBytes32String(name);
    const node = await contract.nodes(id);

    console.log(
      `${name}:`,
      node.authorized ? "AUTHORIZED" : "NOT AUTHORIZED"
    );
  }

  console.log("\nRegistration process completed.");
}

main().catch(error => {
  console.error("ERROR:", error.shortMessage || error.message);
  process.exit(1);
});
