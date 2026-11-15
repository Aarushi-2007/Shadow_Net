
const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");
const { MerkleTree } = require("merkletreejs");
const keccak256 = require("keccak256");

require("dotenv").config({
  path: path.join(__dirname, "../.env")
});

const ABI = [
  "function nodes(bytes32) view returns (bytes32 publicKeyHash, bool authorized, bool exists)",
  "function anchor(bytes32 merkleRoot, uint256 count)",
  "function getBatchCount() view returns (uint256)"
];

const batchesDir = path.join(__dirname, "batches");

function loadPreviousHistory() {
  const latestSequence = new Map();
  const usedPacketIds = new Set();

  if (!fs.existsSync(batchesDir)) {
    return { latestSequence, usedPacketIds };
  }

  const files = fs.readdirSync(batchesDir)
    .filter(file => /^batch-\d+\.json$/.test(file));

  for (const file of files) {
    const manifest = JSON.parse(
      fs.readFileSync(path.join(batchesDir, file), "utf8")
    );

    for (const packet of manifest.packets || []) {
      const previous = latestSequence.get(packet.nodeId) || 0;

      if (packet.sequence > previous) {
        latestSequence.set(packet.nodeId, packet.sequence);
      }

      usedPacketIds.add(packet.packetId);
    }
  }

  return { latestSequence, usedPacketIds };
}

async function main() {
  const { RPC_URL, GATEWAY_PRIVATE_KEY, CONTRACT_ADDRESS } = process.env;

  if (!RPC_URL || !GATEWAY_PRIVATE_KEY || !CONTRACT_ADDRESS) {
    throw new Error("Missing environment variables in .env");
  }

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(GATEWAY_PRIVATE_KEY.trim(), provider);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, wallet);

  console.log("Gateway wallet:", wallet.address);

  const packets = JSON.parse(
    fs.readFileSync(path.join(__dirname, "packets.json"), "utf8")
  );

  const registry = JSON.parse(
    fs.readFileSync(path.join(__dirname, "node-registry.json"), "utf8")
  );

  if (!packets.length) {
    throw new Error("No packets found.");
  }

  // Load sequence numbers and packet IDs from previous batches.
  const { latestSequence, usedPacketIds } = loadPreviousHistory();

  console.log("\nPrevious sequence numbers:");

  for (const [nodeId, sequence] of latestSequence) {
    console.log(`${nodeId}: ${sequence}`);
  }

  const verifiedPackets = [];
  const seenPacketIds = new Set();
  const batchSequences = new Map();

  for (const packet of packets) {
    console.log(`\nVerifying ${packet.packetId} from ${packet.nodeId}...`);

    // Check packet ID duplication within this batch.
    if (seenPacketIds.has(packet.packetId)) {
      throw new Error(`Duplicate packet ID in current batch: ${packet.packetId}`);
    }

    // Check packet ID duplication across previous batches.
    if (usedPacketIds.has(packet.packetId)) {
      throw new Error(`Replay detected: ${packet.packetId} was already submitted.`);
    }

    seenPacketIds.add(packet.packetId);

    // Validate sequence number.
    if (!Number.isSafeInteger(packet.sequence) || packet.sequence < 1) {
      throw new Error(`Invalid sequence number for ${packet.packetId}.`);
    }

    const previousSequence = Math.max(
      latestSequence.get(packet.nodeId) || 0,
      batchSequences.get(packet.nodeId) || 0
    );

    if (packet.sequence <= previousSequence) {
      throw new Error(
        `Replay detected for ${packet.nodeId}. ` +
        `Previous sequence: ${previousSequence}, ` +
        `received: ${packet.sequence}`
      );
    }

    batchSequences.set(packet.nodeId, packet.sequence);

    const node = registry.find(n => n.nodeId === packet.nodeId);

    if (!node) {
      throw new Error(`Node ${packet.nodeId} not found in registry.`);
    }

    const nodeId = ethers.encodeBytes32String(packet.nodeId);
    const packetId = ethers.encodeBytes32String(packet.packetId);

    const dataHash = ethers.keccak256(
      ethers.toUtf8Bytes(packet.data)
    );

    // Check that the node is authorized on Sepolia.
    const onChainNode = await contract.nodes(nodeId);

    if (!onChainNode.exists || !onChainNode.authorized) {
      throw new Error(`${packet.nodeId} is not authorized on-chain.`);
    }

    if (
      onChainNode.publicKeyHash.toLowerCase() !==
      node.publicKeyHash.toLowerCase()
    ) {
      throw new Error(`Public-key hash mismatch for ${packet.nodeId}.`);
    }

    // Recreate the digest signed by the sensor.
    const digest = ethers.solidityPackedKeccak256(
      ["bytes32", "bytes32", "bytes32", "uint256"],
      [nodeId, packetId, dataHash, packet.sequence]
    );

    const recoveredAddress = ethers.verifyMessage(
      ethers.getBytes(digest),
      packet.signature
    );

    const recoveredHash = ethers.keccak256(
      ethers.getBytes(recoveredAddress)
    );

    if (
      recoveredHash.toLowerCase() !==
      node.publicKeyHash.toLowerCase()
    ) {
      throw new Error(`Invalid signature for ${packet.packetId}.`);
    }

    console.log(`Signature valid. Signer: ${recoveredAddress}`);

    // Construct the Merkle leaf.
    const signatureHash = ethers.keccak256(
      ethers.getBytes(packet.signature)
    );

    const leaf = ethers.solidityPackedKeccak256(
      ["bytes32", "bytes32", "bytes32", "uint256", "bytes32"],
      [nodeId, packetId, dataHash, packet.sequence, signatureHash]
    );

    verifiedPackets.push({
      ...packet,
      nodeAddress: recoveredAddress,
      dataHash,
      leaf
    });
  }

  console.log("\nAll packet signatures and sequence numbers verified.");

  // Generate Merkle tree.
  const leaves = verifiedPackets.map(
    p => Buffer.from(p.leaf.slice(2), "hex")
  );

  const tree = new MerkleTree(leaves, keccak256, {
    sortPairs: true
  });

  const merkleRoot = tree.getHexRoot();

  console.log("\nMerkle root:", merkleRoot);
  console.log("Packet count:", verifiedPackets.length);

  const currentCount = await contract.getBatchCount();

  console.log("\nSubmitting batch to Sepolia...");

  const tx = await contract.anchor(
    merkleRoot,
    verifiedPackets.length
  );

  console.log("Transaction:", tx.hash);

  await tx.wait();

  const newCount = await contract.getBatchCount();
  const batchId = newCount - 1n;

  // Save batch manifest and proofs.
  const manifest = {
    batchId: batchId.toString(),
    merkleRoot,
    packetCount: verifiedPackets.length,
    transactionHash: tx.hash,
    packets: verifiedPackets.map(p => ({
      nodeId: p.nodeId,
      packetId: p.packetId,
      sequence: p.sequence,
      data: p.data,
      dataHash: p.dataHash,
      signature: p.signature,
      leaf: p.leaf,
      merkleProof: tree.getHexProof(
        Buffer.from(p.leaf.slice(2), "hex")
      )
    }))
  };

  fs.mkdirSync(batchesDir, { recursive: true });

  const outputPath = path.join(
    batchesDir,
    `batch-${batchId.toString()}.json`
  );

  fs.writeFileSync(
    outputPath,
    JSON.stringify(manifest, null, 2)
  );

  console.log("\nBATCH ANCHORED SUCCESSFULLY!");
  console.log("Batch ID:", batchId.toString());
  console.log("Transaction:", tx.hash);
  console.log("Saved manifest:", outputPath);
  console.log("Previous batch count:", currentCount.toString());
}

main().catch(error => {
  console.error("\nERROR:", error.shortMessage || error.message);
  process.exit(1);
});
