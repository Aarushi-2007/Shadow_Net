
const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");
require("dotenv").config({
    path: path.join(__dirname, "../.env")
});

const ABI = [
    "function getBatch(uint256) view returns (bytes32 merkleRoot, uint256 count, uint256 timestamp)"
];

async function verifyPacket(packetId) {
    const manifestPath = path.join(
        __dirname,
        "batches",
        "batch-0.json"
    );

    const manifest = JSON.parse(
        fs.readFileSync(manifestPath, "utf8")
    );

    const packet = manifest.packets.find(
        p => p.packetId === packetId
    );

    if (!packet) {
        console.log("Packet not found:", packetId);
        return;
    }

    // Connect to Sepolia
    const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);

    const contract = new ethers.Contract(
        process.env.CONTRACT_ADDRESS,
        ABI,
        provider
    );

    // Fetch the actual Merkle root from blockchain
    const batch = await contract.getBatch(manifest.batchId);

    const onChainRoot = batch[0];
    const onChainCount = batch[1];

    console.log("\nPacket:", packet.packetId);
    console.log("On-chain Merkle root:", onChainRoot);

    // Recalculate data hash
    const dataHash = ethers.keccak256(
        ethers.toUtf8Bytes(packet.data)
    );

    if (dataHash !== packet.dataHash) {
        console.log("FAILED: Packet data was modified.");
        return;
    }

    // Recalculate signature hash
    const signatureHash = ethers.keccak256(packet.signature);

    // Recalculate leaf using the same encoding as gateway
    const calculatedLeaf = ethers.solidityPackedKeccak256(
        ["bytes32", "bytes32", "bytes32", "uint256", "bytes32"],
        [
            ethers.encodeBytes32String(packet.nodeId),
            ethers.encodeBytes32String(packet.packetId),
            dataHash,
            packet.sequence,
            signatureHash
        ]
    );

    if (calculatedLeaf.toLowerCase() !== packet.leaf.toLowerCase()) {
        console.log("FAILED: Packet leaf does not match.");
        return;
    }

    // Verify Merkle proof using sorted-pair hashing
    let currentHash = calculatedLeaf;

    for (const sibling of packet.merkleProof) {
        const left = Buffer.from(currentHash.slice(2), "hex");
        const right = Buffer.from(sibling.slice(2), "hex");

        const combined = Buffer.compare(left, right) <= 0
            ? ethers.concat([currentHash, sibling])
            : ethers.concat([sibling, currentHash]);

        currentHash = ethers.keccak256(combined);
    }

    console.log("Calculated Merkle root:", currentHash);

    if (
        currentHash.toLowerCase() === onChainRoot.toLowerCase()
    ) {
        console.log("\nSUCCESS: Packet independently verified!");
        console.log("Data integrity: VALID");
        console.log("Merkle proof: VALID");
        console.log("On-chain anchoring: VERIFIED");
        console.log("Batch packet count:", onChainCount.toString());
    } else {
        console.log("\nFAILED: Merkle proof is invalid.");
    }
}

const packetId = process.argv[2];

if (!packetId) {
    console.log("Usage: node gateway/verify-packet.js P101");
    process.exit(1);
}

verifyPacket(packetId).catch(error => {
    console.error("Verification error:", error.message);
    process.exit(1);
});
