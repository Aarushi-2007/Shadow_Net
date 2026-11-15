
const fs = require("fs");
const path = require("path");

const {
    Wallet,
    encodeBytes32String,
    keccak256,
    toUtf8Bytes,
    solidityPackedKeccak256,
    getBytes
} = require("ethers");

// New packets from the EXISTING registered nodes
const nodes = [
    {
        nodeId: "N1",
        packetId: "P102",
        sequence: 2,
        data: "Temperature=29;Status=normal"
    },
    {
        nodeId: "N2",
        packetId: "P202",
        sequence: 2,
        data: "Temperature=31;Status=normal"
    },
    {
        nodeId: "N3",
        packetId: "P302",
        sequence: 2,
        data: "Temperature=28;Status=normal"
    }
];

async function generatePackets() {
    const registryPath = path.join(__dirname, "node-registry.json");

    // Load the original registered sensor wallets.
    const nodeRegistry = JSON.parse(
        fs.readFileSync(registryPath, "utf8")
    );

    const packets = [];

    for (const node of nodes) {
        const registeredNode = nodeRegistry.find(
            n => n.nodeId === node.nodeId
        );

        if (!registeredNode) {
            throw new Error(`Registered wallet not found for ${node.nodeId}`);
        }

        // Reuse the original private key.
        const wallet = new Wallet(registeredNode.privateKey);

        if (
            wallet.address.toLowerCase() !==
            registeredNode.address.toLowerCase()
        ) {
            throw new Error(`Wallet mismatch for ${node.nodeId}`);
        }

        const nodeId = encodeBytes32String(node.nodeId);
        const packetId = encodeBytes32String(node.packetId);

        const dataHash = keccak256(
            toUtf8Bytes(node.data)
        );

        // Same signing format as before.
        const digest = solidityPackedKeccak256(
            ["bytes32", "bytes32", "bytes32", "uint256"],
            [nodeId, packetId, dataHash, node.sequence]
        );

        const signature = await wallet.signMessage(
            getBytes(digest)
        );

        packets.push({
            nodeId: node.nodeId,
            packetId: node.packetId,
            sequence: node.sequence,
            data: node.data,
            signature
        });

        console.log(`Generated: ${node.packetId}`);
        console.log(`Node: ${node.nodeId}`);
        console.log(`Existing wallet: ${wallet.address}`);
        console.log(`Sequence: ${node.sequence}\n`);
    }

    // Update ONLY packets.json.
    // Never overwrite the original node registry.
    fs.writeFileSync(
        path.join(__dirname, "packets.json"),
        JSON.stringify(packets, null, 2)
    );

    console.log("New signed packets saved successfully.");
    console.log("Original node registry preserved.");
}

generatePackets().catch(error => {
    console.error("ERROR:", error.message);
    process.exit(1);
});
