// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ShadowNetRegistry {
    address public immutable admin;
    bytes32 public gatewayNodeId;

    address private gatewayAddress;

    struct Node {
        bytes32 publicKeyHash;
        bool authorized;
        bool exists;
    }

    struct Batch {
        bytes32 merkleRoot;
        uint256 count;
        uint256 timestamp;
    }

    mapping(bytes32 => Node) public nodes;

    Batch[] public batches;

    event NodeRegistered(bytes32 indexed nodeId, bytes32 publicKeyHash);

    event NodeRevoked(bytes32 indexed nodeId);
    event GatewayRegistered(
    bytes32 indexed nodeId,
    address indexed gatewayAddress
);

    // Existing event retained
    event BatchAnchored(uint256 indexed batchId, bytes32 merkleRoot, uint256 count, uint256 timestamp);

    // Additional audit event
    event BatchAnchoredByGateway(
        uint256 indexed batchId, address indexed gateway, bytes32 indexed gatewayNodeId, bytes32 merkleRoot
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor(bytes32 _gatewayNodeId) {
        require(_gatewayNodeId != bytes32(0), "Invalid gateway ID");

        admin = msg.sender;
        gatewayNodeId = _gatewayNodeId;
    }

    function registerNode(bytes32 nodeId, bytes32 publicKeyHash, bool isGateway, address nodeAddress)
        external
        onlyAdmin
    {
        require(nodeId != bytes32(0), "Invalid node ID");
        require(publicKeyHash != bytes32(0), "Invalid key hash");
        require(!nodes[nodeId].exists, "Node already exists");

        if (isGateway) {
            require(nodeId == gatewayNodeId, "Wrong gateway ID");
            require(nodeAddress != address(0), "Invalid gateway address");
            require(gatewayAddress == address(0), "Gateway already set");

            gatewayAddress = nodeAddress;
            emit GatewayRegistered(nodeId, nodeAddress);
        }

        nodes[nodeId] = Node({publicKeyHash: publicKeyHash, authorized: true, exists: true});

        emit NodeRegistered(nodeId, publicKeyHash);
    }

    function revokeNode(bytes32 nodeId) external onlyAdmin {
        require(nodes[nodeId].exists, "Node does not exist");
        require(nodes[nodeId].authorized, "Already revoked");

        nodes[nodeId].authorized = false;

        emit NodeRevoked(nodeId);
    }

    function anchor(bytes32 merkleRoot, uint256 count) external {
        require(nodes[gatewayNodeId].authorized && msg.sender == gatewayAddress, "Only authorized gateway");

        require(merkleRoot != bytes32(0), "Invalid Merkle root");
        require(count > 0, "Empty batch");

        uint256 batchId = batches.length;

        batches.push(Batch({merkleRoot: merkleRoot, count: count, timestamp: block.timestamp}));

        emit BatchAnchored(batchId, merkleRoot, count, block.timestamp);

        emit BatchAnchoredByGateway(batchId, msg.sender, gatewayNodeId, merkleRoot);
    }

    function getBatchCount() external view returns (uint256) {
        return batches.length;
    }

    function getBatch(uint256 batchId) external view returns (bytes32, uint256, uint256) {
        require(batchId < batches.length, "Invalid batch ID");

        Batch memory batch = batches[batchId];

        return (batch.merkleRoot, batch.count, batch.timestamp);
    }

    function getGatewayAddress() external view returns (address) {
        return gatewayAddress;
    }

    function getNodeDetails(bytes32 nodeId) external view returns (bytes32, bool, bool) {
        Node memory node = nodes[nodeId];

        return (node.publicKeyHash, node.authorized, node.exists);
    }
}
