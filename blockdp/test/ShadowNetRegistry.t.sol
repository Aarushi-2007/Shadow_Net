// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ShadowNetRegistry.sol";

contract ShadowNetRegistryTest is Test {
    ShadowNetRegistry registry;

    address admin = address(1);
    address gateway = address(2);
    address attacker = address(3);

    bytes32 gatewayId = keccak256("GATEWAY");
    bytes32 f1Id = keccak256("F1");
    bytes32 f2Id = keccak256("F2");

    bytes32 gatewayKey = keccak256("GATEWAY_PUBLIC_KEY");
    bytes32 f1Key = keccak256("F1_PUBLIC_KEY");
    bytes32 f2Key = keccak256("F2_PUBLIC_KEY");

    function setUp() public {
        vm.prank(admin);
        registry = new ShadowNetRegistry(gatewayId);

        vm.startPrank(admin);

        registry.registerNode(gatewayId, gatewayKey, true, gateway);

        registry.registerNode(f1Id, f1Key, false, address(0));

        registry.registerNode(f2Id, f2Key, false, address(0));

        vm.stopPrank();
    }

    function testAdminIsCorrect() public view {
        assertEq(registry.admin(), admin);
    }

    function testAllNodesRegistered() public view {
        (, bool gatewayAuthorized,) = registry.nodes(gatewayId);
        (, bool f1Authorized,) = registry.nodes(f1Id);
        (, bool f2Authorized,) = registry.nodes(f2Id);

        assertTrue(gatewayAuthorized);
        assertTrue(f1Authorized);
        assertTrue(f2Authorized);
    }

    function testOnlyAdminCanRegister() public {
        vm.prank(attacker);

        vm.expectRevert("Only admin");

        registry.registerNode(keccak256("F3"), keccak256("F3_KEY"), false, address(0));
    }

    function testOnlyAdminCanRevoke() public {
        vm.prank(attacker);

        vm.expectRevert("Only admin");

        registry.revokeNode(f1Id);
    }

    function testAdminCanRevokeNode() public {
        vm.prank(admin);
        registry.revokeNode(f1Id);

        (, bool authorized,) = registry.nodes(f1Id);

        assertFalse(authorized);
    }

    function testGatewayCanAnchorBatch() public {
        bytes32 root = keccak256("MERKLE_ROOT");

        vm.prank(gateway);
        registry.anchor(root, 3);

        assertEq(registry.getBatchCount(), 1);

        (bytes32 storedRoot, uint256 storedCount, uint256 timestamp) = registry.getBatch(0);

        assertEq(storedRoot, root);
        assertEq(storedCount, 3);
        assertEq(timestamp, block.timestamp);
    }

    function testAttackerCannotAnchor() public {
        vm.prank(attacker);

        vm.expectRevert("Only authorized gateway");

        registry.anchor(keccak256("ROOT"), 3);
    }

    function testRevokedGatewayCannotAnchor() public {
        vm.prank(admin);
        registry.revokeNode(gatewayId);

        vm.prank(gateway);

        vm.expectRevert("Only authorized gateway");

        registry.anchor(keccak256("ROOT"), 3);
    }

    function testCannotRegisterDuplicateNode() public {
        vm.prank(admin);

        vm.expectRevert("Node already exists");

        registry.registerNode(f1Id, keccak256("ANOTHER_KEY"), false, address(0));
    }

    function testCannotAnchorEmptyBatch() public {
        vm.prank(gateway);

        vm.expectRevert("Empty batch");

        registry.anchor(keccak256("ROOT"), 0);
    }
}
