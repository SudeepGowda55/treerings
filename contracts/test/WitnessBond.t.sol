// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {WitnessBond} from "../src/WitnessBond.sol";

/// Stands in for QoreChain's pqcVerify precompile, which Foundry's EVM does not have. It accepts exactly the
/// (pubkey, signature, message) triples a test approves; the real precompile is checked live by
/// scripts/probe-pqcverify.mjs.
contract MockPQC {
    mapping(bytes32 => bool) public ok;

    function approve(bytes calldata pubkey, bytes calldata signature, bytes calldata message) external {
        ok[keccak256(abi.encode(pubkey, signature, message))] = true;
    }

    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message) external view returns (bool) {
        return ok[keccak256(abi.encode(pubkey, signature, message))];
    }
}

contract WitnessBondTest is Test {
    WitnessBond bond;
    MockPQC pqc;
    bytes pubkey = new bytes(2592);
    string constant NAME = "treerings.witness/1";
    string constant ORIGIN = "ct.cloudflare.com/logs/nimbus2026";
    address witnessOwner = address(0xA11CE);
    address reporter = address(0xB0B);

    function setUp() public {
        vm.etch(address(0x0a01), type(MockPQC).runtimeCode);
        pqc = MockPQC(address(0x0a01));
        bond = new WitnessBond(1 ether, 7 days);
        pubkey[0] = 0x42;
        vm.deal(witnessOwner, 10 ether);
        vm.prank(witnessOwner);
        bond.register{value: 2 ether}(NAME, pubkey);
    }

    function cosig(uint64 ts, uint64 size, bytes32 root, string memory sigSeed) internal returns (WitnessBond.Cosig memory c) {
        c = WitnessBond.Cosig(ts, size, root, bytes(sigSeed));
        pqc.approve(pubkey, c.signature, bond.cosignedSubtree(NAME, ts, ORIGIN, size, root));
    }

    // Merkle helpers (RFC 9162)
    function leaf(uint256 i) internal pure returns (bytes32) { return sha256(abi.encodePacked(bytes1(0x00), "entry ", i)); }
    function node(bytes32 l, bytes32 r) internal pure returns (bytes32) { return sha256(abi.encodePacked(bytes1(0x01), l, r)); }

    function test_messageMatchesTheJsCosignerByteForByte() public view {
        bytes memory expected = hex"737562747265652f76310a00137472656572696e67732e7769746e6573732f31000000006b06ae802163742e636c6f7564666c6172652e636f6d2f6c6f67732f6e696d6275733230323600000000000000000000000196fdb376abababababababababababababababababababababababababababababababab";
        bytes32 root = 0xabababababababababababababababababababababababababababababababab;
        assertEq(bond.cosignedSubtree(NAME, 1795600000, ORIGIN, 6828176246, root), expected);
    }

    function test_splitViewTakesTheBond() public {
        WitnessBond.Cosig memory a = cosig(100, 50, keccak256("root A"), "sig a");
        WitnessBond.Cosig memory b = cosig(101, 50, keccak256("root B"), "sig b");
        vm.prank(reporter);
        bond.slashSplitView(NAME, ORIGIN, a, b);
        assertEq(reporter.balance, 2 ether);
        (,, uint256 left,) = bond.witness(NAME);
        assertEq(left, 0);
    }

    function test_twoSignaturesOfTheSameHeadAreNotEvidence() public {
        WitnessBond.Cosig memory a = cosig(100, 50, keccak256("root A"), "sig a");
        WitnessBond.Cosig memory b = cosig(200, 50, keccak256("root A"), "sig b");
        vm.expectRevert(WitnessBond.NotEvidence.selector);
        bond.slashSplitView(NAME, ORIGIN, a, b);
    }

    function test_aForgedCosignatureIsRefused() public {
        WitnessBond.Cosig memory a = cosig(100, 50, keccak256("root A"), "sig a");
        WitnessBond.Cosig memory b = WitnessBond.Cosig(101, 50, keccak256("root B"), "never signed");
        vm.expectRevert(WitnessBond.BadSignature.selector);
        bond.slashSplitView(NAME, ORIGIN, a, b);
    }

    function test_rewrittenHistoryTakesTheBond() public {
        // A: 4 entries. B: 6 entries in which entry 1 was swapped after A was cosigned.
        bytes32 rootA = node(node(leaf(0), leaf(1)), node(leaf(2), leaf(3)));
        bytes32 forged = leaf(999);
        bytes32 rootB = node(node(node(leaf(0), forged), node(leaf(2), leaf(3))), node(leaf(4), leaf(5)));
        WitnessBond.Cosig memory a = cosig(100, 4, rootA, "sig a");
        WitnessBond.Cosig memory b = cosig(200, 6, rootB, "sig b");
        bytes32[] memory pa = new bytes32[](2);
        pa[0] = leaf(0); pa[1] = node(leaf(2), leaf(3));
        bytes32[] memory pb = new bytes32[](3);
        pb[0] = leaf(0); pb[1] = node(leaf(2), leaf(3)); pb[2] = node(leaf(4), leaf(5));
        // sha256 is a precompile call, so leaf hashes are computed before the prank (it applies to the next call)
        WitnessBond.Inclusion memory ia = WitnessBond.Inclusion(1, leaf(1), pa);
        WitnessBond.Inclusion memory ib = WitnessBond.Inclusion(1, forged, pb);
        vm.prank(reporter);
        bond.slashRewrittenHistory(NAME, ORIGIN, a, b, ia, ib);
        assertEq(reporter.balance, 2 ether);
    }

    function test_anHonestExtensionCannotBeSlashed() public {
        bytes32 rootA = node(node(leaf(0), leaf(1)), node(leaf(2), leaf(3)));
        bytes32 rootB = node(node(node(leaf(0), leaf(1)), node(leaf(2), leaf(3))), node(leaf(4), leaf(5)));
        WitnessBond.Cosig memory a = cosig(100, 4, rootA, "sig a");
        WitnessBond.Cosig memory b = cosig(200, 6, rootB, "sig b");
        bytes32[] memory pa = new bytes32[](2);
        pa[0] = leaf(0); pa[1] = node(leaf(2), leaf(3));
        bytes32[] memory pb = new bytes32[](3);
        pb[0] = leaf(0); pb[1] = node(leaf(2), leaf(3)); pb[2] = node(leaf(4), leaf(5));
        WitnessBond.Inclusion memory ia = WitnessBond.Inclusion(1, leaf(1), pa);
        WitnessBond.Inclusion memory same = WitnessBond.Inclusion(1, leaf(1), pb);
        WitnessBond.Inclusion memory madeUp = WitnessBond.Inclusion(1, leaf(999), pb);
        // the same entry under both roots: not evidence
        vm.expectRevert(WitnessBond.NotEvidence.selector);
        bond.slashRewrittenHistory(NAME, ORIGIN, a, b, ia, same);
        // a made-up entry with a path that does not lead to B's root: not evidence either
        vm.expectRevert(WitnessBond.NotEvidence.selector);
        bond.slashRewrittenHistory(NAME, ORIGIN, a, b, ia, madeUp);
    }

    function test_unbondingWaitsAndStaysSlashable() public {
        vm.prank(witnessOwner);
        bond.requestUnbond(NAME);
        vm.prank(witnessOwner);
        vm.expectRevert(WitnessBond.NotYet.selector);
        bond.withdraw(NAME);
        // evidence found during the delay still takes the bond
        WitnessBond.Cosig memory a = cosig(100, 50, keccak256("root A"), "sig a");
        WitnessBond.Cosig memory b = cosig(101, 50, keccak256("root B"), "sig b");
        vm.prank(reporter);
        bond.slashSplitView(NAME, ORIGIN, a, b);
        vm.warp(block.timestamp + 8 days);
        uint256 before = witnessOwner.balance;
        vm.prank(witnessOwner);
        bond.withdraw(NAME);
        assertEq(witnessOwner.balance, before); // nothing left to withdraw
    }

    function test_anHonestWitnessGetsItsBondBack() public {
        vm.prank(witnessOwner);
        bond.requestUnbond(NAME);
        vm.warp(block.timestamp + 7 days);
        uint256 before = witnessOwner.balance;
        vm.prank(witnessOwner);
        bond.withdraw(NAME);
        assertEq(witnessOwner.balance, before + 2 ether);
    }
}
