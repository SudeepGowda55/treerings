// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// QoreChain's post-quantum signature precompile (active on qorechain-diana).
interface IPQC {
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message) external view returns (bool);
}

/// Tree Rings witness bonds. A witness posts a bond with its ML-DSA-87 key; anyone who shows two of its
/// cosignatures that cannot both be honest takes the bond. Two kinds of evidence are accepted, both checked here:
///  - split view: two different roots for the same log origin at the same tree size;
///  - rewritten history: heads of sizes n < m and a leaf index i < n whose leaf differs under the two roots,
///    each shown by an RFC 9162 inclusion proof. If the larger tree extended the smaller one, leaf i would match.
/// Cosignatures sign c2sp tlog-cosignature's CosignedSubtree message (start 0, end = tree size).
contract WitnessBond {
    IPQC public constant PQC = IPQC(address(0x0a01));

    struct Witness {
        address owner;
        bytes pubkey; // ML-DSA-87, 2592 bytes
        uint256 bond;
        uint64 unbondAt; // 0 while bonded
    }

    struct Cosig {
        uint64 timestamp;
        uint64 treeSize;
        bytes32 root;
        bytes signature;
    }

    struct Inclusion {
        uint64 index;
        bytes32 leafHash;
        bytes32[] path;
    }

    uint256 public immutable minBond;
    uint64 public immutable unbondDelay;
    mapping(string => Witness) internal witnesses;

    event Registered(string name, address owner, uint256 bond);
    event UnbondRequested(string name, uint64 at);
    event Withdrawn(string name, uint256 amount);
    event Slashed(string name, string origin, address reporter, uint256 amount, string kind);

    error Exists();
    error UnknownWitness();
    error BondTooSmall();
    error NotOwner();
    error NotYet();
    error BadSignature();
    error NotEvidence();

    constructor(uint256 _minBond, uint64 _unbondDelay) {
        minBond = _minBond;
        unbondDelay = _unbondDelay;
    }

    function register(string calldata name, bytes calldata pubkey) external payable {
        if (witnesses[name].owner != address(0)) revert Exists();
        if (msg.value < minBond) revert BondTooSmall();
        require(pubkey.length == 2592, "ML-DSA-87 key");
        witnesses[name] = Witness(msg.sender, pubkey, msg.value, 0);
        emit Registered(name, msg.sender, msg.value);
    }

    function witness(string calldata name) external view returns (address owner, bytes memory pubkey, uint256 bond, uint64 unbondAt) {
        Witness storage w = witnesses[name];
        return (w.owner, w.pubkey, w.bond, w.unbondAt);
    }

    /// Stop witnessing; the bond stays slashable for unbondDelay, so evidence found later still counts.
    function requestUnbond(string calldata name) external {
        Witness storage w = witnesses[name];
        if (w.owner != msg.sender) revert NotOwner();
        w.unbondAt = uint64(block.timestamp) + unbondDelay;
        emit UnbondRequested(name, w.unbondAt);
    }

    function withdraw(string calldata name) external {
        Witness storage w = witnesses[name];
        if (w.owner != msg.sender) revert NotOwner();
        if (w.unbondAt == 0 || block.timestamp < w.unbondAt) revert NotYet();
        uint256 amount = w.bond;
        w.bond = 0;
        emit Withdrawn(name, amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer");
    }

    function slashSplitView(string calldata name, string calldata origin, Cosig calldata a, Cosig calldata b) external {
        _checkBoth(name, origin, a, b);
        if (a.treeSize != b.treeSize || a.root == b.root) revert NotEvidence();
        _slash(name, origin, "split view");
    }

    function slashRewrittenHistory(
        string calldata name,
        string calldata origin,
        Cosig calldata small,
        Cosig calldata large,
        Inclusion calldata inSmall,
        Inclusion calldata inLarge
    ) external {
        _checkBoth(name, origin, small, large);
        if (small.treeSize >= large.treeSize) revert NotEvidence();
        if (inSmall.index != inLarge.index || inSmall.index >= small.treeSize || inSmall.leafHash == inLarge.leafHash) revert NotEvidence();
        if (!verifyInclusion(inSmall.index, small.treeSize, inSmall.leafHash, inSmall.path, small.root)) revert NotEvidence();
        if (!verifyInclusion(inLarge.index, large.treeSize, inLarge.leafHash, inLarge.path, large.root)) revert NotEvidence();
        _slash(name, origin, "rewritten history");
    }

    function _checkBoth(string calldata name, string calldata origin, Cosig calldata a, Cosig calldata b) internal view {
        Witness storage w = witnesses[name];
        if (w.owner == address(0) || w.bond == 0) revert UnknownWitness();
        if (!PQC.pqcVerify(w.pubkey, a.signature, cosignedSubtree(name, a.timestamp, origin, a.treeSize, a.root))) revert BadSignature();
        if (!PQC.pqcVerify(w.pubkey, b.signature, cosignedSubtree(name, b.timestamp, origin, b.treeSize, b.root))) revert BadSignature();
    }

    function _slash(string calldata name, string calldata origin, string memory kind) internal {
        Witness storage w = witnesses[name];
        uint256 amount = w.bond;
        w.bond = 0;
        emit Slashed(name, origin, msg.sender, amount, kind);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer");
    }

    /// c2sp tlog-cosignature CosignedSubtree for a checkpoint (start 0, end = tree size).
    function cosignedSubtree(string calldata name, uint64 timestamp, string calldata origin, uint64 treeSize, bytes32 root)
        public
        pure
        returns (bytes memory)
    {
        require(bytes(name).length > 0 && bytes(name).length < 256 && bytes(origin).length > 0 && bytes(origin).length < 256, "length");
        return abi.encodePacked(
            "subtree/v1\n", bytes1(0), uint8(bytes(name).length), name, timestamp, uint8(bytes(origin).length), origin, uint64(0), treeSize, root
        );
    }

    /// RFC 9162 section 2.1.3.2.
    function verifyInclusion(uint64 index, uint64 treeSize, bytes32 leafHash, bytes32[] calldata path, bytes32 root)
        public
        pure
        returns (bool)
    {
        if (index >= treeSize) return false;
        uint64 fn = index;
        uint64 sn = treeSize - 1;
        bytes32 r = leafHash;
        for (uint256 i = 0; i < path.length; i++) {
            if (sn == 0) return false;
            if ((fn & 1) == 1 || fn == sn) {
                r = sha256(abi.encodePacked(bytes1(0x01), path[i], r));
                if ((fn & 1) == 0) {
                    while ((fn & 1) == 0 && fn != 0) {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                r = sha256(abi.encodePacked(bytes1(0x01), r, path[i]));
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && r == root;
    }
}
