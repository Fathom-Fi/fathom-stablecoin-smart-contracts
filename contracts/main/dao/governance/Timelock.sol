// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

contract Timelock is TimelockController {
    
    // minDelay is how long you have to wait before executing
    // proposers is the list of addresses that can propose
    // executors is the list of addresses that can execute
    // admin is msg.sender - we must give in an admin at first, so that we can move timelock controller admin so only the DAO can do anything with the timelock contorller
    constructor(uint256 minDelay, address[] memory proposers, address[] memory executors)
        TimelockController(minDelay, proposers, executors, msg.sender)
    {}
}