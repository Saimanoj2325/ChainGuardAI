// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.6.12;

contract Piggy {
    address payable public owner;

    constructor() public payable {
        owner = msg.sender;
    }

    function deposit() external payable {}

    function close() external {
        selfdestruct(msg.sender);
    }
}
