// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract OriginWallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    receive() external payable {}

    function transferTo(address payable dest, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        dest.transfer(amount);
    }
}
