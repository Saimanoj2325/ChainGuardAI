// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract Dividends {
    address public owner;
    address payable[] public shareholders;

    constructor() {
        owner = msg.sender;
    }

    function join() external payable {
        require(msg.value >= 0.01 ether, "min stake");
        shareholders.push(payable(msg.sender));
    }

    function distribute() external {
        require(msg.sender == owner, "not owner");
        uint256 share = address(this).balance / shareholders.length;
        for (uint256 i = 0; i < shareholders.length; i++) {
            shareholders[i].transfer(share);
        }
    }
}
