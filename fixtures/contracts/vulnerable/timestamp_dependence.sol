// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.6.12;

contract FifteenSecondGame {
    uint256 public pastBlockTime;

    constructor() public payable {}

    function play() external payable {
        require(msg.value == 1 ether, "stake is 1 ether");
        require(now != pastBlockTime, "one play per block");
        pastBlockTime = now;
        if (now % 15 == 0) {
            msg.sender.transfer(address(this).balance);
        }
    }
}
