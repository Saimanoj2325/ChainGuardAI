// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.6.12;

contract KingOfTheHill {
    address payable public king;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    function claimThrone() external payable {
        require(msg.value > highestBid, "bid too low");
        if (king != address(0)) {
            pendingReturns[king] += highestBid;
        }
        king = msg.sender;
        highestBid = msg.value;
    }

    function withdrawRefund() external {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "nothing to refund");
        pendingReturns[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "refund failed");
    }
}
