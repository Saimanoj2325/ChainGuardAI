// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.6.12;

contract KingOfTheHill {
    address payable public king;
    uint256 public highestBid;

    function claimThrone() external payable {
        require(msg.value > highestBid, "bid too low");
        require(king.send(highestBid), "refund failed");
        king = msg.sender;
        highestBid = msg.value;
    }
}
