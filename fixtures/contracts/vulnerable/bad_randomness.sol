// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract CoinFlip {
    uint256 public lastBlock;

    constructor() payable {}

    function flip(bool guess) external payable {
        require(msg.value == 0.1 ether, "stake is 0.1 ether");
        require(block.number != lastBlock, "one flip per block");
        lastBlock = block.number;
        uint256 entropy = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp, msg.sender)));
        bool side = entropy % 2 == 1;
        if (side == guess) {
            payable(msg.sender).transfer(0.2 ether);
        }
    }
}
