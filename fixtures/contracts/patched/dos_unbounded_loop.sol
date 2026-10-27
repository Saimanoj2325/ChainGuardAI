// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract Dividends {
    address public owner;
    address[] public shareholders;
    mapping(address => uint256) public owed;
    uint256 public nextIndex;
    uint256 public roundShare;

    constructor() {
        owner = msg.sender;
    }

    function join() external payable {
        require(msg.value >= 0.01 ether, "min stake");
        shareholders.push(msg.sender);
    }

    function startRound() external {
        require(msg.sender == owner, "not owner");
        require(shareholders.length > 0, "no shareholders");
        roundShare = address(this).balance / shareholders.length;
        nextIndex = 0;
    }

    function allocate(uint256 maxCount) external {
        require(msg.sender == owner, "not owner");
        uint256 end = nextIndex + maxCount;
        if (end > shareholders.length) {
            end = shareholders.length;
        }
        for (uint256 i = nextIndex; i < end; i++) {
            owed[shareholders[i]] += roundShare;
        }
        nextIndex = end;
    }

    function claim() external {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "claim failed");
    }
}
