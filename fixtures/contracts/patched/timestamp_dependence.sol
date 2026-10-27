// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.6.12;

contract FifteenSecondGame {
    address public owner;
    bytes32 public immutable ownerCommit;
    bool public settled;
    address[] public players;
    mapping(address => uint256) public guesses;

    constructor(bytes32 _ownerCommit) public payable {
        owner = msg.sender;
        ownerCommit = _ownerCommit;
    }

    function play(uint256 guess) external payable {
        require(!settled, "round over");
        require(msg.value == 1 ether, "stake is 1 ether");
        require(guesses[msg.sender] == 0, "already playing");
        require(guess > 0, "guess must be non-zero");
        guesses[msg.sender] = guess;
        players.push(msg.sender);
    }

    function settle(uint256 secret, bytes32 salt, address payable winner) external {
        require(msg.sender == owner, "not owner");
        require(!settled, "round over");
        require(keccak256(abi.encodePacked(secret, salt)) == ownerCommit, "bad reveal");
        require(guesses[winner] != 0 && guesses[winner] % 15 == secret % 15, "not a winner");
        settled = true;
        winner.transfer(address(this).balance);
    }
}
