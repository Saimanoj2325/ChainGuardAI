// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract CoinFlip {
    struct Bet {
        bool guess;
        uint256 targetBlock;
        bool open;
    }

    address public immutable house;
    bytes32 public houseCommit;
    mapping(address => Bet) public bets;

    constructor(bytes32 _houseCommit) payable {
        house = msg.sender;
        houseCommit = _houseCommit;
    }

    function flip(bool guess) external payable {
        require(msg.value == 0.1 ether, "stake is 0.1 ether");
        require(!bets[msg.sender].open, "bet open");
        bets[msg.sender] = Bet(guess, block.number + 1, true);
    }

    function settle(address payable player, bytes32 houseSecret, bytes32 nextCommit) external {
        require(msg.sender == house, "not house");
        require(keccak256(abi.encodePacked(houseSecret)) == houseCommit, "bad reveal");
        Bet memory bet = bets[player];
        require(bet.open && block.number > bet.targetBlock, "not ready");
        houseCommit = nextCommit;
        delete bets[player];
        bool side = uint256(keccak256(abi.encodePacked(houseSecret, player, bet.targetBlock))) % 2 == 1;
        if (side == bet.guess) {
            player.transfer(0.2 ether);
        }
    }
}
