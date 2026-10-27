// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.4.26;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        require(c / a == b);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);
        return c;
    }
}

contract BatchToken {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function BatchToken(uint256 initialSupply) public {
        balances[msg.sender] = initialSupply;
        totalSupply = initialSupply;
    }

    function transfer(address to, uint256 value) public returns (bool) {
        balances[msg.sender] = balances[msg.sender].sub(value);
        balances[to] = balances[to].add(value);
        return true;
    }

    function batchTransfer(address[] receivers, uint256 value) public returns (bool) {
        uint256 amount = receivers.length.mul(value);
        require(receivers.length > 0 && receivers.length <= 20);
        balances[msg.sender] = balances[msg.sender].sub(amount);
        for (uint256 i = 0; i < receivers.length; i++) {
            balances[receivers[i]] = balances[receivers[i]].add(value);
        }
        return true;
    }
}
