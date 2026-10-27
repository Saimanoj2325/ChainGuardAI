// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.4.26;

contract BatchToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function BatchToken(uint256 initialSupply) public {
        balances[msg.sender] = initialSupply;
        totalSupply = initialSupply;
    }

    function transfer(address to, uint256 value) public returns (bool) {
        require(balances[msg.sender] - value >= 0);
        balances[msg.sender] -= value;
        balances[to] += value;
        return true;
    }

    function batchTransfer(address[] receivers, uint256 value) public returns (bool) {
        uint256 amount = receivers.length * value;
        require(receivers.length > 0 && receivers.length <= 20);
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        for (uint256 i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += value;
        }
        return true;
    }
}
