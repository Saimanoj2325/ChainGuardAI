// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.4.26;

contract PayoutBox {
    address public owner;
    mapping(address => uint256) public credit;

    function PayoutBox() public {
        owner = msg.sender;
    }

    function fund(address beneficiary) public payable {
        credit[beneficiary] += msg.value;
    }

    function payOut() public {
        uint256 amount = credit[msg.sender];
        credit[msg.sender] = 0;
        require(msg.sender.send(amount));
    }

    function forward(address target, uint256 amount) public {
        require(msg.sender == owner);
        require(target.call.value(amount)());
    }
}
