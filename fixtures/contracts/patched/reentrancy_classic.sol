// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract EtherBank {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function totalHeld() external view returns (uint256) {
        return address(this).balance;
    }
}
