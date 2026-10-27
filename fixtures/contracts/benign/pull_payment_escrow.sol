// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.6.12;

contract PullPaymentEscrow {
    address public arbiter;
    mapping(address => uint256) private deposits;

    event Deposited(address indexed payee, uint256 amount);
    event Withdrawn(address indexed payee, uint256 amount);

    constructor() public {
        arbiter = msg.sender;
    }

    function depositFor(address payee) external payable {
        require(msg.sender == arbiter, "not arbiter");
        require(payee != address(0), "zero payee");
        uint256 updated = deposits[payee] + msg.value;
        require(updated >= deposits[payee], "overflow");
        deposits[payee] = updated;
        emit Deposited(payee, msg.value);
    }

    function depositsOf(address payee) external view returns (uint256) {
        return deposits[payee];
    }

    function withdraw() external {
        uint256 payment = deposits[msg.sender];
        require(payment > 0, "nothing owed");
        deposits[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: payment}("");
        require(ok, "withdraw failed");
        emit Withdrawn(msg.sender, payment);
    }
}
