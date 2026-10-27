// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract CoarseTimelock {
    address public immutable beneficiary;
    uint256 public immutable releaseTime;

    constructor(address _beneficiary, uint256 lockDays) payable {
        require(_beneficiary != address(0), "zero beneficiary");
        require(lockDays >= 1 && lockDays <= 3650, "lock range");
        beneficiary = _beneficiary;
        releaseTime = block.timestamp + lockDays * 1 days;
    }

    function release() external {
        require(msg.sender == beneficiary, "not beneficiary");
        require(block.timestamp >= releaseTime, "locked");
        payable(beneficiary).transfer(address(this).balance);
    }
}
