// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract UpgradeableVault {
    address public admin;
    uint256 public withdrawLimit;

    function initialize(address _admin, uint256 _limit) external {
        admin = _admin;
        withdrawLimit = _limit;
    }

    function withdraw(uint256 amount) external {
        require(msg.sender == admin, "not admin");
        require(amount <= withdrawLimit, "over limit");
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
