// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract UpgradeableVault {
    address public admin;
    uint256 public withdrawLimit;
    bool private initialized;
    address private immutable deployer;

    constructor() {
        deployer = msg.sender;
    }

    function initialize(address _admin, uint256 _limit) external {
        require(msg.sender == deployer, "not deployer");
        require(!initialized, "already initialized");
        initialized = true;
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
