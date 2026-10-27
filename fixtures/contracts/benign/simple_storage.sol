// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract SimpleStorage {
    uint256 private value;
    address public immutable owner;

    event ValueChanged(uint256 oldValue, uint256 newValue);

    constructor() {
        owner = msg.sender;
    }

    function set(uint256 newValue) external {
        require(msg.sender == owner, "not owner");
        emit ValueChanged(value, newValue);
        value = newValue;
    }

    function get() external view returns (uint256) {
        return value;
    }
}
