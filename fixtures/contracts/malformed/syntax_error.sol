// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract Broken {
    uint256 public x

    function set(uint256 v) external {
        x = v;
    }

    function get() external view returns (uint256 {
        return x;
