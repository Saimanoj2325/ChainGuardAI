// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract ProxyWallet {
    address public owner;
    uint256 public nonce;

    constructor() {
        owner = msg.sender;
    }

    function execute(address target, bytes calldata data) external payable returns (bytes memory) {
        nonce += 1;
        (bool ok, bytes memory result) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return result;
    }
}
