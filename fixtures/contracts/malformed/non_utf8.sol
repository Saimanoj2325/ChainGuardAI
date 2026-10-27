// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract Latin1 {
    // café üÿş invalid UTF-8 bytes follow
    string public greeting = "olá €";
}
