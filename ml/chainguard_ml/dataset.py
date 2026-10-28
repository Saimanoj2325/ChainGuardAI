"""Benchmark Dataset Loader, Graph Preprocessing, and Leakage-Resistant Splitter."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np

from .features import graph_to_tensors
from .graph import build_program_graph
from .models.gnn import VULN_CLASSES


@dataclass
class ContractSample:
    name: str
    source: str
    labels: List[str]  # list of present VulnClass values
    family: str        # project / template group for leakage prevention
    node_features: np.ndarray = field(default_factory=lambda: np.zeros((1, 64), dtype=np.float32))
    edge_index: np.ndarray = field(default_factory=lambda: np.zeros((2, 0), dtype=np.int64))
    global_features: np.ndarray = field(default_factory=lambda: np.zeros(32, dtype=np.float32))
    label_vector: np.ndarray = field(default_factory=lambda: np.zeros(len(VULN_CLASSES), dtype=np.float32))


def label_to_vector(labels: List[str]) -> np.ndarray:
    y = np.zeros(len(VULN_CLASSES), dtype=np.float32)
    for lbl in labels:
        if lbl in VULN_CLASSES:
            y[VULN_CLASSES.index(lbl)] = 1.0
    return y


def build_benchmark_samples() -> List[ContractSample]:
    """
    Assembles standard benchmark contracts across all 10 vulnerability classes + benign contracts
    derived from curated benchmarks (SmartBugs Curated, SWC Registry, SolidiFI pairs).
    """
    samples: List[ContractSample] = []

    # 1. Reentrancy Classic
    reentrancy_vuln = """
    pragma solidity ^0.8.0;
    contract EtherStore {
        mapping(address => uint256) public balances;
        function deposit() public payable { balances[msg.sender] += msg.value; }
        function withdraw(uint256 _amount) public {
            require(balances[msg.sender] >= _amount);
            (bool sent, ) = msg.sender.call{value: _amount}("");
            require(sent, "Failed to send Ether");
            balances[msg.sender] -= _amount;
        }
    }
    """
    samples.append(ContractSample(name="reentrancy_etherstore.sol", source=reentrancy_vuln, labels=["reentrancy"], family="etherstore"))

    # 1b. Reentrancy Patched (Checks-Effects-Interactions)
    reentrancy_fixed = """
    pragma solidity ^0.8.0;
    contract EtherStorePatched {
        mapping(address => uint256) public balances;
        function deposit() public payable { balances[msg.sender] += msg.value; }
        function withdraw(uint256 _amount) public {
            require(balances[msg.sender] >= _amount);
            balances[msg.sender] -= _amount;
            (bool sent, ) = msg.sender.call{value: _amount}("");
            require(sent, "Failed to send Ether");
        }
    }
    """
    samples.append(ContractSample(name="reentrancy_etherstore_fixed.sol", source=reentrancy_fixed, labels=[], family="etherstore"))

    # 2. Cross-Function Reentrancy
    reentrancy_cross = """
    pragma solidity ^0.8.0;
    contract CrossVault {
        mapping(address => uint256) private userBalances;
        function transfer(address to, uint256 amount) public {
            if (userBalances[msg.sender] >= amount) {
                userBalances[to] += amount;
                userBalances[msg.sender] -= amount;
            }
        }
        function withdrawBalance() public {
            uint256 amount = userBalances[msg.sender];
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            userBalances[msg.sender] = 0;
        }
    }
    """
    samples.append(ContractSample(name="reentrancy_cross_vault.sol", source=reentrancy_cross, labels=["reentrancy"], family="cross_vault"))

    # 3. Unchecked Low-Level Call
    unchecked_call = """
    pragma solidity ^0.8.0;
    contract LottoLocker {
        mapping(address => uint256) public credits;
        function sendReward(address payable winner, uint256 amount) public {
            winner.send(amount); // Unchecked send return value
            credits[winner] = 0;
        }
        function callReward(address payable winner, uint256 amount) public {
            winner.call{value: amount}(""); // Unchecked call return value
            credits[winner] = 0;
        }
    }
    """
    samples.append(ContractSample(name="unchecked_lotto.sol", source=unchecked_call, labels=["unchecked_call"], family="lotto"))

    # 3b. Unchecked Call Patched
    unchecked_call_fixed = """
    pragma solidity ^0.8.0;
    contract LottoLockerPatched {
        mapping(address => uint256) public credits;
        function sendReward(address payable winner, uint256 amount) public {
            credits[winner] = 0;
            bool success = winner.send(amount);
            require(success, "Send failed");
        }
    }
    """
    samples.append(ContractSample(name="unchecked_lotto_fixed.sol", source=unchecked_call_fixed, labels=[], family="lotto"))

    # 4. Tx.Origin Phishing
    tx_origin_vuln = """
    pragma solidity ^0.8.0;
    contract TxUserWallet {
        address public owner;
        constructor() { owner = msg.sender; }
        function transfer(address payable to, uint256 amount) public {
            require(tx.origin == owner, "Not owner");
            to.transfer(amount);
        }
    }
    """
    samples.append(ContractSample(name="tx_origin_wallet.sol", source=tx_origin_vuln, labels=["tx_origin"], family="tx_wallet"))

    # 4b. Tx.Origin Patched
    tx_origin_fixed = """
    pragma solidity ^0.8.0;
    contract TxUserWalletPatched {
        address public owner;
        constructor() { owner = msg.sender; }
        function transfer(address payable to, uint256 amount) public {
            require(msg.sender == owner, "Not owner");
            to.transfer(amount);
        }
    }
    """
    samples.append(ContractSample(name="tx_origin_wallet_fixed.sol", source=tx_origin_fixed, labels=[], family="tx_wallet"))

    # 5. Timestamp Dependence
    timestamp_vuln = """
    pragma solidity ^0.8.0;
    contract TimedLottery {
        uint256 public pastBlockTime;
        function spin() public payable {
            require(msg.value == 1 ether);
            if (block.timestamp % 15 == 0) {
                payable(msg.sender).transfer(address(this).balance);
            }
            pastBlockTime = block.timestamp;
        }
    }
    """
    samples.append(ContractSample(name="timed_lottery.sol", source=timestamp_vuln, labels=["timestamp_dependence"], family="lottery_time"))

    # 6. Integer Overflow (pre-0.8.0)
    overflow_vuln = """
    pragma solidity ^0.7.0;
    contract TimeLock {
        mapping(address => uint256) public balances;
        mapping(address => uint256) public lockTime;
        function deposit() public payable {
            balances[msg.sender] += msg.value;
            lockTime[msg.sender] = block.timestamp + 1 weeks;
        }
        function increaseLockTime(uint256 _secondsToIncrease) public {
            lockTime[msg.sender] += _secondsToIncrease; // Can overflow to 0
        }
        function withdraw() public {
            require(balances[msg.sender] > 0);
            require(block.timestamp > lockTime[msg.sender]);
            msg.sender.transfer(balances[msg.sender]);
            balances[msg.sender] = 0;
        }
    }
    """
    samples.append(ContractSample(name="integer_overflow_timelock.sol", source=overflow_vuln, labels=["integer_overflow"], family="timelock"))

    # 7. Access Control / Unprotected Initializer
    access_vuln = """
    pragma solidity ^0.8.0;
    contract UnprotectedVault {
        address public owner;
        bool public initialized;
        function initWallet() public {
            // Missing access modifier or initializer check
            owner = msg.sender;
        }
        function withdrawAll() public {
            require(msg.sender == owner, "Only owner");
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    """
    samples.append(ContractSample(name="access_control_vault.sol", source=access_vuln, labels=["access_control"], family="vault_access"))

    # 8. Untrusted Delegatecall
    delegatecall_vuln = """
    pragma solidity ^0.8.0;
    contract ProxyDelegate {
        address public target;
        address public owner;
        constructor(address _target) { target = _target; owner = msg.sender; }
        function forward(bytes calldata data) public payable {
            (bool success, ) = target.delegatecall(data);
            require(success);
        }
    }
    """
    samples.append(ContractSample(name="delegatecall_proxy.sol", source=delegatecall_vuln, labels=["delegatecall"], family="proxy_delegate"))

    # 9. Unprotected Selfdestruct
    selfdestruct_vuln = """
    pragma solidity ^0.8.0;
    contract KillableTreasury {
        address public owner;
        function kill(address payable recipient) public {
            // Anyone can trigger selfdestruct
            selfdestruct(recipient);
        }
    }
    """
    samples.append(ContractSample(name="killable_treasury.sol", source=selfdestruct_vuln, labels=["unprotected_selfdestruct"], family="killable"))

    # 10. Denial of Service (Push payment loop)
    dos_vuln = """
    pragma solidity ^0.8.0;
    contract KingOfHillDoS {
        address payable[] public investors;
        function invest() public payable {
            investors.push(payable(msg.sender));
        }
        function refundAll() public {
            for (uint i = 0; i < investors.length; i++) {
                investors[i].transfer(1 ether); // If one reverts, entire refund fails
            }
        }
    }
    """
    samples.append(ContractSample(name="dos_investors.sol", source=dos_vuln, labels=["denial_of_service"], family="dos_king"))

    # 11. Bad Randomness
    bad_randomness = """
    pragma solidity ^0.8.0;
    contract DiceRoll {
        function roll() public payable returns (bool) {
            uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender))) % 6;
            if (random == 0) {
                payable(msg.sender).transfer(address(this).balance);
                return true;
            }
            return false;
        }
    }
    """
    samples.append(ContractSample(name="bad_randomness_dice.sol", source=bad_randomness, labels=["bad_randomness"], family="dice_random"))

    # 12. Benign Standard ERC20
    benign_erc20 = """
    pragma solidity ^0.8.0;
    contract StandardToken {
        string public name = "SecureToken";
        string public symbol = "SEC";
        uint8 public decimals = 18;
        uint256 public totalSupply;
        mapping(address => uint256) public balanceOf;
        mapping(address => mapping(address => uint256)) public allowance;
        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
        constructor(uint256 initialSupply) {
            totalSupply = initialSupply * 10 ** 18;
            balanceOf[msg.sender] = totalSupply;
        }
        function transfer(address to, uint256 value) public returns (bool success) {
            require(balanceOf[msg.sender] >= value, "Insufficient balance");
            balanceOf[msg.sender] -= value;
            balanceOf[to] += value;
            emit Transfer(msg.sender, to, value);
            return true;
        }
        function approve(address spender, uint256 value) public returns (bool success) {
            allowance[msg.sender][spender] = value;
            emit Approval(msg.sender, spender, value);
            return true;
        }
    }
    """
    samples.append(ContractSample(name="standard_token.sol", source=benign_erc20, labels=[], family="erc20_secure"))

    # Preprocess all samples: build graph and extract tensor features
    for s in samples:
        graph = build_program_graph(s.source)
        nodes_f, edges_idx, glob_f = graph_to_tensors(graph, s.source)
        s.node_features = nodes_f
        s.edge_index = edges_idx
        s.global_features = glob_f
        s.label_vector = label_to_vector(s.labels)

    return samples


def leakage_resistant_split(
    samples: List[ContractSample],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    seed: int = 42,
) -> Tuple[List[ContractSample], List[ContractSample], List[ContractSample]]:
    """
    Splits samples into (train, val, test) using contract family grouping to prevent
    vulnerable/fixed contract pair leakage or clone overlap between splits.
    """
    rng = np.random.RandomState(seed)
    families = sorted(list(set(s.family for s in samples)))
    rng.shuffle(families)

    n_families = len(families)
    n_train = max(1, int(n_families * train_ratio))
    n_val = max(1, int(n_families * val_ratio))

    train_fams = set(families[:n_train])
    val_fams = set(families[n_train:n_train + n_val])
    test_fams = set(families[n_train + n_val:])

    train = [s for s in samples if s.family in train_fams]
    val = [s for s in samples if s.family in val_fams]
    test = [s for s in samples if s.family in test_fams]

    return train, val, test
