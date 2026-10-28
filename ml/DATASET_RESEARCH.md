# ChainGuard AI — Smart Contract Vulnerability Dataset Research & ML Strategy

**Authors:** ChainGuard AI Engineering Team · Project ID 32  
**Date:** October 2026  
**Document Status:** Approved Architecture & Strategy Reference  

---

## 1. Executive Summary

Machine learning for smart-contract vulnerability detection requires program representations that preserve semantic control and data dependencies while avoiding cross-contract data leakage. Standard token-sequence models (e.g., standard text transformers) frequently overfit to variable naming conventions and comment artifacts rather than execution semantics.

This research document evaluates seven established smart contract vulnerability benchmarks, identifies critical dataset limitations (syntactic noise, duplicate contracts, and automated labeling artifacts), justifies our curated selection, and defines a leakage-resistant train/validation/test strategy for graph neural network (GNN) and baseline vulnerability detection.

---

## 2. Benchmark Dataset Evaluation & Comparison

We evaluated seven candidate datasets widely cited in smart contract vulnerability research:

| Dataset | Total Contracts | Labeled Classes | Ground Truth Verification | Vulnerable / Fixed Pairs | Source Available | Duplicate Rate | Suitability for AST/CFG/DFG & GNN |
|---|---|---|---|---|---|---|---|
| **SmartBugs Curated** (Durieux et al., ICSE 2020) | 143 contracts (208 tagged bugs) | 9 DASP classes | **Human expert verified** (manual line-level annotation) | Yes (for subset) | **Yes** (Solidity source) | Low (< 5%) | **High** (full source AST/CFG/DFG extraction possible) |
| **SmartBugs Wild** (Ferreira et al., 2020) | 47,398 contracts | 9 DASP classes | **Automated tool consensus** (noisy, high false positive rate) | No | **Yes** (Etherscan scraped) | High (~62% duplicate / template clones) | Moderate (requires extensive deduplication & filtering) |
| **SolidiFI-Benchmark** (Ghaleb et al., TSE 2020) | 350 injected / 50 base contracts | 7 vulnerability classes | **Systematic bug injection** (precise line truth) | **Yes** (clean paired contracts) | **Yes** (Solidity source) | Very Low | **High** (exact vulnerable / patched ground truth) |
| **SWC Registry** (Smart Contract Weakness Classification) | ~112 test contracts | 37 SWC categories | **Human-curated** (ConsenSys standards) | Partial (test fixtures) | **Yes** (Solidity source) | Very Low | **High** (precise vulnerability semantics & test cases) |
| **DefectChecker** (Chen et al., 2021) | 3,467 contracts | 8 defect types | Tool + partial manual review | No | Partial (some bytecode only) | Moderate (~28%) | Moderate (bytecode emphasis) |
| **ContractWard** (Wang et al., IEEE TDSC 2021) | 49,502 contracts | 6 vulnerability classes | Tool-labeled | No | Bytecode only | High (~55%) | Low (lacks source-level AST/CFG graphs) |
| **DASP-10 Taxonomy** (NCC Group) | Reference taxonomy | 10 vulnerability classes | Standard classification scheme | Reference | Reference | N/A | Taxonomy reference for label mapping |

---

## 3. Dataset Selection & Justification

### 3.1 Primary Selected Benchmark: Curated Multi-Source Composite
We select a unified, curated corpus combining:
1. **SmartBugs Curated** (human-annotated real-world vulnerable contracts from ICSE 2020).
2. **SWC Registry Ground Truth** (canonical weakness samples with verified line annotations).
3. **SolidiFI Paired Benchmark** (clean base contracts paired with injected bug variants).

### 3.2 Decision Justification
- **Label Reliability:** Automated-tool datasets like SmartBugs Wild suffer from high false-positive rates (frequently exceeding 40% tool disagreement), which pollutes supervised model loss functions. Our selected composite relies on **human-expert verified ground-truth** and deterministic bug injections.
- **Vulnerable/Fixed Contrastive Pairs:** By incorporating paired contracts from SolidiFI and SWC, the model is trained to differentiate between vulnerable patterns (e.g. state write after `call.value`) and their patched counterparts (Checks-Effects-Interactions pattern or `ReentrancyGuard`), minimizing false alarms on benign idioms.
- **Source-Code Completeness:** Program graph extraction (AST, CFG, DFG) requires valid Solidity source structure to construct node call graphs, variable def-use chains, and statement ordering.
- **Deduplication:** We explicitly filter byte-identical and normalized token-identical contracts using SHA-256 and semantic similarity thresholding (< 0.90 Jaccard on AST token bags).

---

## 4. Supported Vulnerability Classes & Label Mapping

The benchmark classes map to our unified `VulnClass` schema:

| Target `VulnClass` | SWC Mapping | DASP Category | Description |
|---|---|---|---|
| `reentrancy` | SWC-107 | Reentrancy | State modification after untrusted external call |
| `unchecked_call` | SWC-104 | Unchecked Low-Level Calls | Ignored return value of low-level `call`, `send`, `delegatecall` |
| `tx_origin` | SWC-115 | Access Control | Authorization using `tx.origin` vulnerable to phishing |
| `timestamp_dependence` | SWC-116 | Time Manipulation | Critical state or payout logic conditioned on `block.timestamp` |
| `integer_overflow` | SWC-101 | Arithmetic Issues | Unchecked arithmetic underflow/overflow (pre-0.8.0) |
| `access_control` | SWC-105, SWC-106 | Access Control | Missing authorization modifiers (`onlyOwner`, uninitialized owner) |
| `delegatecall` | SWC-112 | Delegatecall | `delegatecall` to untrusted user-controlled target address |
| `unprotected_selfdestruct`| SWC-106 | Access Control | Missing access restriction on `selfdestruct` / `suicide` |
| `denial_of_service` | SWC-113, SWC-128 | Denial of Service | Unbounded loops over dynamic arrays or push-over-pull payments |
| `bad_randomness` | SWC-120 | Bad Randomness | Pseudo-randomness derived from predictable block attributes |

---

## 5. Leakage-Resistant Train / Validation / Test Strategy

### 5.1 The Cross-Split Leakage Problem
In smart contract datasets, multiple contracts share common libraries (e.g., SafeMath, OpenZeppelin Ownable, ERC20 templates) or are identical clones deployed at different addresses. A naive random train/test split causes **severe data leakage**: the test split evaluates contracts whose functions and AST structures were already seen during training, yielding deceptively high F1 scores (>95%) that collapse in real-world deployment.

### 5.2 Leakage Prevention Rules
1. **Contract Family / Project Grouping:** All contracts derived from the same base repository or project family are assigned exclusively to the same split.
2. **Deduplication:** Near-duplicate contracts with Jaccard AST similarity > 0.85 are clustered; entire clusters remain inside a single split.
3. **Paired Invariant:** Vulnerable contracts and their patched counterparts are placed together in either train or test, never split across both.
4. **Temporal Split Validation:** Pre-0.8.0 vs post-0.8.0 arithmetic contracts are balanced across splits to verify generalization across compiler versions.

---

## 6. Program Graph Construction (AST / CFG / DFG)

For each contract, ChainGuard constructs a multi-relational directed graph $G = (V, E, X)$:
- **Nodes ($V$):**
  - Contract definitions, Function headers, State variables, Statements (assignments, requirements, if/else), Expression calls (external calls, transfers, delegatecalls).
- **Edges ($E$):**
  - **AST Edges:** Hierarchical syntactic containment (Function $\to$ Block $\to$ Statement $\to$ Expression).
  - **CFG Edges:** Control-flow transitions (sequential next, conditional branch true/false, loop back-edges).
  - **DFG Edges:** Data-flow dependencies (variable definition to variable read/use, state variable read/write).
- **Node Features ($X$):**
  - 64-dimensional feature vector encoding statement type, opcode semantics, call category, access restriction flags, and arithmetic operators.

---

## 7. Model Architecture & Baselines

1. **Baseline Model:**
   - Multi-label classifier (Random Forest / Gradient Boosted Trees / MLP) trained on global graph structural statistics (node degree distributions, call counts, state var writes) and syntactic feature vectors.
2. **Graph Neural Network (GNN):**
   - 2-layer Graph Convolutional Network (GCN / GAT) with node feature dimension $d=64$, hidden dimension $h=128$, ReLU activations, dropout ($p=0.2$).
   - Graph-level representation obtained via concatenated Mean and Max graph pooling.
   - Classification head: Multi-label sigmoid output over the 10 vulnerability classes.

---

## 8. Summary of Strategy

ChainGuard AI commits to honest, verified evaluation:
- No fabricated benchmark metrics.
- Clear separation between synthetic test fixtures (`fixtures/`) and genuine benchmark results (`ml/reports/`).
- Pluggable runtime integration through `chainguard_ml.analyzer.MLAnalyzer`.
