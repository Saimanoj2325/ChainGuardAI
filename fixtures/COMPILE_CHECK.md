# Fixture compile check (SYNTHETIC fixtures)

Generated 2026-10-27T08:45:50+00:00 on aarch64 by `python fixtures/scripts/compile_check.py`.

Expectation: vulnerable/patched/benign compile cleanly; malformed should fail; resource files are stress inputs.

| file | pragma | backend | compiles | note |
|---|---|---|---|---|
| vulnerable/access_control_initializer.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| vulnerable/access_control_owner.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| vulnerable/bad_randomness.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| vulnerable/delegatecall.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| vulnerable/dos_push_payment.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| vulnerable/dos_unbounded_loop.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| vulnerable/integer_overflow.sol | 0.4.26+commit.4563c3fc.Emscripten.clang | solcjs | True |  |
| vulnerable/integer_overflow_timelock.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| vulnerable/reentrancy_classic.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| vulnerable/reentrancy_cross_function.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| vulnerable/timestamp_dependence.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| vulnerable/tx_origin.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| vulnerable/unchecked_call.sol | 0.4.26+commit.4563c3fc.Emscripten.clang | solcjs | True |  |
| vulnerable/unprotected_selfdestruct.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| patched/access_control_initializer.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| patched/access_control_owner.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| patched/bad_randomness.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| patched/delegatecall.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| patched/dos_push_payment.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| patched/dos_unbounded_loop.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| patched/integer_overflow.sol | 0.4.26+commit.4563c3fc.Emscripten.clang | solcjs | True |  |
| patched/integer_overflow_timelock.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| patched/reentrancy_classic.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| patched/reentrancy_cross_function.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| patched/timestamp_dependence.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| patched/tx_origin.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| patched/unchecked_call.sol | 0.4.26+commit.4563c3fc.Emscripten.clang | solcjs | True |  |
| patched/unprotected_selfdestruct.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| benign/coarse_timelock.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| benign/multisig_lite.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| benign/pull_payment_escrow.sol | 0.6.12+commit.27d51765.Emscripten.clang | solcjs | True |  |
| benign/simple_storage.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| benign/simple_token.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| malformed/binary_garbage.sol | - | none | False | not valid UTF-8 (not compiled) |
| malformed/empty.sol | - | none | False | no exact pragma version found (not compiled) |
| malformed/long_line.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |
| malformed/non_utf8.sol | - | none | False | not valid UTF-8 (not compiled) |
| malformed/syntax_error.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | False | ParserError: Expected ';' but got 'function'  --> syntax_error.sol:8:5:   \| 8 \|     function set(uint256 v) external {   \|     ^^^^^^^^   |
| malformed/unsupported_pragma.sol | 0.3.0 | none | False | pragma 0.3.0 predates every available solc build |
| resource/deep_nesting.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | False | ParserError: Maximum recursion depth reached during parsing.  --> deep_nesting.sol:7:266:   \| 7 \|  ... ((((((((((((((((((((((((((((((((((((((((((((((((((((((( |
| resource/many_functions.sol | 0.8.24+commit.e11b9ed9.Emscripten.clang | solcjs | True |  |

**Unexpected failures in vulnerable/patched/benign:** none
