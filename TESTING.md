# Testing Coverage Documentation

## Coverage Summary

**Current Coverage: 84%** (up from initial 29%)

## Test Suite

The test suite includes 30 tests covering:

### Core Functionality
- **Parsing tests** (8 tests): Valid lines, negative returns, resumed calls, unfinished calls, PID/timestamp prefixes, hex return values
- **Description/Category tests** (4 tests): Known/unknown syscalls, categories, manpage URLs
- **Parameter extraction tests** (1 test): Normal parameters, unfinished calls, resumed calls

### Integration Tests
- **Output tests** (5 tests): explain_line with different verbosity levels, category filtering, summary output (with/without data)
- **File processing tests** (2 tests): Reading from files, handling missing files
- **CLI tests** (4 tests): Command-line arguments, verbose mode, filters, --catlist flag

### Category Tests
- **Utility tests** (1 test): get_all_categories function

## Uncovered Code (16%)

The following code is intentionally not covered by tests:

### Signal Handling (lines 788-792)
**Reason**: Requires interactive signal injection (Ctrl-C handling)
```python
def signal_handler(signum, frame):
    self.interrupted = True
    print("\n[Interrupted - finishing up...]", file=sys.stderr)
```

### process_stdin Method (lines 960, 965-967, 971-984)
**Reason**: Requires interactive stdin and signal handling
- Reading from stdin in a loop
- KeyboardInterrupt handling
- Signal-based interruption

This functionality is tested indirectly through the file processing tests, as both code paths use the same core `explain_line` method.

### Edge Cases (lines 813, 852, 858, 867)
Minor edge cases in parameter truncation and error handling that are difficult to trigger without contrived inputs.

### if __name__ == "__main__" (line 1042)
This line is excluded from coverage via pyproject.toml configuration as it's just a script entry point.

## Running Tests

```bash
# Run all tests
make test
# or
pytest

# Run with coverage
make test-cov
# or
pytest --cov=explain_strace --cov-report=html --cov-report=term

# Run with verbose output
pytest -v
```

## Bugs Fixed During Test Development

1. **Hex return value parsing**: Regex alternation order was incorrect, causing hex values like `0x7f...` to match as decimal `0`. Fixed by reordering the regex pattern to check hex before decimal.

2. **Unfinished call handling**: The `explain_parameters` method wasn't checking for unfinished calls before looking for closing parentheses. Fixed by checking for `<unfinished` earlier in the method.

3. **Resumed call handling**: Similar issue - resumed calls don't have opening parentheses. Fixed by checking for `resumed>` marker.
