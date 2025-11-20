# explain-strace

Parse and explain strace output with human-readable descriptions.

## Features

- Read strace output from file or stdin
- One-line description for each system call
- Multiple verbosity levels for detailed information
- Summary statistics of all system calls
- Graceful Ctrl-C handling when reading from stdin
- Filter by system call categories (filesystem, network, memory, etc.)

## Installation

### From PyPI (when published)

```bash
pip install explain-strace
```

### From source

```bash
git clone https://github.com/bjdean/explain-strace.git
cd explain-strace
pip install -e .
```

### For development

```bash
git clone https://github.com/bjdean/explain-strace.git
cd explain-strace
pip install -e ".[dev]"
```

## Usage

### Basic usage (from stdin)
```bash
strace ls /tmp 2>&1 | explain-strace
```

### Read from file
```bash
strace ls /tmp 2>&1 > output.txt
explain-strace output.txt
```

### Verbose mode (documentation links)
```bash
strace ls 2>&1 | explain-strace -v
```

### Filter by category
Filter the output to show only specific categories of system calls:
```bash
# Capture all syscalls, but only display filesystem-related ones
strace ls 2>&1 | explain-strace --filter filesystem

# Or filter by network calls
strace wget http://example.com 2>&1 | explain-strace --filter network
```

**Note:** You can also filter at the strace level using `-e trace=...`, but this loses information about other syscalls that may be important for debugging:
```bash
# This only captures filesystem calls - you won't see network/memory operations
strace -e trace=open,openat,read,write ls 2>&1 | explain-strace
```

### Interrupt stdin reading
When reading from stdin, press Ctrl-C to stop reading and display the summary. For example to strace a running process with PID 1234:
```bash
strace -p 1234 2>&1 | explain-strace
# Press Ctrl-C to stop and see summary
```

## Verbosity Levels

| Level | Flag | Output |
|-------|------|--------|
| 0     | (none) | Original strace line + category + description + return value |
| 1     | `-v` | All of the above + link to man page documentation |

## Output Format

### Basic output (verbosity 0)
```
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
 - Category: filesystem
 - Description: Open file relative to a directory file descriptor
 - Returned: 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0"..., 832) = 832
 - Category: filesystem
 - Description: Read from a file descriptor
 - Returned: 832
close(3) = 0
 - Category: filesystem
 - Description: Close a file descriptor
 - Returned: 0
```

### Verbose output (verbosity 1: `-v`)
Adds documentation links to man pages:
```
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
 - Category: filesystem
 - Description: Open file relative to a directory file descriptor
 - Returned: 3
 - Documentation: https://man7.org/linux/man-pages/man2/openat.2.html
```

### Summary
At the end of processing, a summary is displayed showing all system calls and their counts:
```
======================================================================
SUMMARY OF SYSTEM CALLS
======================================================================
System Call  Count  Description
----------------------------------------------------------------------
close        7      Close a file descriptor
openat       7      Open file relative to a directory file descriptor
read         5      Read from a file descriptor
write        1      Write to a file descriptor
----------------------------------------------------------------------
Total: 20 calls across 4 unique system calls

======================================================================
SUMMARY BY CATEGORY
======================================================================
Category      Count
----------------------------------------------------------------------
filesystem    20
----------------------------------------------------------------------
Total: 20 calls across 1 categories
```

## Examples

### Debug a program
```bash
strace -o trace.txt ./myprogram
explain-strace trace.txt
```

### Monitor a running process
```bash
# In one terminal
strace -p 1234 2>&1 | explain-strace -v

# Press Ctrl-C when done
```

### Filter by category (alternative approach)
```bash
# Capture everything, filter during analysis - preserves full context
strace ./myprogram 2>&1 | explain-strace --filter filesystem
```

### Reduce strace output size (use with caution)
If you only want to capture specific syscalls at the strace level (useful for very high-volume traces):
```bash
# Only captures specific syscalls - loses context from other operations
strace -e trace=open,openat,read,write ls 2>&1 | explain-strace
```

### List available categories
```bash
explain-strace --catlist
```

## Requirements

- Python 3.8+
- No external dependencies

## Implementation Details

The script includes descriptions for 300+ Linux system calls and handles:
- Standard syscall format: `syscall(args) = retval`
- Unfinished calls: `syscall(args <unfinished ...>`
- Resumed calls: `<... syscall resumed> ...)`
- Timestamps and PIDs in strace output
- Signal interruption (Ctrl-C)

## Development

### Running tests

```bash
make test
```

### Running tests with coverage

```bash
make test-cov
```

### Linting

```bash
make lint
```

### Formatting

```bash
make format
```

### Running all checks

```bash
make check
```

## License

MIT License - see [LICENSE](LICENSE) file for details.
