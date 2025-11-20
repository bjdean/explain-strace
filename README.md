# explain-strace

Parse and explain strace output with human-readable descriptions.

## Features

- One-line description for each system call
- Summarise the details of the call
- Summary statistics of all system calls
- Reads strace output from file or stdin
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

### Show details only once per syscall type
When analyzing output with many repeated syscalls, use `--once` to see the full explanation only the first time each syscall appears:
```bash
# Show full details only for the first occurrence of each syscall
strace ls 2>&1 | explain-strace --once
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
System Call      Count  Category    Description
----------------------------------------------------------------------
mmap             18  memory      Map files or devices into memory
close             9  filesystem  Close a file descriptor
fstat             8  filesystem  Get file status by file descriptor
openat            7  filesystem  Open a file relative to a directory file descriptor
mprotect          5  memory      Set protection on region of memory
read              5  filesystem  Read from a file descriptor
brk               3  memory      Change data segment size
access            2  filesystem  Check user permissions for a file
getdents64        2  filesystem  Get directory entries (64-bit)
pread64           2  filesystem  Read from file descriptor at offset
statfs            2  filesystem  Get filesystem statistics
arch_prctl        1  process     Set architecture-specific thread state
execve            1  process     Execute program
exit_group        1  process     Terminate all threads in process
getrandom         1  system      Get random bytes
ioctl             1  device      Control device
munmap            1  memory      Unmap files or devices from memory
prlimit64         1  system      Get/set resource limits
rseq              1  process     Register restartable sequence
set_robust_list   1  ipc         Set robust futex list
set_tid_address   1  process     Set pointer to thread ID
write             1  filesystem  Write to a file descriptor
----------------------------------------------------------------------
Total: 74 calls across 22 unique system calls

======================================================================
SUMMARY BY CATEGORY
======================================================================
Category    Count
----------------------------------------------------------------------
filesystem  38
memory      27
process      5
system       2
device       1
ipc          1
----------------------------------------------------------------------
Total: 74 calls across 6 categories

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

### Reduce output verbosity
```bash
# Only show detailed explanations for the first occurrence of each syscall type
strace ./myprogram 2>&1 | explain-strace --once
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

- Python 3.9+
- No external dependencies

## Implementation Details

The script includes descriptions for 300+ Linux system calls and handles:
- Standard syscall format: `syscall(args) = retval`
- Unfinished calls: `syscall(args <unfinished ...>`
- Resumed calls: `<... syscall resumed> ...)`
- Timestamps and PIDs in strace output
- Signal interruption (Ctrl-C)

### System Call Data Management

System call data is managed through a JSON file (`src/explain_strace/syscalls.json`) that can be generated from Linux kernel source. This allows:
- Easy updates when kernel adds/removes syscalls
- Detection of new, removed, or obsolete syscalls
- Warnings in verbose mode about syscall status
- Tracking of syscall changes across kernel versions

See [SYSCALLS.md](SYSCALLS.md) for detailed documentation on updating syscall data from kernel source.

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
