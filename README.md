# explain_strace.py

Parse and explain strace output with human-readable descriptions.

## Features

- Read strace output from file or stdin
- One-line description for each system call
- Multiple verbosity levels for detailed information
- Summary statistics of all system calls
- Graceful Ctrl-C handling when reading from stdin

## Usage

### Basic usage (from stdin)
```bash
strace ls /tmp 2>&1 | python3 explain_strace.py
```

### Read from file
```bash
strace ls /tmp 2>&1 > output.txt
python3 explain_strace.py output.txt
```

### Verbose mode (documentation links)
```bash
strace ls 2>&1 | python3 explain_strace.py -v
```

### More verbose (parameter descriptions)
```bash
strace ls 2>&1 | python3 explain_strace.py -vv
```

### Maximum verbosity (original strace line)
```bash
strace ls 2>&1 | python3 explain_strace.py -vvv
```

### Interrupt stdin reading
When reading from stdin, press Ctrl-C to stop reading and display the summary:
```bash
strace -p 1234 2>&1 | python3 explain_strace.py
# Press Ctrl-C to stop and see summary
```

## Verbosity Levels

| Level | Flag    | Output |
|-------|---------|--------|
| 0     | (none)  | System call name, description, and return value |
| 1     | `-v`    | + Link to man page documentation |
| 2     | `-vv`   | + Parameter descriptions |
| 3     | `-vvv`  | + Original strace line |

## Output Format

### Basic output
```
openat               - Open file relative to directory [returned: 3]
read                 - Read from a file descriptor [returned: 832]
close                - Close a file descriptor [returned: 0]
```

### Verbose output (-vv)
```
openat               - Open file relative to directory [returned: 3]
  Documentation: https://man7.org/linux/man-pages/man2/openat.2.html
  Parameters: AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC
```

### Summary
```
======================================================================
SUMMARY OF SYSTEM CALLS
======================================================================
System Call  Count  Description
----------------------------------------------------------------------
close   7  Close a file descriptor
openat  7  Open file relative to directory
read    5  Read from a file descriptor
write   1  Write to a file descriptor
----------------------------------------------------------------------
Total: 20 calls across 4 unique system calls
```

## Examples

### Debug a program
```bash
strace -o trace.txt ./myprogram
python3 explain_strace.py trace.txt
```

### Monitor a running process
```bash
# In one terminal
strace -p 1234 2>&1 | python3 explain_strace.py -v

# Press Ctrl-C when done
```

### Filter specific syscalls
```bash
strace -e trace=open,openat,read,write ls 2>&1 | python3 explain_strace.py
```

## Requirements

- Python 3.6+
- No external dependencies

## Implementation Details

The script includes descriptions for 300+ Linux system calls and handles:
- Standard syscall format: `syscall(args) = retval`
- Unfinished calls: `syscall(args <unfinished ...>`
- Resumed calls: `<... syscall resumed> ...)`
- Timestamps and PIDs in strace output
- Signal interruption (Ctrl-C)

## License

This tool is provided as-is for educational and debugging purposes.
