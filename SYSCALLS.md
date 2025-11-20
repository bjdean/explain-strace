# System Call Data Management

This document explains how the system call data is managed and how to keep it up to date with the latest Linux kernel.

## Overview

`explain-strace` uses a JSON data file (`src/explain_strace/syscalls.json`) that contains:
- System call names and numbers (from Linux kernel source)
- Human-readable descriptions
- Categories (filesystem, network, memory, etc.)
- Status tracking (active, new, removed, obsolete)

This approach allows the application to:
- Stay current with the latest Linux kernel syscalls
- Detect when syscalls are added or removed
- Warn users about deprecated or new syscalls in verbose mode
- Be easily updated without modifying code

## Data Structure

The `syscalls.json` file has the following structure:

```json
{
  "metadata": {
    "kernel_version": "6.11.0",
    "generated_date": "2025-01-20",
    "architecture": "x86_64",
    "source": "Linux kernel syscall table",
    "previous_version": "6.8.0"
  },
  "syscalls": {
    "open": {
      "number": 2,
      "description": "Open a file or device",
      "category": "filesystem",
      "status": "active"
    },
    "openat2": {
      "number": 437,
      "description": "Open file with extended options",
      "category": "filesystem",
      "status": "new",
      "first_seen_version": "5.6.0"
    }
  },
  "changes": {
    "new": ["openat2", "clone3"],
    "removed": ["oldstat"],
    "total": 354
  }
}
```

### Syscall Status Values

- `active`: Normal, currently supported syscall
- `new`: Recently added syscall (shown with ⚠️ warning in verbose mode)
- `removed`: Syscall removed from kernel (shown with ⚠️ warning in verbose mode)
- `obsolete`: Deprecated syscall still present but discouraged (shown with ⚠️ warning in verbose mode)

## Updating from Linux Kernel Source

### Prerequisites

1. Download or clone the Linux kernel source:
   ```bash
   # Option 1: Download specific version
   wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.11.tar.xz
   tar xf linux-6.11.tar.xz

   # Option 2: Clone the git repository
   git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
   cd linux
   git checkout v6.11
   ```

2. Note the path to the kernel source directory

### Running the Generator Script

The `scripts/generate_syscalls.py` script parses the kernel's syscall table and merges it with existing metadata:

```bash
# Generate for x86_64 (default)
python scripts/generate_syscalls.py /path/to/linux-6.11.0

# Generate for specific architecture
python scripts/generate_syscalls.py /path/to/linux-6.11.0 --arch x86_64
python scripts/generate_syscalls.py /path/to/linux-6.11.0 --arch x86
python scripts/generate_syscalls.py /path/to/linux-6.11.0 --arch arm

# Specify output location
python scripts/generate_syscalls.py /path/to/linux-6.11.0 --output custom_path.json
```

### What the Generator Does

1. **Parses kernel syscall table** - Reads the authoritative syscall list from:
   - x86_64: `arch/x86/entry/syscalls/syscall_64.tbl`
   - x86: `arch/x86/entry/syscalls/syscall_32.tbl`
   - ARM: `arch/arm/tools/syscall.tbl`

2. **Detects kernel version** - Extracts version from kernel `Makefile`

3. **Merges with existing data**:
   - Updates syscall numbers from kernel source
   - Preserves human-curated descriptions and categories
   - Marks new syscalls (in kernel but not in old data)
   - Marks removed syscalls (in old data but not in kernel)

4. **Reports changes**:
   ```
   Parsing kernel syscall table from /usr/src/linux-6.11.0...
   Detected kernel version: 6.11.0
   Found 354 syscalls in kernel
   Loaded existing data (previous version: 6.8.0)

   New syscalls (2):
     + map_shadow_stack
     + futex_requeue

   Removed syscalls (1):
     - oldstat

   Wrote 355 syscalls to src/explain_strace/syscalls.json
   ```

## Adding Descriptions and Categories

After generating from kernel source, new syscalls will have:
- `description`: "Unknown system call"
- `category`: "unknown"
- `status`: "new"

You should manually edit `syscalls.json` to add proper descriptions and categories for new syscalls.

### Category Options

- `filesystem` - File and directory operations
- `network` - Socket and network operations
- `memory` - Memory management
- `process` - Process/thread management
- `signal` - Signal handling
- `scheduling` - Process scheduling
- `time` - Time and timer operations
- `ipc` - Inter-process communication
- `security` - Security and permissions
- `device` - Device control
- `async_io` - Asynchronous I/O
- `system` - System information and control

### Example Edit

```json
{
  "map_shadow_stack": {
    "number": 453,
    "description": "Map shadow stack for control-flow integrity",
    "category": "memory",
    "status": "active",
    "first_seen_version": "6.6.0"
  }
}
```

## Marking Syscalls as Obsolete

If a syscall is deprecated but not yet removed from the kernel, mark it as obsolete:

```json
{
  "_sysctl": {
    "number": 156,
    "description": "Read/write system parameters (obsolete)",
    "category": "system",
    "status": "obsolete",
    "obsolete_since": "5.5.0"
  }
}
```

## Testing After Updates

After updating `syscalls.json`:

1. **Run the test suite**:
   ```bash
   make test
   ```

2. **Test with real strace output**:
   ```bash
   strace ls 2>&1 | python -m explain_strace.cli
   ```

3. **Check verbose mode warnings**:
   ```bash
   strace ls 2>&1 | python -m explain_strace.cli -v
   ```

4. **Verify categories**:
   ```bash
   python -m explain_strace.cli --catlist
   ```

## Bootstrap Process (First Time Setup)

If you're setting up this feature for the first time without kernel source:

```bash
# Create initial syscalls.json from hard-coded data in cli.py
python scripts/generate_syscalls.py --from-hardcoded
```

This creates a starting point that can later be updated from kernel source.

## Continuous Updates

To keep syscalls current:

1. **Set up a periodic update schedule** (e.g., when new kernel releases)
2. **Run the generator** with the latest kernel source
3. **Review and document new syscalls**
4. **Update descriptions and categories** for any "unknown" entries
5. **Test thoroughly**
6. **Commit changes** to version control

## Fallback Behavior

If `syscalls.json` is missing or corrupted, the application falls back to hard-coded dictionaries in `cli.py`. However, you'll lose:
- Syscall status tracking (new/removed/obsolete warnings)
- Up-to-date syscall numbers
- Easy maintenance

## Troubleshooting

### "Syscall table not found"

The kernel path is incorrect or doesn't contain the expected architecture:
```bash
# Verify the path exists
ls /path/to/linux/arch/x86/entry/syscalls/syscall_64.tbl
```

### "Could not detect kernel version"

The `Makefile` is missing or malformed. You can still generate without version info:
```bash
python scripts/generate_syscalls.py /path/to/linux
# Check the output - version will be "None"
```

### Missing syscalls in output

The parser may not handle all architectures. Check:
- Architecture support in `generate_syscalls.py`
- Syscall table format for your architecture

## Contributing

When contributing syscall updates:

1. Update from the latest **stable** kernel release
2. Include kernel version in commit message
3. Ensure all new syscalls have descriptions and categories
4. Run tests before submitting
5. Document any unusual syscalls in commit message

Example commit:
```
Update syscalls from Linux kernel 6.11.0

- Added 2 new syscalls: map_shadow_stack, futex_requeue
- Marked oldstat as removed
- Updated descriptions for shadow stack syscalls
```
