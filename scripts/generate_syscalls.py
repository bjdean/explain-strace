#!/usr/bin/env python3
"""
Generate syscalls.json from Linux kernel source.

This script parses the Linux kernel syscall tables and merges them with
existing syscall metadata (descriptions, categories) to create an updated
syscalls.json file.

Usage:
    python scripts/generate_syscalls.py /path/to/linux/kernel/source
    python scripts/generate_syscalls.py --from-hardcoded  # Bootstrap from existing code
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set


def parse_kernel_syscall_table(kernel_path: Path, arch: str = "x86_64") -> Dict[str, int]:
    """
    Parse Linux kernel syscall table.

    Args:
        kernel_path: Path to Linux kernel source root
        arch: Architecture (x86_64, x86, arm, etc.)

    Returns:
        Dictionary mapping syscall names to their numbers
    """
    # Map architecture names to kernel paths
    arch_paths = {
        "x86_64": "arch/x86/entry/syscalls/syscall_64.tbl",
        "x86": "arch/x86/entry/syscalls/syscall_32.tbl",
        "arm": "arch/arm/tools/syscall.tbl",
        "arm64": "arch/arm64/include/asm/unistd.h",  # Note: ARM64 uses different format
    }

    if arch not in arch_paths:
        print(f"Error: Unsupported architecture '{arch}'", file=sys.stderr)
        print(f"Supported: {', '.join(arch_paths.keys())}", file=sys.stderr)
        sys.exit(1)

    table_path = kernel_path / arch_paths[arch]

    if not table_path.exists():
        print(f"Error: Syscall table not found at {table_path}", file=sys.stderr)
        sys.exit(1)

    syscalls = {}

    # Parse the table file
    # Format: <number> <abi> <name> <entry point>
    # Example: 0  common  read  sys_read
    with open(table_path) as f:
        for line in f:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Parse table entry
            parts = line.split()
            if len(parts) < 3:
                continue

            try:
                number = int(parts[0])
                # ABI is in parts[1] (common, 64, x32, etc.)
                name = parts[2]

                # For x86_64, prefer 'common' and '64' ABI entries, skip 'x32'
                if arch == "x86_64" and len(parts) > 1:
                    abi = parts[1]
                    if abi == "x32":
                        continue

                syscalls[name] = number
            except (ValueError, IndexError):
                continue

    return syscalls


def get_kernel_version(kernel_path: Path) -> Optional[str]:
    """Extract kernel version from Makefile."""
    makefile = kernel_path / "Makefile"

    if not makefile.exists():
        return None

    version = {}
    with open(makefile) as f:
        for line in f:
            line = line.strip()
            for key in ["VERSION", "PATCHLEVEL", "SUBLEVEL"]:
                if line.startswith(f"{key} ="):
                    version[key] = line.split("=")[1].strip()

    if "VERSION" in version and "PATCHLEVEL" in version:
        v = f"{version['VERSION']}.{version['PATCHLEVEL']}"
        if "SUBLEVEL" in version and version["SUBLEVEL"]:
            v += f".{version['SUBLEVEL']}"
        return v

    return None


def load_existing_syscalls(json_path: Path) -> Dict:
    """Load existing syscalls.json if it exists."""
    if not json_path.exists():
        return {
            "metadata": {
                "kernel_version": None,
                "generated_date": None,
                "architecture": None,
                "source": None,
            },
            "syscalls": {},
        }

    with open(json_path) as f:
        return json.load(f)


def merge_syscalls(
    kernel_syscalls: Dict[str, int],
    existing_data: Dict,
    kernel_version: Optional[str],
    arch: str,
) -> Dict:
    """
    Merge kernel syscalls with existing metadata.

    Detects:
    - New syscalls (in kernel but not in existing)
    - Removed syscalls (in existing but not in kernel)
    - Updated syscall numbers
    """
    kernel_names = set(kernel_syscalls.keys())
    existing_names = set(existing_data["syscalls"].keys())

    # Detect changes
    new_syscalls = kernel_names - existing_names
    removed_syscalls = existing_names - kernel_names
    common_syscalls = kernel_names & existing_names

    # Build updated syscalls dict
    updated_syscalls = {}

    # Process existing syscalls
    for name in common_syscalls:
        existing_entry = existing_data["syscalls"][name]
        updated_syscalls[name] = {
            "number": kernel_syscalls[name],
            "description": existing_entry.get("description", "Unknown system call"),
            "category": existing_entry.get("category", "unknown"),
            "status": existing_entry.get("status", "active"),
        }

        # Preserve additional metadata
        for key in ["first_seen_version", "obsolete_since"]:
            if key in existing_entry:
                updated_syscalls[name][key] = existing_entry[key]

    # Add new syscalls
    for name in new_syscalls:
        updated_syscalls[name] = {
            "number": kernel_syscalls[name],
            "description": "Unknown system call",
            "category": "unknown",
            "status": "new",
            "first_seen_version": kernel_version,
        }

    # Mark removed syscalls
    for name in removed_syscalls:
        existing_entry = existing_data["syscalls"][name]
        updated_syscalls[name] = {
            "number": existing_entry.get("number", -1),
            "description": existing_entry.get("description", "Unknown system call"),
            "category": existing_entry.get("category", "unknown"),
            "status": "removed",
            "removed_version": kernel_version,
        }

    # Build complete data structure
    result = {
        "metadata": {
            "kernel_version": kernel_version,
            "generated_date": datetime.now().strftime("%Y-%m-%d"),
            "architecture": arch,
            "source": "Linux kernel syscall table",
            "previous_version": existing_data["metadata"].get("kernel_version"),
        },
        "syscalls": updated_syscalls,
        "changes": {
            "new": sorted(list(new_syscalls)),
            "removed": sorted(list(removed_syscalls)),
            "total": len(updated_syscalls),
        },
    }

    return result


def bootstrap_from_hardcoded(hardcoded_descriptions: Dict, hardcoded_categories: Dict) -> Dict:
    """
    Bootstrap syscalls.json from hard-coded data in cli.py.

    This is used to create the initial syscalls.json before having kernel source.
    """
    syscalls = {}

    for name, description in hardcoded_descriptions.items():
        syscalls[name] = {
            "number": -1,  # Unknown, will be filled from kernel
            "description": description,
            "category": hardcoded_categories.get(name, "unknown"),
            "status": "active",
        }

    return {
        "metadata": {
            "kernel_version": "unknown",
            "generated_date": datetime.now().strftime("%Y-%m-%d"),
            "architecture": "x86_64",
            "source": "Bootstrapped from hard-coded data",
        },
        "syscalls": syscalls,
        "changes": {
            "new": [],
            "removed": [],
            "total": len(syscalls),
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate syscalls.json from Linux kernel source",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate from kernel source
  python scripts/generate_syscalls.py /usr/src/linux-6.11.0

  # Generate from kernel source with specific architecture
  python scripts/generate_syscalls.py /usr/src/linux-6.11.0 --arch x86_64

  # Bootstrap from hard-coded data in cli.py
  python scripts/generate_syscalls.py --from-hardcoded
        """,
    )

    parser.add_argument(
        "kernel_path",
        nargs="?",
        type=Path,
        help="Path to Linux kernel source root",
    )

    parser.add_argument(
        "--arch",
        default="x86_64",
        choices=["x86_64", "x86", "arm", "arm64"],
        help="Target architecture (default: x86_64)",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("src/explain_strace/syscalls.json"),
        help="Output path for syscalls.json (default: src/explain_strace/syscalls.json)",
    )

    parser.add_argument(
        "--from-hardcoded",
        action="store_true",
        help="Bootstrap from hard-coded data in cli.py (used for initial generation)",
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.from_hardcoded and not args.kernel_path:
        parser.error("Either provide kernel_path or use --from-hardcoded")

    if args.from_hardcoded:
        # Import from cli.py
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from explain_strace.cli import SYSCALL_DESCRIPTIONS, SYSCALL_CATEGORIES

        print("Bootstrapping from hard-coded data...")
        data = bootstrap_from_hardcoded(SYSCALL_DESCRIPTIONS, SYSCALL_CATEGORIES)
    else:
        kernel_path = args.kernel_path

        if not kernel_path.exists():
            print(f"Error: Kernel path does not exist: {kernel_path}", file=sys.stderr)
            sys.exit(1)

        print(f"Parsing kernel syscall table from {kernel_path}...")

        # Get kernel version
        kernel_version = get_kernel_version(kernel_path)
        if kernel_version:
            print(f"Detected kernel version: {kernel_version}")
        else:
            print("Warning: Could not detect kernel version", file=sys.stderr)

        # Parse syscall table
        kernel_syscalls = parse_kernel_syscall_table(kernel_path, args.arch)
        print(f"Found {len(kernel_syscalls)} syscalls in kernel")

        # Load existing data
        existing_data = load_existing_syscalls(args.output)
        if existing_data["syscalls"]:
            prev_version = existing_data["metadata"].get("kernel_version")
            print(f"Loaded existing data (previous version: {prev_version})")

        # Merge
        print("Merging with existing metadata...")
        data = merge_syscalls(kernel_syscalls, existing_data, kernel_version, args.arch)

        # Report changes
        if data["changes"]["new"]:
            print(f"\nNew syscalls ({len(data['changes']['new'])}):")
            for name in data["changes"]["new"]:
                print(f"  + {name}")

        if data["changes"]["removed"]:
            print(f"\nRemoved syscalls ({len(data['changes']['removed'])}):")
            for name in data["changes"]["removed"]:
                print(f"  - {name}")

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)

    print(f"\nWrote {len(data['syscalls'])} syscalls to {args.output}")
    print(f"Architecture: {data['metadata']['architecture']}")
    print(f"Kernel version: {data['metadata']['kernel_version']}")


if __name__ == "__main__":
    main()
