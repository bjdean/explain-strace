#!/usr/bin/env python3
"""
explain_strace.py - Parse and explain strace output

Reads strace output from a file or stdin and provides human-readable explanations
of each system call, with optional verbose modes for additional details.
"""

import sys
import re
import argparse
import signal
from typing import Dict, List, Tuple, Optional
from collections import Counter


# System call descriptions
SYSCALL_DESCRIPTIONS = {
    'open': 'Open a file or device',
    'openat': 'Open a file relative to a directory file descriptor',
    'close': 'Close a file descriptor',
    'read': 'Read from a file descriptor',
    'write': 'Write to a file descriptor',
    'stat': 'Get file status',
    'fstat': 'Get file status by file descriptor',
    'lstat': 'Get file status (do not follow symlinks)',
    'newfstatat': 'Get file status relative to directory file descriptor',
    'statx': 'Get extended file status',
    'poll': 'Wait for events on file descriptors',
    'lseek': 'Reposition file offset',
    'mmap': 'Map files or devices into memory',
    'mprotect': 'Set protection on region of memory',
    'munmap': 'Unmap files or devices from memory',
    'brk': 'Change data segment size',
    'rt_sigaction': 'Examine/change signal action',
    'rt_sigprocmask': 'Examine/change blocked signals',
    'rt_sigreturn': 'Return from signal handler',
    'ioctl': 'Control device',
    'pread64': 'Read from file descriptor at offset',
    'pwrite64': 'Write to file descriptor at offset',
    'readv': 'Read data into multiple buffers',
    'writev': 'Write data from multiple buffers',
    'access': 'Check user permissions for a file',
    'faccessat': 'Check user permissions relative to directory',
    'faccessat2': 'Check user permissions with flags',
    'pipe': 'Create pipe',
    'pipe2': 'Create pipe with flags',
    'select': 'Synchronous I/O multiplexing',
    'sched_yield': 'Yield the processor',
    'mremap': 'Remap virtual memory',
    'msync': 'Synchronize memory with physical storage',
    'mincore': 'Determine whether pages are in memory',
    'madvise': 'Give advice about use of memory',
    'shmget': 'Allocate shared memory segment',
    'shmat': 'Attach shared memory segment',
    'shmctl': 'Control shared memory segment',
    'dup': 'Duplicate file descriptor',
    'dup2': 'Duplicate file descriptor to specific number',
    'dup3': 'Duplicate file descriptor with flags',
    'pause': 'Wait for signal',
    'nanosleep': 'High-resolution sleep',
    'getitimer': 'Get value of interval timer',
    'alarm': 'Set alarm clock for delivery of signal',
    'setitimer': 'Set value of interval timer',
    'getpid': 'Get process ID',
    'sendfile': 'Transfer data between file descriptors',
    'socket': 'Create endpoint for communication',
    'connect': 'Initiate connection on socket',
    'accept': 'Accept connection on socket',
    'accept4': 'Accept connection with flags',
    'sendto': 'Send message on socket',
    'recvfrom': 'Receive message from socket',
    'sendmsg': 'Send message on socket (complex)',
    'recvmsg': 'Receive message from socket (complex)',
    'shutdown': 'Shut down part of full-duplex connection',
    'bind': 'Bind name to socket',
    'listen': 'Listen for connections on socket',
    'getsockname': 'Get socket name',
    'getpeername': 'Get name of connected peer',
    'socketpair': 'Create pair of connected sockets',
    'setsockopt': 'Set socket options',
    'getsockopt': 'Get socket options',
    'clone': 'Create child process',
    'clone3': 'Create child process (extended)',
    'fork': 'Create child process',
    'vfork': 'Create child process (shares memory)',
    'execve': 'Execute program',
    'exit': 'Terminate calling process',
    'exit_group': 'Terminate all threads in process',
    'wait4': 'Wait for process to change state',
    'waitid': 'Wait for process to change state (extended)',
    'kill': 'Send signal to process',
    'uname': 'Get name and information about kernel',
    'semget': 'Get semaphore set identifier',
    'semop': 'Semaphore operations',
    'semctl': 'Control semaphore set',
    'shmdt': 'Detach shared memory segment',
    'msgget': 'Get message queue identifier',
    'msgsnd': 'Send message to queue',
    'msgrcv': 'Receive message from queue',
    'msgctl': 'Control message queue',
    'fcntl': 'Manipulate file descriptor',
    'flock': 'Apply or remove advisory lock on file',
    'fsync': 'Synchronize file with storage',
    'fdatasync': 'Synchronize file data with storage',
    'truncate': 'Truncate file to specified length',
    'ftruncate': 'Truncate file by descriptor to length',
    'getdents': 'Get directory entries',
    'getdents64': 'Get directory entries (64-bit)',
    'getcwd': 'Get current working directory',
    'chdir': 'Change working directory',
    'fchdir': 'Change working directory by descriptor',
    'rename': 'Rename file',
    'renameat': 'Rename file relative to directory',
    'renameat2': 'Rename file with flags',
    'mkdir': 'Create directory',
    'mkdirat': 'Create directory relative to descriptor',
    'rmdir': 'Remove directory',
    'creat': 'Create file',
    'link': 'Create hard link',
    'linkat': 'Create hard link relative to directory',
    'unlink': 'Remove file',
    'unlinkat': 'Remove file relative to directory',
    'symlink': 'Create symbolic link',
    'symlinkat': 'Create symbolic link relative to directory',
    'readlink': 'Read value of symbolic link',
    'readlinkat': 'Read symbolic link relative to directory',
    'chmod': 'Change file permissions',
    'fchmod': 'Change file permissions by descriptor',
    'fchmodat': 'Change permissions relative to directory',
    'chown': 'Change file owner and group',
    'fchown': 'Change owner/group by descriptor',
    'lchown': 'Change owner/group (no follow symlinks)',
    'fchownat': 'Change owner/group relative to directory',
    'umask': 'Set file creation mask',
    'gettimeofday': 'Get time',
    'getrlimit': 'Get resource limits',
    'getrusage': 'Get resource usage',
    'sysinfo': 'Get system information',
    'times': 'Get process times',
    'ptrace': 'Process trace',
    'getuid': 'Get user ID',
    'syslog': 'Read/clear kernel message ring buffer',
    'getgid': 'Get group ID',
    'setuid': 'Set user ID',
    'setgid': 'Set group ID',
    'geteuid': 'Get effective user ID',
    'getegid': 'Get effective group ID',
    'setpgid': 'Set process group ID',
    'getppid': 'Get parent process ID',
    'getpgrp': 'Get process group',
    'setsid': 'Create session and set process group ID',
    'setreuid': 'Set real and effective user IDs',
    'setregid': 'Set real and effective group IDs',
    'getgroups': 'Get supplementary group IDs',
    'setgroups': 'Set supplementary group IDs',
    'setresuid': 'Set real, effective, saved user IDs',
    'getresuid': 'Get real, effective, saved user IDs',
    'setresgid': 'Set real, effective, saved group IDs',
    'getresgid': 'Get real, effective, saved group IDs',
    'getpgid': 'Get process group ID',
    'setfsuid': 'Set user ID for filesystem checks',
    'setfsgid': 'Set group ID for filesystem checks',
    'getsid': 'Get session ID',
    'capget': 'Get capabilities of thread',
    'capset': 'Set capabilities of thread',
    'rt_sigpending': 'Examine pending signals',
    'rt_sigtimedwait': 'Wait for queued signals',
    'rt_sigqueueinfo': 'Queue signal and data',
    'rt_sigsuspend': 'Wait for signal',
    'sigaltstack': 'Set/get signal stack context',
    'utime': 'Change file timestamps',
    'mknod': 'Create special/ordinary file',
    'mknodat': 'Create special file relative to directory',
    'uselib': 'Load shared library (obsolete)',
    'personality': 'Set process execution domain',
    'ustat': 'Get filesystem statistics (obsolete)',
    'statfs': 'Get filesystem statistics',
    'fstatfs': 'Get filesystem statistics by descriptor',
    'sysfs': 'Get filesystem type information',
    'getpriority': 'Get program scheduling priority',
    'setpriority': 'Set program scheduling priority',
    'sched_setparam': 'Set scheduling parameters',
    'sched_getparam': 'Get scheduling parameters',
    'sched_setscheduler': 'Set scheduling algorithm/parameters',
    'sched_getscheduler': 'Get scheduling algorithm',
    'sched_get_priority_max': 'Get max static priority',
    'sched_get_priority_min': 'Get min static priority',
    'sched_rr_get_interval': 'Get SCHED_RR interval',
    'mlock': 'Lock memory pages',
    'munlock': 'Unlock memory pages',
    'mlockall': 'Lock all memory pages',
    'munlockall': 'Unlock all memory pages',
    'vhangup': 'Simulate hangup on terminal',
    'modify_ldt': 'Get/set thread local descriptor table',
    'pivot_root': 'Change root filesystem',
    '_sysctl': 'Read/write system parameters (obsolete)',
    'prctl': 'Operations on a process',
    'arch_prctl': 'Set architecture-specific thread state',
    'adjtimex': 'Tune kernel clock',
    'setrlimit': 'Set resource limits',
    'chroot': 'Change root directory',
    'sync': 'Commit filesystem caches to disk',
    'acct': 'Switch process accounting on/off',
    'settimeofday': 'Set time',
    'mount': 'Mount filesystem',
    'umount2': 'Unmount filesystem',
    'swapon': 'Start swapping to file/device',
    'swapoff': 'Stop swapping to file/device',
    'reboot': 'Reboot or enable/disable Ctrl-Alt-Del',
    'sethostname': 'Set hostname',
    'setdomainname': 'Set NIS domain name',
    'iopl': 'Change I/O privilege level',
    'ioperm': 'Set port I/O permissions',
    'create_module': 'Create loadable module (obsolete)',
    'init_module': 'Load kernel module',
    'delete_module': 'Unload kernel module',
    'get_kernel_syms': 'Get exported kernel symbols (obsolete)',
    'query_module': 'Query module (obsolete)',
    'quotactl': 'Manipulate disk quotas',
    'nfsservctl': 'NFS daemon operations (obsolete)',
    'getpmsg': 'Get STREAMS message (unimplemented)',
    'putpmsg': 'Send STREAMS message (unimplemented)',
    'afs_syscall': 'AFS system call (unimplemented)',
    'tuxcall': 'Tux system call (unimplemented)',
    'security': 'Security system call (unimplemented)',
    'gettid': 'Get thread ID',
    'readahead': 'Initiate file readahead',
    'setxattr': 'Set extended attribute',
    'lsetxattr': 'Set extended attribute (no follow symlinks)',
    'fsetxattr': 'Set extended attribute by descriptor',
    'getxattr': 'Get extended attribute',
    'lgetxattr': 'Get extended attribute (no follow symlinks)',
    'fgetxattr': 'Get extended attribute by descriptor',
    'listxattr': 'List extended attributes',
    'llistxattr': 'List extended attributes (no follow symlinks)',
    'flistxattr': 'List extended attributes by descriptor',
    'removexattr': 'Remove extended attribute',
    'lremovexattr': 'Remove extended attribute (no follow symlinks)',
    'fremovexattr': 'Remove extended attribute by descriptor',
    'tkill': 'Send signal to thread',
    'time': 'Get time in seconds',
    'futex': 'Fast userspace mutex',
    'sched_setaffinity': 'Set CPU affinity mask',
    'sched_getaffinity': 'Get CPU affinity mask',
    'set_thread_area': 'Set thread local storage',
    'io_setup': 'Create async I/O context',
    'io_destroy': 'Destroy async I/O context',
    'io_getevents': 'Get async I/O events',
    'io_submit': 'Submit async I/O',
    'io_cancel': 'Cancel async I/O',
    'get_thread_area': 'Get thread local storage',
    'lookup_dcookie': 'Get directory entry cookie',
    'epoll_create': 'Create epoll file descriptor',
    'epoll_ctl_old': 'Control epoll descriptor (old)',
    'epoll_wait_old': 'Wait for epoll events (old)',
    'remap_file_pages': 'Create nonlinear file mapping',
    'getdents64': 'Get directory entries (64-bit)',
    'set_tid_address': 'Set pointer to thread ID',
    'restart_syscall': 'Restart system call after interruption',
    'semtimedop': 'Semaphore operations with timeout',
    'fadvise64': 'Predeclare access pattern for file data',
    'timer_create': 'Create POSIX per-process timer',
    'timer_settime': 'Arm/disarm POSIX timer',
    'timer_gettime': 'Fetch state of POSIX timer',
    'timer_getoverrun': 'Get overrun count for POSIX timer',
    'timer_delete': 'Delete POSIX timer',
    'clock_settime': 'Set time of clock',
    'clock_gettime': 'Get time of clock',
    'clock_getres': 'Get resolution of clock',
    'clock_nanosleep': 'High-resolution sleep with clock',
    'exit_group': 'Exit all threads in process',
    'epoll_wait': 'Wait for epoll events',
    'epoll_ctl': 'Control epoll descriptor',
    'tgkill': 'Send signal to thread in thread group',
    'utimes': 'Change file timestamps',
    'vserver': 'Linux virtual server (unimplemented)',
    'mbind': 'Set memory policy for range',
    'set_mempolicy': 'Set default NUMA memory policy',
    'get_mempolicy': 'Get NUMA memory policy',
    'mq_open': 'Open message queue',
    'mq_unlink': 'Remove message queue',
    'mq_timedsend': 'Send message to queue with timeout',
    'mq_timedreceive': 'Receive message with timeout',
    'mq_notify': 'Register for notification',
    'mq_getsetattr': 'Get/set message queue attributes',
    'kexec_load': 'Load new kernel for later execution',
    'waitid': 'Wait for process state change',
    'add_key': 'Add key to kernel key management',
    'request_key': 'Request key from kernel',
    'keyctl': 'Manipulate kernel key management',
    'ioprio_set': 'Set I/O scheduling priority',
    'ioprio_get': 'Get I/O scheduling priority',
    'inotify_init': 'Initialize inotify instance',
    'inotify_add_watch': 'Add watch to inotify instance',
    'inotify_rm_watch': 'Remove watch from inotify instance',
    'migrate_pages': 'Move pages between NUMA nodes',
    'openat': 'Open file relative to directory',
    'mkdirat': 'Create directory relative to directory',
    'mknodat': 'Create special file relative to directory',
    'fchownat': 'Change owner relative to directory',
    'futimesat': 'Change timestamps relative to directory',
    'newfstatat': 'Get file status relative to directory',
    'unlinkat': 'Remove file relative to directory',
    'renameat': 'Rename file relative to directory',
    'linkat': 'Create hard link relative to directory',
    'symlinkat': 'Create symbolic link relative to directory',
    'readlinkat': 'Read symbolic link relative to directory',
    'fchmodat': 'Change permissions relative to directory',
    'faccessat': 'Check permissions relative to directory',
    'pselect6': 'Synchronous I/O multiplexing with signal mask',
    'ppoll': 'Wait for events with signal mask',
    'unshare': 'Disassociate parts of process context',
    'set_robust_list': 'Set robust futex list',
    'get_robust_list': 'Get robust futex list',
    'splice': 'Splice data to/from pipe',
    'tee': 'Duplicate pipe content',
    'sync_file_range': 'Sync file region with disk',
    'vmsplice': 'Splice user pages into pipe',
    'move_pages': 'Move pages between processes/nodes',
    'utimensat': 'Change timestamps with nanosecond precision',
    'epoll_pwait': 'Wait for epoll events with signal mask',
    'signalfd': 'Create file descriptor for signals',
    'timerfd_create': 'Create timer as file descriptor',
    'eventfd': 'Create file descriptor for event notification',
    'fallocate': 'Allocate space for file',
    'timerfd_settime': 'Set timer via file descriptor',
    'timerfd_gettime': 'Get timer via file descriptor',
    'accept4': 'Accept connection with flags',
    'signalfd4': 'Create signal file descriptor with flags',
    'eventfd2': 'Create event file descriptor with flags',
    'epoll_create1': 'Create epoll descriptor with flags',
    'dup3': 'Duplicate file descriptor with flags',
    'pipe2': 'Create pipe with flags',
    'inotify_init1': 'Initialize inotify with flags',
    'preadv': 'Read into multiple buffers at offset',
    'pwritev': 'Write from multiple buffers at offset',
    'rt_tgsigqueueinfo': 'Queue signal to thread group',
    'perf_event_open': 'Open performance monitoring event',
    'recvmmsg': 'Receive multiple messages',
    'fanotify_init': 'Initialize fanotify',
    'fanotify_mark': 'Add/remove/flush fanotify marks',
    'prlimit64': 'Get/set resource limits',
    'name_to_handle_at': 'Get handle for pathname',
    'open_by_handle_at': 'Open file via handle',
    'clock_adjtime': 'Adjust clock',
    'syncfs': 'Sync filesystem containing file',
    'sendmmsg': 'Send multiple messages',
    'setns': 'Join namespace',
    'getcpu': 'Get CPU and NUMA node',
    'process_vm_readv': 'Read from another process memory',
    'process_vm_writev': 'Write to another process memory',
    'kcmp': 'Compare kernel resources',
    'finit_module': 'Load kernel module from file descriptor',
    'sched_setattr': 'Set scheduling attributes',
    'sched_getattr': 'Get scheduling attributes',
    'renameat2': 'Rename with flags',
    'seccomp': 'Set secure computing mode',
    'getrandom': 'Get random bytes',
    'memfd_create': 'Create anonymous file',
    'kexec_file_load': 'Load new kernel from file descriptor',
    'bpf': 'Perform BPF command',
    'execveat': 'Execute program relative to directory',
    'userfaultfd': 'Create userfaultfd object',
    'membarrier': 'Issue memory barriers',
    'mlock2': 'Lock memory with flags',
    'copy_file_range': 'Copy range between files',
    'preadv2': 'Read into multiple buffers with flags',
    'pwritev2': 'Write from multiple buffers with flags',
    'pkey_mprotect': 'Set protection with memory protection key',
    'pkey_alloc': 'Allocate memory protection key',
    'pkey_free': 'Free memory protection key',
    'statx': 'Get extended file status',
    'io_pgetevents': 'Get async I/O events with signal',
    'rseq': 'Register restartable sequence',
    'pidfd_send_signal': 'Send signal to process via file descriptor',
    'io_uring_setup': 'Setup io_uring context',
    'io_uring_enter': 'Submit/wait for io_uring requests',
    'io_uring_register': 'Register io_uring resources',
    'open_tree': 'Open filesystem tree',
    'move_mount': 'Move mount point',
    'fsopen': 'Open filesystem context',
    'fsconfig': 'Configure filesystem context',
    'fsmount': 'Create mount from filesystem context',
    'fspick': 'Pick existing filesystem',
    'pidfd_open': 'Open process as file descriptor',
    'clone3': 'Create child process with extended options',
    'close_range': 'Close range of file descriptors',
    'openat2': 'Open file with extended options',
    'pidfd_getfd': 'Get file descriptor from another process',
    'faccessat2': 'Check permissions with flags',
    'process_madvise': 'Give memory advice for another process',
    'epoll_pwait2': 'Wait for epoll events with timespec',
    'mount_setattr': 'Change mount attributes',
}

# Documentation base URLs
MANPAGE_BASE = "https://man7.org/linux/man-pages/man2"


class StraceExplainer:
    """Parse and explain strace output."""

    def __init__(self, verbosity: int = 0):
        self.verbosity = verbosity
        self.syscall_counts: Counter = Counter()
        self.interrupted = False

        # Regex to match strace lines
        # Matches: syscall(args) = retval
        # or: syscall(args) = retval <extra>
        # or: syscall(args <unfinished ...>
        # or: <... syscall resumed>...
        self.syscall_pattern = re.compile(
            r'^(?:\d+\s+)?'  # Optional PID
            r'(?:\[\d+:\d+:\d+(?:\.\d+)?\]\s+)?'  # Optional timestamp
            r'(?:<\.\.\.\s+(\w+)\s+resumed>|'  # Resumed call
            r'(\w+)\()'  # Or regular call
        )

        # Extract syscall name and result
        self.result_pattern = re.compile(r'=\s*(-?\d+|0x[0-9a-fA-F]+|\?)')

    def setup_signal_handler(self):
        """Setup Ctrl-C handler for graceful interruption."""
        def signal_handler(signum, frame):
            self.interrupted = True
            print("\n[Interrupted - finishing up...]", file=sys.stderr)

        signal.signal(signal.SIGINT, signal_handler)

    def parse_line(self, line: str) -> Optional[Tuple[str, str, Optional[str]]]:
        """
        Parse a single strace line.

        Returns:
            Tuple of (syscall_name, full_line, result) or None if not a syscall line
        """
        line = line.strip()
        if not line:
            return None

        # Try to match syscall pattern
        match = self.syscall_pattern.search(line)
        if not match:
            return None

        # Get syscall name (either from resumed or regular)
        syscall_name = match.group(1) or match.group(2)
        if not syscall_name:
            return None

        # Extract result if present
        result_match = self.result_pattern.search(line)
        result = result_match.group(1) if result_match else None

        return (syscall_name, line, result)

    def get_syscall_description(self, syscall: str) -> str:
        """Get one-line description of syscall."""
        return SYSCALL_DESCRIPTIONS.get(syscall, "Unknown system call")

    def get_manpage_url(self, syscall: str) -> str:
        """Get URL to man page for syscall."""
        return f"{MANPAGE_BASE}/{syscall}.2.html"

    def explain_parameters(self, line: str, syscall: str) -> str:
        """
        Extract and explain parameters from syscall line.
        Returns a formatted string explaining parameters.
        """
        # Try to extract parameters from the line
        # This is a simplified version - full parameter parsing would be complex
        paren_start = line.find('(')
        paren_end = line.rfind(')')

        if paren_start == -1 or paren_end == -1:
            return "Parameter description unavailable"

        params = line[paren_start+1:paren_end]

        # For unfinished calls
        if '<unfinished' in params:
            return "Call unfinished (continued in next line)"

        # For resumed calls
        if params.startswith('...'):
            return "Call resumed from previous line"

        # Truncate very long parameter lists
        if len(params) > 200:
            params = params[:197] + "..."

        return f"Parameters: {params}"

    def explain_line(self, line: str) -> None:
        """Parse and explain a single strace line."""
        parsed = self.parse_line(line)
        if not parsed:
            # Not a syscall line, skip silently
            return

        syscall, full_line, result = parsed
        self.syscall_counts[syscall] += 1

        # Basic output: syscall and description
        description = self.get_syscall_description(syscall)
        output = f"{syscall:20s} - {description}"

        # Add result if available
        if result:
            output += f" [returned: {result}]"

        print(output)

        # Verbose mode: add documentation link
        if self.verbosity >= 1:
            manpage_url = self.get_manpage_url(syscall)
            print(f"  Documentation: {manpage_url}")

        # More verbose: add parameter explanation
        if self.verbosity >= 2:
            param_desc = self.explain_parameters(full_line, syscall)
            print(f"  {param_desc}")

        # Even more verbose: show original line
        if self.verbosity >= 3:
            print(f"  Original: {full_line}")

    def print_summary(self) -> None:
        """Print summary of system calls seen."""
        if not self.syscall_counts:
            print("\nNo system calls found in input.")
            return

        print("\n" + "="*70)
        print("SUMMARY OF SYSTEM CALLS")
        print("="*70)

        # Sort by count (descending) then by name
        sorted_calls = sorted(
            self.syscall_counts.items(),
            key=lambda x: (-x[1], x[0])
        )

        # Calculate column widths
        max_name_len = max(len(name) for name, _ in sorted_calls)
        max_count_len = max(len(str(count)) for _, count in sorted_calls)

        print(f"{'System Call':<{max_name_len}}  {'Count':>{max_count_len}}  Description")
        print("-" * 70)

        for syscall, count in sorted_calls:
            desc = self.get_syscall_description(syscall)
            print(f"{syscall:<{max_name_len}}  {count:>{max_count_len}}  {desc}")

        total = sum(self.syscall_counts.values())
        unique = len(self.syscall_counts)
        print("-" * 70)
        print(f"Total: {total} calls across {unique} unique system calls")

    def process_file(self, filepath: str) -> None:
        """Process strace output from a file."""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if self.interrupted:
                        break
                    self.explain_line(line)
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)

    def process_stdin(self) -> None:
        """Process strace output from stdin with Ctrl-C handling."""
        self.setup_signal_handler()

        try:
            for line in sys.stdin:
                if self.interrupted:
                    break
                self.explain_line(line)
        except KeyboardInterrupt:
            # Already handled by signal handler
            pass
        except Exception as e:
            if not self.interrupted:
                print(f"Error reading stdin: {e}", file=sys.stderr)
                sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Explain strace output with human-readable descriptions.',
        epilog='Examples:\n'
               '  strace ls 2>&1 | explain_strace.py\n'
               '  explain_strace.py strace_output.txt\n'
               '  explain_strace.py -vv strace_output.txt',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'file',
        nargs='?',
        help='Strace output file (if not provided, reads from stdin)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase verbosity (can be used multiple times: -v, -vv, -vvv)'
    )

    args = parser.parse_args()

    explainer = StraceExplainer(verbosity=args.verbose)

    if args.file:
        explainer.process_file(args.file)
    else:
        explainer.process_stdin()

    explainer.print_summary()


if __name__ == '__main__':
    main()
