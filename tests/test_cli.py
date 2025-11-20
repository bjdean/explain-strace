"""Tests for explain_strace CLI."""

import sys
import tempfile
from pathlib import Path

import pytest

from explain_strace.cli import StraceExplainer, get_all_categories


class TestStraceExplainer:
    """Tests for StraceExplainer class."""

    def test_init(self):
        """Test initialization."""
        explainer = StraceExplainer()
        assert explainer.verbosity == 0
        assert explainer.filter_category is None
        assert len(explainer.syscall_counts) == 0

    def test_init_with_verbosity(self):
        """Test initialization with verbosity."""
        explainer = StraceExplainer(verbosity=2)
        assert explainer.verbosity == 2

    def test_init_with_filter(self):
        """Test initialization with category filter."""
        explainer = StraceExplainer(filter_category="filesystem")
        assert explainer.filter_category == "filesystem"

    def test_parse_line_valid(self):
        """Test parsing a valid strace line."""
        explainer = StraceExplainer()
        line = 'openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3'
        result = explainer.parse_line(line)
        assert result is not None
        syscall, full_line, retval = result
        assert syscall == "openat"
        assert full_line == line
        assert retval == "3"

    def test_parse_line_with_negative_return(self):
        """Test parsing a line with negative return value."""
        explainer = StraceExplainer()
        line = 'open("/nonexistent", O_RDONLY) = -1 ENOENT'
        result = explainer.parse_line(line)
        assert result is not None
        syscall, full_line, retval = result
        assert syscall == "open"
        assert retval == "-1"

    def test_parse_line_invalid(self):
        """Test parsing an invalid line."""
        explainer = StraceExplainer()
        line = "This is not a syscall line"
        result = explainer.parse_line(line)
        assert result is None

    def test_parse_line_empty(self):
        """Test parsing an empty line."""
        explainer = StraceExplainer()
        result = explainer.parse_line("")
        assert result is None

    def test_get_syscall_description_known(self):
        """Test getting description for known syscall."""
        explainer = StraceExplainer()
        desc = explainer.get_syscall_description("open")
        assert desc == "Open a file or device"

    def test_get_syscall_description_unknown(self):
        """Test getting description for unknown syscall."""
        explainer = StraceExplainer()
        desc = explainer.get_syscall_description("unknown_syscall")
        assert desc == "Unknown system call"

    def test_get_syscall_category_known(self):
        """Test getting category for known syscall."""
        explainer = StraceExplainer()
        category = explainer.get_syscall_category("open")
        assert category == "filesystem"

    def test_get_syscall_category_unknown(self):
        """Test getting category for unknown syscall."""
        explainer = StraceExplainer()
        category = explainer.get_syscall_category("unknown_syscall")
        assert category == "unknown"

    def test_get_manpage_url(self):
        """Test getting man page URL."""
        explainer = StraceExplainer()
        url = explainer.get_manpage_url("open")
        assert url == "https://man7.org/linux/man-pages/man2/open.2.html"

    def test_parse_line_resumed(self):
        """Test parsing a resumed syscall line."""
        explainer = StraceExplainer()
        line = '<... read resumed> "data", 100) = 100'
        result = explainer.parse_line(line)
        assert result is not None
        syscall, full_line, retval = result
        assert syscall == "read"
        assert retval == "100"

    def test_parse_line_unfinished(self):
        """Test parsing an unfinished syscall line."""
        explainer = StraceExplainer()
        line = "read(3, <unfinished ...>"
        result = explainer.parse_line(line)
        assert result is not None
        syscall, full_line, retval = result
        assert syscall == "read"
        assert retval is None  # No return value yet

    def test_parse_line_with_pid(self):
        """Test parsing line with PID prefix."""
        explainer = StraceExplainer()
        line = '1234 open("/etc/hostname", O_RDONLY) = 3'
        result = explainer.parse_line(line)
        assert result is not None
        syscall, full_line, retval = result
        assert syscall == "open"
        assert retval == "3"

    def test_parse_line_with_timestamp(self):
        """Test parsing line with timestamp."""
        explainer = StraceExplainer()
        line = '[12:34:56.789] open("/tmp/test.txt", O_RDONLY) = 3'
        result = explainer.parse_line(line)
        assert result is not None
        syscall, full_line, retval = result
        assert syscall == "open"
        assert retval == "3"

    def test_parse_line_hex_return(self):
        """Test parsing line with hex return value."""
        explainer = StraceExplainer()
        line = "mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f1234567000"
        result = explainer.parse_line(line)
        assert result is not None
        syscall, full_line, retval = result
        assert syscall == "mmap"
        assert retval == "0x7f1234567000"

    def test_explain_parameters(self):
        """Test parameter extraction and explanation."""
        explainer = StraceExplainer()

        # Test normal parameters
        line = 'openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3'
        result = explainer.explain_parameters(line, "openat")
        assert "AT_FDCWD" in result
        assert "/etc/ld.so.cache" in result

        # Test unfinished call
        line = "read(3, <unfinished ...>"
        result = explainer.explain_parameters(line, "read")
        assert "unfinished" in result.lower()

        # Test resumed call
        line = '<... read resumed> "data", 100) = 100'
        result = explainer.explain_parameters(line, "read")
        assert "resumed" in result.lower()

    def test_explain_line(self, capsys):
        """Test explaining a full strace line."""
        explainer = StraceExplainer(verbosity=0)

        # Test basic syscall
        line = 'open("/etc/hostname", O_RDONLY) = 3'
        explainer.explain_line(line)
        captured = capsys.readouterr()
        assert 'open("/etc/hostname", O_RDONLY) = 3' in captured.out
        assert "filesystem" in captured.out
        assert "Open a file or device" in captured.out
        assert "3" in captured.out

        # Verify syscall was counted
        assert explainer.syscall_counts["open"] == 1
        assert explainer.category_counts["filesystem"] == 1

    def test_explain_line_with_verbosity(self, capsys):
        """Test explaining with verbose mode."""
        explainer = StraceExplainer(verbosity=1)

        line = 'open("/tmp/config.txt", O_RDONLY) = 3'
        explainer.explain_line(line)
        captured = capsys.readouterr()
        assert "Documentation:" in captured.out
        assert "man7.org" in captured.out

    def test_explain_line_with_filter(self, capsys):
        """Test filtering by category."""
        explainer = StraceExplainer(filter_category="filesystem")

        # Should process filesystem syscall
        explainer.explain_line('open("/tmp/data.txt", O_RDONLY) = 3')
        assert explainer.syscall_counts["open"] == 1

        # Should skip network syscall
        explainer.explain_line("socket(AF_INET, SOCK_STREAM, 0) = 4")
        assert "socket" not in explainer.syscall_counts

    def test_print_summary(self, capsys):
        """Test summary output."""
        explainer = StraceExplainer()

        # Add some syscalls
        explainer.explain_line('open("/etc/hostname", O_RDONLY) = 3')
        explainer.explain_line('read(3, "data", 100) = 100')
        explainer.explain_line("close(3) = 0")
        explainer.explain_line('open("/tmp/test.txt", O_RDONLY) = 3')

        # Clear previous output
        capsys.readouterr()

        # Print summary
        explainer.print_summary()
        captured = capsys.readouterr()

        # Check summary content
        assert "SUMMARY OF SYSTEM CALLS" in captured.out
        assert "open" in captured.out
        assert "read" in captured.out
        assert "close" in captured.out
        assert "2" in captured.out  # open called twice
        assert "Total: 4 calls" in captured.out
        assert "3 unique system calls" in captured.out
        assert "SUMMARY BY CATEGORY" in captured.out
        assert "filesystem" in captured.out

    def test_print_summary_empty(self, capsys):
        """Test summary with no syscalls."""
        explainer = StraceExplainer()
        explainer.print_summary()
        captured = capsys.readouterr()
        assert "No system calls found" in captured.out

    def test_process_file(self, capsys):
        """Test processing strace output from a file."""
        # Create a temporary file with strace output
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write('open("/tmp/app.log", O_RDONLY) = 3\n')
            f.write('read(3, "data", 100) = 100\n')
            f.write("close(3) = 0\n")
            temp_path = f.name

        try:
            explainer = StraceExplainer()
            explainer.process_file(temp_path)

            # Verify syscalls were processed
            assert explainer.syscall_counts["open"] == 1
            assert explainer.syscall_counts["read"] == 1
            assert explainer.syscall_counts["close"] == 1
        finally:
            Path(temp_path).unlink()

    def test_process_file_not_found(self, capsys):
        """Test processing a non-existent file."""
        explainer = StraceExplainer()
        with pytest.raises(SystemExit) as exc_info:
            explainer.process_file("/nonexistent/file.txt")
        assert exc_info.value.code == 1


class TestCategories:
    """Tests for category functions."""

    def test_get_all_categories(self):
        """Test getting all categories."""
        categories = get_all_categories()
        assert isinstance(categories, list)
        assert len(categories) > 0
        assert "filesystem" in categories
        assert "network" in categories
        assert "memory" in categories
        # Check that categories are sorted
        assert categories == sorted(categories)


class TestCLI:
    """Tests for CLI argument parsing and main function."""

    def test_main_with_file(self, capsys, monkeypatch):
        """Test main() with file argument."""
        # Create a temporary file with strace output
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write('open("/etc/hostname", O_RDONLY) = 3\n')
            f.write("close(3) = 0\n")
            temp_path = f.name

        try:
            # Mock sys.argv to simulate command line arguments
            monkeypatch.setattr(sys, "argv", ["explain-strace", temp_path])

            # Import and run main
            from explain_strace.cli import main

            main()

            captured = capsys.readouterr()
            assert "open" in captured.out
            assert "close" in captured.out
            assert "SUMMARY" in captured.out
        finally:
            Path(temp_path).unlink()

    def test_main_with_verbose(self, capsys, monkeypatch):
        """Test main() with verbose flag."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write('open("/tmp/debug.log", O_RDONLY) = 3\n')
            temp_path = f.name

        try:
            monkeypatch.setattr(sys, "argv", ["explain-strace", "-v", temp_path])

            from explain_strace.cli import main

            main()

            captured = capsys.readouterr()
            assert "Documentation:" in captured.out
            assert "man7.org" in captured.out
        finally:
            Path(temp_path).unlink()

    def test_main_with_filter(self, capsys, monkeypatch):
        """Test main() with category filter."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write('open("/tmp/config.ini", O_RDONLY) = 3\n')
            f.write("socket(AF_INET, SOCK_STREAM, 0) = 4\n")
            f.write("close(3) = 0\n")
            temp_path = f.name

        try:
            monkeypatch.setattr(
                sys, "argv", ["explain-strace", "--filter", "filesystem", temp_path]
            )

            from explain_strace.cli import main

            main()

            captured = capsys.readouterr()
            # Should show filesystem syscalls
            assert "open" in captured.out or "close" in captured.out
            # Should not show network syscalls
            assert "socket" not in captured.out or "SUMMARY" in captured.out
        finally:
            Path(temp_path).unlink()

    def test_main_catlist(self, capsys, monkeypatch):
        """Test main() with --catlist flag."""
        monkeypatch.setattr(sys, "argv", ["explain-strace", "--catlist"])

        from explain_strace.cli import main

        try:
            main()
        except SystemExit as e:
            assert e.code == 0

        captured = capsys.readouterr()
        assert "filesystem" in captured.out
        assert "network" in captured.out
        assert "memory" in captured.out
