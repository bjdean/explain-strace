"""Tests for explain_strace CLI."""

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
