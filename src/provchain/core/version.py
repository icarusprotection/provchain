"""Version parsing and comparison utilities"""

from packaging.version import Version, parse


def parse_version(version_str: str) -> Version:
    """Parse a version string"""
    return parse(version_str)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings

    Returns:
        -1 if v1 < v2
        0 if v1 == v2
        1 if v1 > v2
    """
    ver1 = parse_version(v1)
    ver2 = parse_version(v2)

    if ver1 < ver2:
        return -1
    elif ver1 > ver2:
        return 1
    else:
        return 0


def is_valid_version(version_str: str) -> bool:
    """Check if a version string is valid"""
    try:
        parse_version(version_str)
        return True
    except Exception:
        return False
