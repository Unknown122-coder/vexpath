"""Process exit codes.

These are a published contract with CI systems, so they are defined in one
place and must not be reused for new meanings. The important distinction is
between code 1 and code 2: a build that fails because the code is vulnerable
must never look like a build that fails because the scanner broke.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Exit status of the ``sscp`` process."""

    #: Analysis completed and the policy passed.
    OK = 0
    #: Analysis completed and the policy failed.
    POLICY_FAILED = 1
    #: Analysis could not complete: parse failure, missing lockfile, upstream
    #: outage. The verdicts are unknown, not clean.
    ANALYSIS_ERROR = 2
    #: Bad configuration: unparsable policy, malformed .sscp.yml, invalid flags.
    CONFIG_ERROR = 3


__all__ = ["ExitCode"]
