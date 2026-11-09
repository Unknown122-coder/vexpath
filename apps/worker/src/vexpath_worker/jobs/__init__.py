"""Job implementations.

Every job is idempotent. Each one will be retried at some point, by a queue
redelivery or by a human re-running a command, and a job that corrupts state on
its second run is a job that corrupts state.
"""

from __future__ import annotations
