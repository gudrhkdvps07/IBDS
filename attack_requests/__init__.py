"""Attack request list package.

This package defines attack request patterns only.
It does not mutate real requests, send HTTP traffic, or decide findings.
"""

from .request_list import build_attack_request_list, export_attack_request_list

__all__ = ["build_attack_request_list", "export_attack_request_list"]
