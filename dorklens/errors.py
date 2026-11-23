from __future__ import annotations


class DorkLensError(Exception):
    pass


class UsageError(DorkLensError):
    pass


class SearchError(DorkLensError):
    pass
