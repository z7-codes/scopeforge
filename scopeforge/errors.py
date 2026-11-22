from __future__ import annotations


class ScopeForgeError(Exception):
    exit_code = 1


class UsageError(ScopeForgeError):
    exit_code = 2


class ScopeError(UsageError):
    pass


class DataError(UsageError):
    pass


class NetworkError(ScopeForgeError):
    pass


class BudgetExhausted(ScopeForgeError):
    exit_code = 3


class NothingFound(ScopeForgeError):
    exit_code = 4
