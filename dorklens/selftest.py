from __future__ import annotations

from .modules.dirs import is_soft
from .modules.dork import extract
from .modules.payloads import replace_param, similarity
from .scope import Scope


def check(label: str, condition: bool) -> bool:
    print(("  ok   " if condition else "  FAIL ") + label)
    return condition


def run_all() -> bool:
    scope = Scope(allow=["a.io", "*.a.io"], deny=["dev.a.io"])
    results = [
        check("root", scope.in_scope("a.io")),
        check("sub", scope.in_scope("x.a.io")),
        check("deny", not scope.in_scope("dev.a.io")),
        check("outside", not scope.in_scope("evil.com")),
        check("empty", not scope.in_scope("")),
        check("replace", replace_param("http://a/?x=1&id=9", "id", "'") == "http://a/?x=1&id=%27"),
        check("keep others", "x=1" in replace_param("http://a/?x=1&id=9", "id", "'")),
        check("sim same", similarity("abc", "abc") == 1.0),
        check("sim diff", similarity("a" * 200, "b" * 200) < 0.5),
        check("soft404", is_soft([(200, 4000)], 200, 4010) and not is_soft([(200, 4000)], 200, 9000)),
        check(
            "ddg",
            extract(
                '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fx.io%2Fa">x</a>',
                "a.result__a",
            )
            == ["https://x.io/a"],
        ),
    ]
    passed = all(results)
    print(f"\n{'PASS' if passed else 'FAIL'} ({sum(results)}/{len(results)})")
    return passed
