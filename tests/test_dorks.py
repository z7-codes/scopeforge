import yaml

from dorklens.config import DATA, Config
from dorklens.modules.dork import plans


def test_catalog_size() -> None:
    rows = yaml.safe_load((DATA / "dorks.yaml").read_text(encoding="utf-8")) or []
    assert len(rows) == 33
    assert sum(len(row["q"]) for row in rows) == 380
    assert all("{{d}}" in query for row in rows for query in row["q"])


def test_plans_are_priority_ranked_and_limited() -> None:
    cfg = Config.from_domain("example.com").apply_profile("full")
    items = plans(cfg)
    assert len(items) == 40
    assert items[0][0] == "high"
    assert all("example.com" in query for _, _, query in items)


def test_deep_profile_wider_dork_limit() -> None:
    cfg = Config.from_domain("example.com").apply_profile("deep")
    assert len(plans(cfg)) == 80
