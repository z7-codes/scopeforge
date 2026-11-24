import yaml

from dorklens.config import DATA, Config
from dorklens.modules import params
from scripts.lab_assert import CASES, CLEAN, MAX_FINDINGS


def test_lab_profile_is_offline_and_targeted() -> None:
    cfg = Config.from_domain("127.0.0.1:3000").apply_profile("lab")
    assert cfg.stages == ["crawl", "dirs", "payload"]
    assert cfg.wordlist == DATA / "lab-wordlist.txt"
    assert cfg.wordlist.exists()
    assert cfg.min_confidence == 1
    assert cfg.post
    assert cfg.post_paths == ["/rest/user/login"]


def test_lab_payloads_cover_juice_shop_params() -> None:
    specs = yaml.safe_load((DATA / "payloads.yaml").read_text(encoding="utf-8")) or {}
    assert "q" in specs["sqli_error"]["params"]
    assert "q" in specs["sqli_bool"]["params"]
    assert "to" in specs["open_redirect"]["params"]
    assert "to" in params.INTERESTING


def test_lab_matrix_uses_precision_not_count() -> None:
    assert any(path == "/rest/products/search" and param == "q" for path, param, _ in CASES)
    assert any(path == "/redirect" and param == "to" for path, param, _ in CASES)
    assert "/api/Products" in CLEAN
    assert "/rest/captcha" in CLEAN
    assert MAX_FINDINGS == 40
