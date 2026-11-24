import yaml

from dorklens.config import DATA, Config
from dorklens.modules import params


def test_lab_profile_is_offline_and_targeted() -> None:
    cfg = Config.from_domain("127.0.0.1:3000").apply_profile("lab")
    assert cfg.stages == ["dirs", "payload"]
    assert cfg.wordlist == DATA / "lab-wordlist.txt"
    assert cfg.wordlist.exists()
    assert cfg.min_confidence == 1


def test_lab_payloads_cover_juice_shop_params() -> None:
    specs = yaml.safe_load((DATA / "payloads.yaml").read_text(encoding="utf-8")) or {}
    assert "q" in specs["sqli_error"]["params"]
    assert "q" in specs["sqli_bool"]["params"]
    assert "to" in specs["open_redirect"]["params"]
    assert "to" in params.INTERESTING
