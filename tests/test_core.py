from src.core.config import HoneypotConfig


def test_honeypot_config_defaults():
    """Verifică valorile implicite pentru configurația honeypot."""
    config = HoneypotConfig()
    assert config.ssh_port == 2222
    assert config.telnet_port == 2323
    assert config.db_host == "honeypot_mysql"