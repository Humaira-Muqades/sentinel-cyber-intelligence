"""Parser tests. Run with: python -m pytest tests/ -v"""

from src.parsers import parse, parse_stats


def test_auth_extracts_attacker_ip_and_user():
    line = ("Mar 11 14:22:07 web-01 sshd[2841]: Failed password "
            "for root from 203.0.113.44 port 51022 ssh2")
    (event,) = parse(line, "auth")
    assert event["src_ip"] == "203.0.113.44"
    assert event["user"] == "root"
    assert event["outcome"] == "Failed password"


def test_firewall_extracts_action_and_ports():
    line = ("2024-03-11 14:22:30 DENY TCP 203.0.113.44:51030 "
            "-> 10.0.4.12:3306 rule=BLOCK_DB_EXTERNAL")
    (event,) = parse(line, "firewall")
    assert event["action"] == "DENY"
    assert event["dst_port"] == "3306"
    assert event["rule"] == "BLOCK_DB_EXTERNAL"


def test_comments_and_blanks_are_skipped():
    assert parse("# header\n\n", "firewall") == []


def test_unparseable_lines_are_kept_not_dropped():
    (event,) = parse("garbage line", "firewall")
    assert "unparsed" in event
    assert parse_stats([event])["unparsed"] == 1
