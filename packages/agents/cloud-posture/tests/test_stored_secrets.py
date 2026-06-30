"""W6 red-team bank — stored-credential extraction precision."""

from cloud_posture.tools.stored_secrets import stored_secret_grants

_ARN = "arn:aws:ecs:us-east-1:111:service/web"
# Assembled so push-protection doesn't flag a literal key; AKIA + 16 chars.
_KEY = "AKIA" + "EXAMPLE0STORED01"


def test_extracts_access_key_id_from_env():
    out = stored_secret_grants([(_ARN, [f"AWS_ACCESS_KEY_ID={_KEY}"])])
    assert out == [(_ARN, _KEY)]


def test_bare_key_value():
    assert stored_secret_grants([(_ARN, [_KEY])]) == [(_ARN, _KEY)]


def test_dedup_same_key_twice():
    assert len(stored_secret_grants([(_ARN, [_KEY, f"X={_KEY}"])])) == 1


# --- traps → nothing ---


def test_trap_no_key_in_env():
    assert stored_secret_grants([(_ARN, ["LOG_LEVEL=debug", "PORT=8080"])]) == []


def test_trap_empty_env():
    assert stored_secret_grants([(_ARN, [])]) == []
