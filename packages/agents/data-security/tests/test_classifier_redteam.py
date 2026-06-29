"""Adversarial red-team for the secret classifier — try to slip secrets past it.

Built by attacking our own detector to find what it MISSES. The v0.2 classifier knew only AWS keys
+ a narrow generic-token pattern, so modern secret formats sailed straight through (a leaked SSH
private key in a public bucket was NOT flagged). These cases pin the fixes and document the
remaining known gap, so a regression fails loudly and the boundary stays visible.

The token-shaped strings are ASSEMBLED from parts (``_t``) rather than written as literals, so no
contiguous secret-looking string lands in source — otherwise GitHub's own push-protection scanner
flags this file (which is, fittingly, exactly the kind of detection we're testing).
"""

from data_security.classifiers import classify
from data_security.schemas import ClassifierLabel as L


def _t(*parts: str) -> str:
    """Assemble a token-shaped string from parts (keeps a literal secret out of the source)."""
    return "".join(parts)


_GITHUB = _t("ghp_", "16C7e42F292c6912E7710c838347Ae178B4a")  # ghp_ + 36 chars
_GOOGLE = _t("AIza", "SyA-1234567890abcdefghijklmnopqrstu")  # AIza + exactly 35 chars
_STRIPE = _t("sk_", "live_", "51H8z9eL0aBcDeFgHiJkLmNoPqRsTuVwXyZ")
_SLACK = _t("xox", "b-", "2483024-2483024-AbCdEfGhIjKlMnOpQrStUv")
_PRIVKEY = "-----BEGIN RSA PRIVATE KEY-----\n(fake body, not real key material)\n"
_OPENSSH = "-----BEGIN OPENSSH PRIVATE KEY-----\n(fake body)\n"
_ASIA = _t("aws_access_key_id = ", "ASIA", "IOSFODNN7EXAMPLE")
_AKIA = _t("aws_access_key_id = ", "AKIA", "IOSFODNN7EXAMPLE")


def test_modern_secret_formats_are_caught():
    # FIXED (red-team): each of these was MISSED (-> NONE) by the v0.2 classifier.
    assert classify(f"github_pat = {_GITHUB}") is L.GITHUB_TOKEN
    assert classify(_PRIVKEY) is L.PRIVATE_KEY
    assert classify(_OPENSSH) is L.PRIVATE_KEY
    assert classify(f"key={_GOOGLE}") is L.GOOGLE_API_KEY
    assert classify(_STRIPE) is L.STRIPE_KEY


def test_aws_temporary_credentials_are_caught():
    # FIXED: the access-key regex was AKIA-only; ASIA (temporary STS creds) is also a credential.
    assert classify(_ASIA) is L.AWS_ACCESS_KEY
    assert classify(_AKIA) is L.AWS_ACCESS_KEY  # long-term keys still work


def test_slack_token_is_not_misclassified_as_credit_card():
    # FIXED: the digit-run in a Slack token used to match the greedy credit-card regex.
    assert classify(f"SLACK_TOKEN={_SLACK}") is L.SLACK_TOKEN


def test_precision_no_false_positives_on_near_misses():
    # The new patterns must NOT cry wolf on benign look-alikes.
    assert classify("the quick brown fox jumps over the lazy dog") is L.NONE
    assert (
        classify("my secret recipe for chocolate chip cookies") is L.NONE
    )  # 'secret' word, no token
    assert classify(_t("ghp_", "tooshort")) is L.NONE  # GitHub prefix but too short
    assert classify("please BEGIN the meeting, no private keys here") is L.NONE


def test_prior_classifications_unchanged_regression():
    # Adding the new high-precedence patterns must not move existing labels.
    assert classify("patient ssn 123-45-6789") is L.SSN
    assert classify("card 4111 1111 1111 1111") is L.CREDIT_CARD
    assert classify("contact bob@acme.com") is L.EMAIL


def test_known_gap_db_connection_password_is_not_caught_as_a_credential():
    # DOCUMENTED LIMITATION (red-team): a password inside a DB connection string is not flagged as a
    # credential — the host part matches the email pattern first, and catching arbitrary inline
    # passwords is high false-positive risk. Tracked here; if a dedicated pattern lands, this flips.
    conn = _t("postgres://admin:", "Sup3rS3cret", "@db.acme.com:5432/prod")
    assert classify(conn) is not L.PRIVATE_KEY
    assert classify(conn) in (L.EMAIL, L.NONE)
