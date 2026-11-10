"""Webhook URL validation and payload signing.

This is the module that stops a feature from being server-side request
forgery, so the tests are a list of bypasses and the assertion that each one
is closed. The ones that matter most, in order of how much they would cost:

``169.254.169.254`` — the cloud metadata endpoint, which hands out the
instance's credentials to anybody who can make it a request. It is link-local
rather than private, so a check that only asked ``is_private`` would let it
through. That is the single most valuable address on the internal network and
the one a naive allowlist misses.

A hostname resolving to several addresses, one of them loopback. Checking the
first resolved address and connecting by name means the socket may pick the
other one.

``::ffff:127.0.0.1`` — loopback written as IPv6. A string comparison against
``127.0.0.1`` does not see it.
"""

from __future__ import annotations

import ipaddress

import pytest

from vexpath_platform import outbound


def test_an_ordinary_https_url_is_accepted() -> None:
    target = outbound.check_url("https://hooks.example.com/vexpath?token=abc")
    assert target.host == "hooks.example.com"
    assert target.port == 443


def test_plain_http_is_refused() -> None:
    with pytest.raises(outbound.UrlRefusedError, match="https"):
        outbound.check_url("http://hooks.example.com/x")


@pytest.mark.parametrize(
    "scheme",
    ["file", "ftp", "gopher", "data", "jar", "dict", "ldap"],
)
def test_other_schemes_are_refused(scheme: str) -> None:
    # Every one of these has been used to turn a URL field into a file read or
    # a protocol-smuggling primitive.
    with pytest.raises(outbound.UrlRefusedError):
        outbound.check_url(f"{scheme}://hooks.example.com/x")


def test_credentials_in_the_url_are_refused() -> None:
    with pytest.raises(outbound.UrlRefusedError, match="credentials"):
        outbound.check_url("https://user:secret@hooks.example.com/x")


def test_an_unusual_port_is_refused() -> None:
    # Port 6379 is Redis, 5432 is Postgres, 9200 is Elasticsearch. A webhook
    # receiver is not on any of them.
    for port in (22, 5432, 6379, 8080, 9200, 11211):
        with pytest.raises(outbound.UrlRefusedError, match="port"):
            outbound.check_url(f"https://hooks.example.com:{port}/x")


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "0.0.0.0",
        "10.1.2.3",
        "172.16.0.9",
        "192.168.1.1",
        "169.254.169.254",
        "[::1]",
        "[fe80::1]",
        "[::ffff:127.0.0.1]",
        "localhost",
        "db.internal",
        "printer.local",
        "api.localhost",
    ],
)
def test_addresses_that_are_not_on_the_public_internet_are_refused(host: str) -> None:
    with pytest.raises(outbound.UrlRefusedError, match="public"):
        outbound.check_url(f"https://{host}/hook")


def test_the_metadata_endpoint_is_refused_specifically() -> None:
    # Written as its own test because it is the one address whose compromise
    # hands over the whole deployment, and because it is technically global
    # rather than private: a check that asked only `is_private` would allow it.
    address = ipaddress.ip_address("169.254.169.254")
    assert address.is_private is False or address.is_link_local
    assert not outbound.is_public_address(address)


def test_loopback_wearing_an_ipv6_hat_is_refused() -> None:
    assert not outbound.is_public_address(ipaddress.ip_address("::ffff:127.0.0.1"))
    assert not outbound.is_public_address(ipaddress.ip_address("::ffff:10.0.0.1"))


def test_a_public_address_is_accepted() -> None:
    for candidate in ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"):
        assert outbound.is_public_address(ipaddress.ip_address(candidate))


def test_a_fragment_is_refused() -> None:
    with pytest.raises(outbound.UrlRefusedError, match="fragment"):
        outbound.check_url("https://hooks.example.com/x#never-sent")


def test_an_empty_or_absurd_url_is_refused() -> None:
    with pytest.raises(outbound.UrlRefusedError):
        outbound.check_url("   ")
    with pytest.raises(outbound.UrlRefusedError, match="long"):
        outbound.check_url("https://hooks.example.com/" + "a" * 3000)


# --- Resolution -------------------------------------------------------------


def test_every_resolved_address_has_to_be_public() -> None:
    # The bypass: a name that resolves to one public and one loopback address.
    # Checking the first would pass, and the socket might then pick the other.
    with pytest.raises(outbound.UrlRefusedError, match="public"):
        outbound.refuse_private_addresses("mixed.example.com", ["93.184.216.34", "127.0.0.1"])


def test_a_name_that_resolves_publicly_is_allowed() -> None:
    outbound.refuse_private_addresses("ok.example.com", ["93.184.216.34", "93.184.216.35"])


def test_a_name_that_does_not_resolve_is_refused() -> None:
    with pytest.raises(outbound.UrlRefusedError, match="does not resolve"):
        outbound.refuse_private_addresses("nowhere.example.com", [])


def test_an_unparseable_resolved_address_is_refused() -> None:
    # Fails closed: something that is not an address cannot be shown to be
    # public, so it is not treated as public.
    with pytest.raises(outbound.UrlRefusedError):
        outbound.refuse_private_addresses("odd.example.com", ["not-an-address"])


# --- Signing ----------------------------------------------------------------


def test_a_signature_verifies_against_its_own_inputs() -> None:
    secret = outbound.new_secret()
    body = b'{"event":"ping"}'
    signature = outbound.sign(secret, 1700000000, body)
    assert signature.startswith(outbound.SIGNATURE_PREFIX)
    assert outbound.verify(secret, 1700000000, body, signature)


def test_a_signature_does_not_verify_under_another_secret() -> None:
    body = b"{}"
    signature = outbound.sign(outbound.new_secret(), 1, body)
    assert not outbound.verify(outbound.new_secret(), 1, body, signature)


def test_changing_the_body_invalidates_the_signature() -> None:
    secret = outbound.new_secret()
    signature = outbound.sign(secret, 1, b'{"amount":1}')
    assert not outbound.verify(secret, 1, b'{"amount":2}', signature)


def test_changing_the_timestamp_invalidates_the_signature() -> None:
    secret = outbound.new_secret()
    signature = outbound.sign(secret, 1700000000, b"{}")
    # The timestamp is inside the signature, which is what lets a receiver
    # refuse a replayed delivery. Signing the body alone would make any
    # captured delivery valid forever.
    assert not outbound.verify(secret, 1700000001, b"{}", signature)


def test_the_timestamp_and_body_cannot_run_together() -> None:
    secret = outbound.new_secret()
    # Without a separator, timestamp 1 with body "23..." and timestamp 12 with
    # body "3..." would sign the same bytes and share a signature.
    first = outbound.sign(secret, 1, b"23")
    second = outbound.sign(secret, 12, b"3")
    assert first != second


def test_two_secrets_are_never_the_same() -> None:
    assert len({outbound.new_secret() for _ in range(200)}) == 200


def test_a_secret_is_recognisable_as_one() -> None:
    # A prefix a secret scanner can match, so a leaked one is found by the
    # tools that look for leaked credentials.
    assert outbound.new_secret().startswith("whsec_")


def test_a_fingerprint_does_not_reveal_the_secret() -> None:
    secret = outbound.new_secret()
    label = outbound.fingerprint(secret)
    assert secret not in label
    assert len(label) <= 16
    assert label == outbound.fingerprint(secret)
    assert label != outbound.fingerprint(outbound.new_secret())


def test_verification_tolerates_surrounding_whitespace() -> None:
    secret = outbound.new_secret()
    signature = outbound.sign(secret, 5, b"{}")
    # A header value arrives trimmed by some clients and not others, and a
    # receiver failing on that would look like a signing bug.
    assert outbound.verify(secret, 5, b"{}", f"  {signature}  ")
