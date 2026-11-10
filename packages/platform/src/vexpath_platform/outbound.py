"""Outbound requests to a URL somebody else chose, and how to sign them.

A webhook is the one feature where a user hands this system an address and it
connects to it. That makes it server-side request forgery by design, and the
only question is whether it is constrained. Unconstrained, a webhook URL
reaches everything the application can reach and nothing else can: the cloud
provider's metadata endpoint at ``169.254.169.254`` and the credentials it
hands out, the database on a private subnet, an internal admin service that
trusts its network. "Give us a URL and we will fetch it" is the single most
productive vulnerability class in a hosted product.

So the rules here are refusals, and each one closes a specific bypass.

**Only https, and only to a public address.** Every address the hostname
resolves to is checked, not the first: a name that resolves to one public and
one loopback address would otherwise pass and then connect to whichever the
socket picked.

**Resolved again at delivery, not only at registration.** A hostname that
resolved publicly an hour ago can resolve to ``127.0.0.1`` now. Validating
once at registration and trusting it afterwards is the DNS rebinding bypass,
and it is the one that gets missed.

**No redirects.** A redirect is a second URL that nothing validated. The
endpoint either answers or it does not.

**No credentials in the URL, and no exotic ports.** ``https://user:pass@host``
leaks a credential into logs, and a port outside the normal range is almost
always somebody probing the internal network rather than receiving a webhook.

The signature is HMAC-SHA256 over a timestamp and the body, in that order,
with the timestamp also sent as a header. Signing the body alone would let
anybody who captured one delivery replay it forever; including the timestamp
lets the receiver refuse an old one. The receiver is told to compare in
constant time, because a receiver that uses ``==`` has a timing oracle on its
own secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

#: Ports a webhook receiver is plausibly on. Anything else is more likely
#: somebody mapping the internal network than an endpoint expecting a POST.
ALLOWED_PORTS = frozenset({443, 8443})

#: Schemes. One, and it is the encrypted one: a webhook carries a signature
#: and a finding, and sending either in clear text over somebody else's
#: network defeats the point of signing it.
ALLOWED_SCHEMES = frozenset({"https"})

#: How long a receiver should accept a signature for. Sent in the
#: documentation rather than enforced here -- the receiver is the only party
#: that can enforce it -- but named so both sides mean the same thing.
SIGNATURE_TOLERANCE_SECONDS = 300

#: Header names. Fixed, because a receiver hard-codes them.
SIGNATURE_HEADER = "X-Vexpath-Signature"
TIMESTAMP_HEADER = "X-Vexpath-Timestamp"
EVENT_HEADER = "X-Vexpath-Event"
DELIVERY_HEADER = "X-Vexpath-Delivery"

#: Prefix on the signature value, so the algorithm is visible in the header
#: and a future second algorithm does not have to guess what it is replacing.
SIGNATURE_PREFIX = "sha256="

#: Bytes of entropy in a webhook signing secret.
SECRET_BYTES = 32


class UrlRefusedError(ValueError):
    """A webhook URL this system will not connect to, and why."""


@dataclass(frozen=True, slots=True)
class Target:
    """A URL that passed the checks that do not need DNS."""

    url: str
    host: str
    port: int


def check_url(candidate: str) -> Target:
    """Validate everything about a URL that does not require a lookup.

    Raises:
        UrlRefusedError: with a message for the person who typed it. Each refusal
            closes a specific bypass rather than being a style preference, and
            the message says which.
    """
    url = candidate.strip()
    if not url:
        msg = "a webhook needs a URL"
        raise UrlRefusedError(msg)
    if len(url) > 2000:
        msg = "that URL is implausibly long"
        raise UrlRefusedError(msg)

    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        msg = (
            "a webhook URL has to use https. A signed payload sent in clear "
            "text over somebody else's network defeats the point of signing it"
        )
        raise UrlRefusedError(msg)
    if parts.username or parts.password:
        msg = (
            "a webhook URL must not carry credentials. They would be written "
            "into every log line that records the delivery; use the signing "
            "secret instead"
        )
        raise UrlRefusedError(msg)
    if parts.fragment:
        msg = "a webhook URL must not have a fragment: it is never sent"
        raise UrlRefusedError(msg)

    host = (parts.hostname or "").strip().lower()
    if not host:
        msg = "that URL has no host"
        raise UrlRefusedError(msg)

    try:
        port = parts.port or 443
    except ValueError as exc:
        msg = "that URL has an unreadable port"
        raise UrlRefusedError(msg) from exc
    if port not in ALLOWED_PORTS:
        msg = (
            f"a webhook URL has to use port {' or '.join(str(p) for p in sorted(ALLOWED_PORTS))}. "
            f"Another port is more often somebody mapping an internal network "
            f"than an endpoint expecting a delivery"
        )
        raise UrlRefusedError(msg)

    # A literal address is checked here; a name is checked after resolution,
    # by the caller, because that lookup has to happen again at delivery time.
    literal = _as_address(host)
    if literal is not None and not is_public_address(literal):
        msg = _private_message(host)
        raise UrlRefusedError(msg)
    if host.endswith((".localhost", ".internal", ".local")) or host == "localhost":
        msg = _private_message(host)
        raise UrlRefusedError(msg)

    return Target(url=url, host=host, port=port)


def _as_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _private_message(host: str) -> str:
    return (
        f"{host} is not a public address. A webhook can only be delivered to "
        f"the public internet: an address on this network would let a URL in a "
        f"form reach services that are only reachable from inside, including "
        f"the cloud metadata endpoint that hands out credentials"
    )


def is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether this address may be connected to.

    Everything that is not plainly on the public internet is refused, and the
    list is written out rather than relying on ``is_private`` alone, because
    the addresses that matter most are the ones that are technically global:
    ``169.254.169.254`` is link-local, and it is the cloud metadata endpoint
    that hands out credentials to anybody who asks.
    """
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # ::ffff:127.0.0.1 is loopback wearing a different hat.
        return is_public_address(address.ipv4_mapped)
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def refuse_private_addresses(host: str, resolved: list[str]) -> None:
    """Refuse unless every resolved address is public.

    Every one, not the first. A name that resolves to one public and one
    loopback address would otherwise pass validation and then connect to
    whichever the socket happened to pick -- which is a bypass, not a race.

    Raises:
        UrlRefusedError: if the name does not resolve, or any address is not
            public.
    """
    if not resolved:
        msg = f"{host} does not resolve to any address"
        raise UrlRefusedError(msg)
    for candidate in resolved:
        address = _as_address(candidate)
        if address is None or not is_public_address(address):
            raise UrlRefusedError(_private_message(host))


# --- Signing ----------------------------------------------------------------


def new_secret() -> str:
    """A signing secret to share with the receiver."""
    return f"whsec_{secrets.token_urlsafe(SECRET_BYTES)}"


def sign(secret: str, timestamp: int, body: bytes) -> str:
    """The signature for one delivery.

    Over the timestamp and then the body, separated by a dot so the two can
    never run together: without a separator, a body beginning with digits
    could be read as part of the timestamp, and two different deliveries would
    share a signature.

    The timestamp is inside the signature and also sent as a header, which is
    what lets a receiver refuse a replayed delivery. Signing the body alone
    would make any captured delivery valid forever.
    """
    payload = f"{timestamp}.".encode() + body
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_PREFIX}{digest}"


def verify(secret: str, timestamp: int, body: bytes, presented: str) -> bool:
    """Whether a signature is the right one.

    Here so a receiver can be written against this implementation, and so the
    tests check the real thing rather than a second copy of the same
    arithmetic. Constant-time, because a receiver that compares with ``==``
    has a timing oracle on its own secret.
    """
    expected = sign(secret, timestamp, body)
    return hmac.compare_digest(expected, presented.strip())


def fingerprint(secret: str) -> str:
    """A short, non-reversible label for a secret.

    Shown in a list so two webhooks can be told apart without the secret
    being displayed again.
    """
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest()[:6]).decode(
        "ascii"
    )


__all__ = [
    "ALLOWED_PORTS",
    "ALLOWED_SCHEMES",
    "DELIVERY_HEADER",
    "EVENT_HEADER",
    "SECRET_BYTES",
    "SIGNATURE_HEADER",
    "SIGNATURE_PREFIX",
    "SIGNATURE_TOLERANCE_SECONDS",
    "TIMESTAMP_HEADER",
    "Target",
    "UrlRefusedError",
    "check_url",
    "fingerprint",
    "is_public_address",
    "new_secret",
    "refuse_private_addresses",
    "sign",
    "verify",
]
