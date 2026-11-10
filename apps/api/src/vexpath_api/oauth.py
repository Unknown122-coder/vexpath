"""Signing in with GitHub.

GitHub is the only identity provider at launch, and the choice is not
incidental: the people who run a dependency scan already have a GitHub account,
and asking them to invent a password means this system has to store one. It
does not, and the user table has no password column to forget to hash.

The flow is the standard authorisation code exchange, with three details that
matter more than the rest.

**The state parameter is verified before anything else happens.** Without it an
attacker can complete the flow with their own authorisation code in a victim's
browser, and the victim ends up signed into the attacker's account, uploading
their dependency inventory to it. The state is signed and time-limited rather
than stored, and carries the page the user was trying to reach.

**The provider is an interface, with a real implementation and a fake one.**
Every branch of the callback -- a denied authorisation, a rejected code, a
GitHub outage, an account with no verified email -- is reachable in a test
without a network. The ones that are never exercised are the ones that answer
500 the first time a real user hits them.

**Only the subject is trusted to be stable.** A GitHub login can be renamed and
reused by somebody else, so the account is keyed on the numeric subject and the
login is display only. Keying on the login would mean a renamed account silently
becoming a different one, or worse, somebody else's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx

#: What this application asks for, and no more. ``read:user`` to identify the
#: account and ``user:email`` because the primary address is not in the profile
#: unless it is public. Nothing that touches a repository: this is sign-in, and
#: a token that could read private code would be a liability to hold.
SCOPES = "read:user user:email"

#: Short, because a user is waiting on a redirect. A provider that is slow to
#: answer during sign-in is better reported than waited on.
TIMEOUT = 10.0


class OAuthError(Exception):
    """Sign-in could not be completed.

    One exception for every cause. The handler turns it into one page, because
    the user has one remedy -- try again -- and the detail that distinguishes
    the causes is useful in a log and useless on a screen.
    """


@dataclass(frozen=True, slots=True)
class Identity:
    """Who signed in, as the provider describes them."""

    #: The provider's stable identifier. Never the login: that can be renamed
    #: and the name reused by somebody else.
    subject: str
    login: str
    name: str | None = None
    email: str | None = None


class IdentityProvider(Protocol):
    """What the sign-in handler needs from an identity provider."""

    @property
    def provider(self) -> str:
        """The value stored in ``users.provider``."""
        ...

    def authorize_url(self, *, redirect_uri: str, state: str) -> str:
        """Where to send the browser to begin."""
        ...

    async def identity(self, *, code: str, redirect_uri: str) -> Identity:
        """Exchange an authorisation code for the account behind it.

        Raises:
            OAuthError: if the code is not accepted or the account cannot be
                read.
        """
        ...


@dataclass(frozen=True, slots=True)
class GitHubProvider:
    """GitHub, over HTTP.

    The two base URLs are parameters rather than constants so a test can point
    the whole flow at a stand-in, and so GitHub Enterprise is a configuration
    change rather than a code change.
    """

    client_id: str
    client_secret: str
    oauth_base: str = "https://github.com"
    api_base: str = "https://api.github.com"

    @property
    def provider(self) -> str:
        return "github"

    def authorize_url(self, *, redirect_uri: str, state: str) -> str:
        query = urlencode(
            {
                "client_id": self.client_id,
                "redirect_uri": redirect_uri,
                "scope": SCOPES,
                "state": state,
                # Forces the authorisation screen rather than silently reusing
                # an existing grant, so signing in as a different account is
                # possible without first revoking the application.
                "allow_signup": "true",
            }
        )
        return f"{self.oauth_base.rstrip('/')}/login/oauth/authorize?{query}"

    async def identity(self, *, code: str, redirect_uri: str) -> Identity:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            token = await self._exchange(client, code=code, redirect_uri=redirect_uri)
            profile = await self._get(client, f"{self.api_base.rstrip('/')}/user", token)
            subject = profile.get("id")
            login = profile.get("login")
            if subject is None or not login:
                msg = "GitHub returned a profile with no account identifier"
                raise OAuthError(msg)

            email = profile.get("email") or await self._primary_email(client, token)

        return Identity(
            subject=str(subject),
            login=str(login),
            name=str(profile["name"]) if profile.get("name") else None,
            email=email,
        )

    async def _exchange(self, client: httpx.AsyncClient, *, code: str, redirect_uri: str) -> str:
        try:
            response = await client.post(
                f"{self.oauth_base.rstrip('/')}/login/oauth/access_token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                # Without this GitHub answers in form encoding, which is a
                # standing trap: the parse succeeds and the token is empty.
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            msg = f"GitHub could not be reached: {exc}"
            raise OAuthError(msg) from exc

        if response.status_code >= 400:
            msg = f"GitHub refused the authorisation code with {response.status_code}"
            raise OAuthError(msg)

        try:
            payload: dict[str, Any] = response.json()
        except ValueError as exc:
            msg = "GitHub answered the token exchange with something that is not JSON"
            raise OAuthError(msg) from exc

        if payload.get("error"):
            # Reported verbatim into the log and never onto the page: the
            # description sometimes contains the code that was refused.
            msg = f"GitHub refused the authorisation code: {payload['error']}"
            raise OAuthError(msg)

        token = payload.get("access_token")
        if not token:
            msg = "GitHub accepted the exchange but returned no access token"
            raise OAuthError(msg)
        return str(token)

    async def _get(self, client: httpx.AsyncClient, url: str, token: str) -> dict[str, Any]:
        try:
            response = await client.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
        except httpx.HTTPError as exc:
            msg = f"GitHub could not be reached: {exc}"
            raise OAuthError(msg) from exc

        if response.status_code >= 400:
            msg = f"GitHub answered {response.status_code} for {url}"
            raise OAuthError(msg)
        try:
            payload = response.json()
        except ValueError as exc:
            msg = f"GitHub answered {url} with something that is not JSON"
            raise OAuthError(msg) from exc
        if not isinstance(payload, dict):
            msg = f"GitHub answered {url} with {type(payload).__name__}, not an object"
            raise OAuthError(msg)
        return payload

    async def _primary_email(self, client: httpx.AsyncClient, token: str) -> str | None:
        """The verified primary address, or None.

        None is an ordinary outcome, not an error: an account can keep every
        address private, and refusing to sign that person in would be a
        surprising place to draw a line. Nothing here needs the address; it is
        stored so a human can be recognised in an audit log.

        An unverified address is never taken. Anyone can add any address to a
        GitHub account, so an unverified one is a claim rather than an
        identifier, and treating it as one would let somebody impersonate a
        colleague in the audit log.
        """
        try:
            response = await client.get(
                f"{self.api_base.rstrip('/')}/user/emails",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        except httpx.HTTPError:
            return None
        if response.status_code >= 400:
            return None
        try:
            addresses = response.json()
        except ValueError:
            return None
        if not isinstance(addresses, list):
            return None

        for address in addresses:
            if (
                isinstance(address, dict)
                and address.get("primary")
                and address.get("verified")
                and address.get("email")
            ):
                return str(address["email"])
        return None


__all__ = ["SCOPES", "TIMEOUT", "GitHubProvider", "Identity", "IdentityProvider", "OAuthError"]
