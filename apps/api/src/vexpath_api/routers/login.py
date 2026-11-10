"""Signing in, and signing out.

Four routes, all of them plain redirects and one HTML page. There is no
JavaScript in this flow and there could not be: an authorisation code exchange
is a sequence of browser redirects, which is the one thing the web has always
done without help.

The order of checks in the callback is the security of the whole flow, so it is
written out rather than left to the reader: **state first, code second,
everything else after.** A callback that exchanged the code before verifying
the state would have already spent an attacker's authorisation code by the
time it noticed.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from vexpath_api.dependencies import get_engine
from vexpath_api.oauth import GitHubProvider, IdentityProvider, OAuthError
from vexpath_api.session import (
    LOGIN_PATH,
    CsrfVerified,
    CurrentSession,
    clear_session_cookie,
    create_session,
    revoke_session,
    safe_return_path,
    set_session_cookie,
    sign_in,
)
from vexpath_api.templating import render
from vexpath_platform import sessions as tokens
from vexpath_platform.logging import get_logger
from vexpath_platform.settings import Settings, get_settings

log = get_logger(__name__)

router = APIRouter(tags=["login"], include_in_schema=False)

#: Where the provider sends the browser back to. Fixed rather than derived from
#: the incoming request, because a redirect URI taken from a request header is
#: a redirect URI an attacker chooses.
CALLBACK_PATH = "/auth/github/callback"


def get_provider(request: Request) -> IdentityProvider | None:
    """The identity provider, or None when this deployment has no credentials.

    Taken from application state when something put one there, which is how a
    test exercises every branch of the flow without a network, and how GitHub
    Enterprise would be configured.
    """
    injected = getattr(request.app.state, "identity_provider", None)
    if injected is not None:
        provider: IdentityProvider = injected
        return provider

    settings: Settings = request.app.state.settings
    if not settings.sign_in_available:
        return None
    assert settings.github_client_id is not None  # narrowed by sign_in_available
    assert settings.github_client_secret is not None
    return GitHubProvider(
        client_id=settings.github_client_id,
        client_secret=settings.github_client_secret,
        oauth_base=settings.github_oauth_base,
        api_base=settings.github_api_base,
    )


@router.get(LOGIN_PATH, response_class=HTMLResponse, response_model=None, summary="Sign in")
async def login_page(
    request: Request,
    session: CurrentSession,
    provider: Annotated[IdentityProvider | None, Depends(get_provider)],
    next_path: Annotated[str | None, Query(alias="next")] = None,
    error: Annotated[str | None, Query()] = None,
) -> HTMLResponse | RedirectResponse:
    """The sign-in page.

    A browser that is already signed in is sent on rather than shown a sign-in
    form, because a form that does nothing is a form people fill in twice.
    """
    target = safe_return_path(next_path)
    if session is not None:
        return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)

    return render(
        request,
        "login.html",
        {
            "next": target,
            # Said on the page when the deployment has no credentials. A
            # sign-in button that redirects into a GitHub error page is the
            # most confusing possible way to be misconfigured.
            "available": provider is not None,
            "error": _error_message(error),
        },
    )


def _error_message(code: str | None) -> str | None:
    """What to show after a failed attempt.

    A closed vocabulary rather than an echoed query parameter: text taken from
    the URL and rendered on the page is how a phishing message gets hosted on
    somebody else's domain, autoescaping or not.
    """
    messages = {
        "denied": "GitHub sign-in was cancelled. Nothing was shared.",
        "state": "That sign-in link had expired. Please try again.",
        "provider": "GitHub could not complete the sign-in. Please try again.",
    }
    return messages.get(code or "")


@router.get("/auth/github/start", summary="Begin GitHub sign-in")
async def start(
    request: Request,
    provider: Annotated[IdentityProvider | None, Depends(get_provider)],
    next_path: Annotated[str | None, Query(alias="next")] = None,
) -> RedirectResponse:
    """Redirect to GitHub with a signed state parameter.

    The state carries where to return to, signed, so the destination cannot be
    edited while it is out of this application's hands.
    """
    if provider is None:
        return RedirectResponse(LOGIN_PATH, status_code=status.HTTP_303_SEE_OTHER)

    settings: Settings = request.app.state.settings
    state = tokens.sign_state(settings.secret_key, safe_return_path(next_path))
    url = provider.authorize_url(redirect_uri=_redirect_uri(settings), state=state)
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


@router.get(CALLBACK_PATH, summary="Complete GitHub sign-in")
async def callback(
    request: Request,
    provider: Annotated[IdentityProvider | None, Depends(get_provider)],
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
) -> RedirectResponse:
    """Verify the state, exchange the code, and establish a session.

    Every failure lands back on the sign-in page with a short reason. The
    detail goes to the log: a sign-in failure page that explained which part of
    a forged request was wrong would be a debugging aid for whoever forged it.
    """
    settings: Settings = request.app.state.settings

    if error or provider is None:
        # The user declined on GitHub's own screen, which is not a fault.
        log.info("api.signin.declined", reason=error or "unconfigured")
        return _back("denied")

    # State first. Exchanging the code before this check would spend an
    # attacker's authorisation code before noticing the request was forged,
    # and the point of the state parameter is that the code is never spent.
    return_to = tokens.verify_state(settings.secret_key, state or "")
    if return_to is None:
        log.info("api.signin.bad_state")
        return _back("state")
    if not code:
        return _back("provider")

    try:
        identity = await provider.identity(code=code, redirect_uri=_redirect_uri(settings))
    except OAuthError as exc:
        # Logged in full, shown as one sentence.
        log.warning("api.signin.provider_error", error=str(exc))
        return _back("provider")

    engine = get_engine(request)
    async with engine.begin() as connection:
        # The owner's connection: there is no organisation in scope yet, and
        # finding out which one applies is what this does.
        user_id, org_id = await sign_in(connection, identity, provider=provider.provider)
        secret = await create_session(connection, user_id=user_id, org_id=org_id)

    log.info("api.signin.ok", user=user_id, org=org_id, provider=provider.provider)
    response = RedirectResponse(safe_return_path(return_to), status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(response, secret, settings)
    return response


def _back(reason: str) -> RedirectResponse:
    return RedirectResponse(f"{LOGIN_PATH}?error={reason}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/logout", summary="Sign out")
async def logout(request: Request, principal: CsrfVerified) -> RedirectResponse:
    """End the session and clear the cookie.

    A POST, not a GET. A sign-out on a GET can be triggered by any image tag
    on any page, which is a nuisance rather than a breach but an avoidable one,
    and the CSRF token is verified for the same reason every other
    state-changing form carries one.
    """
    engine = get_engine(request)
    async with engine.begin() as connection:
        # The owner's connection: the row is being deleted, and doing it under
        # a tenant context would make the delete depend on the context being
        # right rather than on the session identifier.
        await revoke_session(connection, principal.session_id)

    settings: Settings = request.app.state.settings
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    clear_session_cookie(response, settings)
    log.info("api.signout", user=principal.user_id)
    return response


def _redirect_uri(settings: Settings) -> str:
    return f"{settings.base_url.rstrip('/')}{CALLBACK_PATH}"


def resolve_settings() -> Settings:
    """Process settings, as a dependency, for handlers that need them."""
    return get_settings()


__all__ = ["CALLBACK_PATH", "get_provider", "router"]
