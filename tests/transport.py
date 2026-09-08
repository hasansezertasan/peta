"""A deterministic transport for exercising peta's shared HTTP client.

Sources reach the network only through :mod:`peta.core.http`, so tests install
a real :class:`httpx.Client` backed by :class:`httpx.MockTransport` rather than
replacing the ``httpx`` module with a mock. The request path — URL building,
query parameters, headers, status handling, body decoding — is therefore the
same one production runs, and canned replies are real
:class:`httpx.Response` objects, so headers and status codes behave.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["FakeTransport"]


@dataclass(frozen=True)
class _Reply:
    """One canned outcome, matched against a substring of the request URL."""

    match: str
    status: int = 200
    json: object | None = None
    text: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    error: Exception | None = None

    def to_response(self, request: httpx.Request) -> httpx.Response:
        """Build the response this reply describes.

        Returns:
            The canned response, bound to ``request``.
        """
        if self.text is not None:
            return httpx.Response(
                self.status, text=self.text, headers=self.headers, request=request
            )
        if self.json is not None:
            return httpx.Response(
                self.status, json=self.json, headers=self.headers, request=request
            )
        return httpx.Response(self.status, headers=self.headers, request=request)


class FakeTransport:
    """Answers peta's shared client from canned replies, recording requests."""

    def __init__(self) -> None:
        """Start with no replies queued and nothing recorded."""
        self.requests: list[httpx.Request] = []
        self.on_request: Callable[[httpx.Request], None] | None = None
        """Run for each request before it is answered.

        Separate from the canned replies, which say *what* comes back: this
        says something about *when*. Tests that need a request to block, or to
        observe that two overlap, set it; nothing else has to know.
        """
        self._replies: list[_Reply] = []

    def reply(
        self,
        *,
        url: str = "",
        status: int = 200,
        json: object | None = None,
        text: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Answer requests whose URL contains ``url`` with this response.

        The most recently registered matching reply answers, so a test can
        change what a URL returns partway through — a source that first sends
        a body and then answers "not modified", say. Replies are reusable, so
        one registration serves however many matching requests follow it. An
        empty ``url`` matches everything, which is what a test exercising a
        single source wants.

        Args:
            url: Substring the request URL must contain to match.
            status: HTTP status to return.
            json: Body to serialize as JSON, or ``None`` for no body.
            text: Raw body text, for exercising undecodable responses.
            headers: Response headers.
        """
        self._replies.append(
            _Reply(
                match=url, status=status, json=json, text=text, headers=headers or {}
            )
        )

    def fail(self, error: Exception, *, url: str = "") -> None:
        """Raise ``error`` instead of replying to requests matching ``url``.

        Args:
            error: The transport-level exception to raise, such as
                :class:`httpx.ConnectError`.
            url: Substring the request URL must contain to match.
        """
        self._replies.append(_Reply(match=url, error=error))

    @property
    def request(self) -> httpx.Request:
        """The one request that was made.

        Returns:
            The single recorded request.
        """
        assert len(self.requests) == 1, f"expected 1 request, got {self.requests}"
        return self.requests[0]

    def handle(self, request: httpx.Request) -> httpx.Response:
        """Record ``request`` and answer it from the queued replies.

        A matching :meth:`fail` registration raises its own exception instead
        of returning, standing in for a transport-level failure.

        Returns:
            The most recently registered matching response.

        Raises:
            AssertionError: If no reply matches, which means the test made a
                request it did not set up.
        """
        self.requests.append(request)
        if self.on_request is not None:
            self.on_request(request)
        url = str(request.url)
        for reply in reversed(self._replies):
            if reply.match not in url:
                continue
            if reply.error is not None:
                raise reply.error
            return reply.to_response(request)
        msg = f"no reply registered for {url}"
        raise AssertionError(msg)
