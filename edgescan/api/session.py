import logging
from dataclasses import dataclass, field
from edgescan.constants import MAX_RETRIES_ON_HTTP_REDIRECTS, MAX_RETRIES_ON_HTTP_CONNECTION_ERRORS, \
    MAX_RETRIES_ON_HTTP_READ_ERRORS, HTTP_REQUEST_BACKOFF_FACTOR
from requests import Session as _Session
from requests.adapters import HTTPAdapter, BaseAdapter
from typing import Dict
from typing import Iterable, List
from urllib3.util.retry import Retry

import edgescan.api.authentication

logger = logging.getLogger(__name__)


class Session(_Session):
    def send(self, request, **kwargs):
        url = request.url
        method = request.method
        logger.info("Sending HTTP %s request: %s", method, url)
        response = super(Session, self).send(request=request, **kwargs)
        logger.info("Received HTTP %s response: %s (status code: %d)", method, url, response.status_code)
        return response


@dataclass(frozen=True)
class HttpRequestPolicy:
    def to_http_adapter(self) -> HTTPAdapter:
        raise NotImplementedError()


@dataclass(frozen=True)
class AutomaticRetryPolicy(HttpRequestPolicy):
    max_retries_on_connection_errors: int = MAX_RETRIES_ON_HTTP_CONNECTION_ERRORS
    max_retries_on_read_errors: int = MAX_RETRIES_ON_HTTP_READ_ERRORS
    max_retries_on_redirects: int = MAX_RETRIES_ON_HTTP_REDIRECTS
    backoff_factor: float = HTTP_REQUEST_BACKOFF_FACTOR
    force_retry_on: List[int] = field(default_factory=lambda: [502, 503, 504])

    def to_http_adapter(self) -> HTTPAdapter:
        return HTTPAdapter(
            max_retries=Retry(
                connect=self.max_retries_on_connection_errors,
                read=self.max_retries_on_read_errors,
                redirect=self.max_retries_on_redirects,
                backoff_factor=self.backoff_factor,
                status_forcelist=self.force_retry_on,
                method_whitelist=None,
            )
        )


def get_automatic_retry_policy() -> AutomaticRetryPolicy:
    return AutomaticRetryPolicy()


def get_session(api_key: str) -> Session:
    edgescan.api.authentication.validate_api_key(api_key)

    session = Session()
    session.headers.update(get_http_headers(api_key))

    auto_retry_policy = get_automatic_retry_policy()
    attach_session_policies(session=session, policies=[auto_retry_policy])
    return session


def attach_session_policies(session: Session, policies: Iterable[HttpRequestPolicy]):
    adapters = [policy.to_http_adapter() for policy in policies]
    attach_session_adapters(session=session, adapters=adapters)


def attach_session_adapters(session: Session, adapters: Iterable[BaseAdapter]):
    for prefix in ['http://', 'https://']:
        for adapter in adapters:
            session.mount(prefix, adapter)


def get_http_headers(api_key: str) -> Dict[str, str]:
    return {
        'X-Api-Token': api_key,
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
    }
