from edgescan.errors import MissingCredentialsError


def validate_api_key(key: str) -> str:
    if not key:
        raise MissingCredentialsError("An API key is required")
    return key
