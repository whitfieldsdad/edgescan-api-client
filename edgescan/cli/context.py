from edgescan.constants import DEFAULT_API_KEY, DEFAULT_HOST


def get_context(edgescan_host: str = DEFAULT_HOST, edgescan_api_key: str = DEFAULT_API_KEY) -> dict:
    return {
        'config': {
            'edgescan': {
                'host': edgescan_host,
                'api_key': edgescan_api_key,
            }
        }
    }
