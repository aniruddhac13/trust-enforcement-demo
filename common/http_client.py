import requests
from typing import Any, Dict, Optional
from common.config import REQUEST_TIMEOUT_SECONDS

def request_json(method: str, url: str, json_body: Optional[Dict[str, Any]] = None, files=None, data=None, headers=None):
    response = requests.request(
        method=method,
        url=url,
        json=json_body,
        files=files,
        data=data,
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()
    return response
