from mitmproxy import http
from urllib.parse import urlsplit, parse_qs, unquote_plus
from datetime import datetime, timezone
import json

LOG_FILE = "/logs/mitm.log"


def request(flow: http.HTTPFlow):
    request_url = flow.request.pretty_url

    # Parse URL
    parsed = urlsplit(request_url)

    # Keep only scheme + host + path.
    # Everything after '?' is removed.
    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Extract ?q=...
    search_term = ""

    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)

        if "q" in params and params["q"]:
            search_term = unquote_plus(params["q"][0])

    log = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "web_visit",
        "client_ip": flow.client_conn.address[0],
        "method": flow.request.method,
        "host": flow.request.host,
        "url": clean_url,
        "search_term": search_term
    }

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log, ensure_ascii=False) + "\n")
        f.flush()
