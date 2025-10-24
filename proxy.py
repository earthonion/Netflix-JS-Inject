from mitmproxy import http
import os

def request(flow: http.HTTPFlow) -> None:

    # Trigger an error (probably appboot)
    if "netflix" in flow.request.pretty_host or "playstation" in flow.request.pretty_host:
        flow.response = http.Response.make( 
            200,
            b"uwu"*9999999, # probably don't need this many uwus. just corrupt the response 
            {"Content-Type": "application/x-msl+json"}
        )
        return

    # Map error text js to inject.js
    if "/js/common/config/text/config.text.lruderrorpage" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "inject.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read()
                print(f"[+] Loaded {len(content)} bytes from inject.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
        except FileNotFoundError:
            print(f"[!] ERROR: inject.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: inject.js",
                {"Content-Type": "text/plain"}
            )

