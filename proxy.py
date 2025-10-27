#mitmproxy -s proxy.py
from mitmproxy import http
from mitmproxy.proxy.layers import tls
import os

def tls_clienthello(data: tls.ClientHelloData) -> None:
   
    if data.context.server.address:
        hostname = data.context.server.address[0]
        
        # Block sony at TLS layer
        if "playstation" in hostname.lower():
            # Kill the connection before TLS handshake completes
            data.ignore_connection = True
            print(f"[*] Blocked HTTPS connection to: {hostname}")

def request(flow: http.HTTPFlow) -> None:
    """Handle HTTP/HTTPS requests after TLS handshake"""
    if "playstation" in flow.request.pretty_host:
        flow.response = http.Response.make( 
            404,
            b"uwu",  #
        )
        return
    # Trigger an error (probably appboot) and block Sony servers
    if "netflix" in flow.request.pretty_host:
        flow.response = http.Response.make( 
            404,
            b"uwu"*9999999,  # probably don't need this many uwus. just corrupt the response 
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
