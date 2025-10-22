# Netflix-PS4-JS-Inject

Inject custom JavaScript into the Netflix PS4 error screen by intercepting Netflix's requests to localhost.

> This project uses a local MITM proxy to inject and execute `inject.js` on the Netflix error page

---

## Requirements

- Python (for `mitmproxy`)
- `mitmproxy` (`pip install mitmproxy`)

---

## Installation & Usage

```bash
# install mitmproxy
pip install mitmproxy

# clone repository
git clone https://github.com/earthonion/Netflix-PS4-JS-Inject/
cd Netflix-PS4-JS-Inject

# run mitmproxy with the provided script
mitmproxy -s proxy.py


```

### Network / Proxy Setup

On your PS4:

1. Go to Settings → Network.


2. Select Set Up Internet Connection and choose your connection type (Wi-Fi or LAN).


3. Use Automatic for DNS Settings and MTU Settings.


4. When prompted for Proxy Server, choose Use and enter:

IP address: <your local machine IP> (example: 192.168.1.100)

Port: 8080



5. Save settings and run Test Internet Connection (be ready to press it).



> Make sure your PC running mitmproxy is on the same network and reachable at the IP you entered.




---

### Netflix

Open the Netflix app on the PS4.

Wait for Netflix to hit the error flow (probably ui-800)

If injection is successful, the error screen will load and inject.js will be executed. Netflix may crash after the injection depending on payload.


---
### License

This repository uses the GNU license. See LICENSE for details.
