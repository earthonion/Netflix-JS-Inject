# Netflix 'N Hack

Inject custom JavaScript into the Netflix PS5 error screen by intercepting Netflix's requests to localhost.

PS5 firmware version: 4.03-12.XX

Lowest working version: https://prosperopatches.com/PPSA01615?v=05.000.000

> This project uses a local MITM proxy to inject and execute `inject.js` on the Netflix error page
---
## Netflix Versions Tested On PS5

| Version    | Works |
|-------------|:-----:|
| 01.000.000  | ❌ |
| 01.100.000  | ❌ |
| 02.000.000  | ❌ |
| 03.000.000  | ❌ |
| 04.000.000  | ❌ |
| [05.000.000 US](https://prosperopatches.com/PPSA01614?v=05.000.000) | ✅ |
| [06.000.000 EU](https://prosperopatches.com/PPSA01615?v=06.000.000) | ✅ |
| 07.000.000  | ❌ |
| 08.000.000  | ❌ |
| 09.000.000  | ❌ |
| 10.000.000  | ❌ |
| 11.000.000  | ❌ |
| 12.000.000  | ❌ |
| 13.000.000  | ❌ |
| 14.000.000  | ❌ |
| 15.000.000  | ❌ |
| 16.000.000  | ❌ |
| 17.000.000  | ❌ |
| 18.000.000  | ❌ |

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

Current script will trigger after the WebSocket for remote logging is initiated.

```bash
# install websockets
pip install websockets

# run WebSocket server
python ws.py

```

### Network / Proxy Setup

On your PS5:

1. Go to Settings → Network.


2. Select Set Up Internet Connection and choose your connection type (Wi-Fi or LAN).


3. Use Automatic for DNS Settings and MTU Settings.


4. When prompted for Proxy Server, choose Use and enter:

- IP address: \<your local machine IP\>

- Port: 8080



5. Save settings and run Test Internet Connection (be ready to press it).



> Make sure your PC running mitmproxy is on the same network and reachable at the IP you entered.




---

### Netflix

Open the Netflix app on the PS5.

Wait for Netflix to hit the error flow (probably ui-800)

If injection is successful, the error screen will load and inject.js will be executed. Netflix may crash after the injection depending on payload.

### credits 
- HUGE thanks to [c0w-ar](https://github.com/c0w-ar/) for complete inject.js userland exploit.
- [ufm42](https://github.com/ufm42) for regex sandbox escape exploit and ideas! 
- [autechre](https://github.com/autechre-warp) for the idea!
- Dr.YenYen for testing!
- [Gezine](https://github.com/gezine)for help with exploit/Y2JB for reference 


---
### License

This repository uses the GNU license. See LICENSE for details.
