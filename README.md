# Netflix N Hack

Inject custom JavaScript into the Netflix PS5 error screen by intercepting Netflix's requests to localhost.

PS5 firmware version: 4.03-12.XX

Lowest working version: https://prosperopatches.com/PPSA01615?v=05.000.000

This is a PoC of ROP and Syscall developed while learning about PS5 v8 (Javascript) userland exploiting techniques. Code is intended for developers.

Code working on NF App EU 6.000 : https://prosperopatches.com/PPSA01615

> This project uses a local MITM proxy to inject and execute `inject.js` on the Netflix error page
---
## Tested On PS5 

| Version    | Works |
|-------------|:-----:|
| 01.000.000  | ❌ |
| 01.100.000  | ❌ |
| 02.000.000  | ❌ |
| 03.000.000  | ❌ |
| 04.000.000  | ❌ |
| [05.000.000](https://prosperopatches.com/PPSA01615?v=05.000.000) | ✅ |
| [06.000.000](https://prosperopatches.com/PPSA01615?v=06.000.000) | ✅ |
| [07.000.000](https://prosperopatches.com/PPSA01615?v=07.000.000) | ✅ |
| [08.000.000](https://prosperopatches.com/PPSA01615?v=08.000.000) | ✅ |
| [09.000.000](https://prosperopatches.com/PPSA01615?v=09.000.000) | ✅ |
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
- earthonion for base code https://github.com/earthonion/Netflix-N-Hack
- autechre for the idea https://github.com/autechre-warp
- Dr.YenYen for testing!
- Gezine for help with exploit/Y2JB for reference
- ufm42 for exploit ideas as well

---
### License

This repository uses the GNU license. See LICENSE for details.
