# Netflix 'N Hack

Inject custom JavaScript into the Netflix PS5 error screen by intercepting Netflix's requests to localhost.

PS5 firmware version: 4.03-12.XX

Lowest working version: https://prosperopatches.com/PPSA01615?v=05.000.000

> This project uses a local MITM proxy to inject and execute `inject.js` on the Netflix error page


---
# Instructions

## Download image from [Releases](https://github.com/earthonion/Netflix-N-Hack/releases/latest)

### M.2 Drive Setup (Windows Only)

> **Note:** For the current M.2 drives, Windows is required. Append their names with `Windows_Only` for clarity.

#### Step 1: Download Required Software
- Download **HDD Raw Copy Tool** from:  
  [https://hddguru.com/software/HDD-Raw-Copy-Tool/](https://hddguru.com/software/HDD-Raw-Copy-Tool/)

#### Step 2: Connect the M.2 Drive
- Plug the M.2 SSD into your PC using:
  - An **M.2 enclosure**, or  
  - A **spare M.2 slot** on your motherboard.

#### Step 3: Prepare the Image
- Unzip the image file corresponding to your SSD size.

#### Step 4: Write the Image to the M.2 Drive
1. Open **HDD Raw Copy Tool**.
2. Next to **FILE**, double-click and select the unzipped image file.
3. Click **Continue**.
4. Select your **empty M.2 drive** as the destination.
5. Click **START** to begin the imaging process.

---

### System Backup Restore

#### Step 1: Prepare the Backup USB
1. Format a USB drive as **exFAT** or **FAT32**.
2. Unzip the **system backup** onto the formatted USB drive.

#### Step 2: Restore the System
Follow Sony’s official guide to restore your PS5 system from the USB:  
[https://www.playstation.com/en-gb/support/hardware/back-up-ps5-data-USB/](https://www.playstation.com/en-gb/support/hardware/back-up-ps5-data-USB/)




# Safe Internet Connection Setup for Netflix

## Step 1: Open Network Settings
1. On your console, go to:  
   **Settings > Network > Settings > Set Up Internet Connection**

2. Scroll to the bottom and select:  
   **Set Up Manually**

---

## Step 2: Choose Connection Type
- **Wi-Fi:** Select **Use Wi-Fi**  
- **LAN Cable:** Select **Use a LAN Cable**

If using **Wi-Fi**:
1. Choose **Enter Manually**.  
2. Set **Security Method** to **WPA-Personal** (or similar).  
3. Enter your **Wi-Fi network name** and **password**.

---

## Step 3: Configure Proxy Settings
For either **Wi-Fi** or **LAN**, continue the setup:

1. Scroll to the **Proxy** setting.  
2. Change it from **Automatic** to **Manual**.  
3. Enter the following details:

   - **Address:** `172.105.156.37`  
   - **Port:** `42069`

4. Press **Done** to save your settings.

---

## Step 4: Finalize and Connect
- Wait for the console to attempt a connection.  
- You may see a **network failure or PSN connection error** — this is expected and can be safely ignored.  
- The connection will still function normally.  

You can now open **YouTube** to send your payload or continue using **Netflix** safely.



---
# How to run proxy locally

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

### Credits 
- HUGE thanks to [c0w-ar](https://github.com/c0w-ar/) for complete inject.js userland exploit and lapse port!
- [ufm42](https://github.com/ufm42) for regex sandbox escape exploit and ideas! 
- [autechre](https://github.com/autechre-warp) for the idea!
- Dr.yenyen for testing and coordinating system back up, and much more help!
- [Gezine](https://github.com/gezine) for help with exploit/Y2JB for reference and lapse port!
- Rush for creating system backup, 256GB and 2TB images !
- Jester for testing 2TB!

---
### License

This repository uses the GNU license. See LICENSE for details.
