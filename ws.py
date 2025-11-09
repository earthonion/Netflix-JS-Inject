import ssl
import asyncio
import websockets

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
#openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"

async def handle_client(websocket: websockets.WebSocketServerProtocol):
    client_ip = websocket.remote_address[0]
    print(f"Client connected from {client_ip}")

    try:
        async for message in websocket:
            print(message)
    except websockets.ConnectionClosed:
        print("Client disconnected")

async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 1337, ssl=ssl_context):
        print("listening to 0.0.0.0:1337...")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())