from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import os
from collections import defaultdict

app = FastAPI(title="MES Pro+", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

rooms: dict[str, set[WebSocket]] = defaultdict(set)
online_counts: dict[str, int] = defaultdict(int)

@app.get("/", response_class=HTMLResponse)
async def root():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/room/{room_id}", response_class=HTMLResponse)
async def room_page(room_id: str):
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.websocket("/ws/{room_id}")
async def ws_endpoint(ws: WebSocket, room_id: str):
    await ws.accept()
    rooms[room_id].add(ws)
    online_counts[room_id] = len(rooms[room_id])
    await broadcast_count(room_id)
    try:
        while True:
            msg = await ws.receive()
            if msg.get("type") != "websocket.receive":
                continue
            # Relay text frames (encrypted JSON packets from clients)
            if msg.get("text") is not None:
                data = msg["text"]
                # Guard single-frame size (~1.5 MiB per frame is fine with chunking)
                if len(data) > 1_600_000:
                    continue
                dead = []
                for peer in rooms[room_id]:
                    try:
                        if peer is ws:
                            continue
                        await peer.send_text(data)
                    except Exception:
                        dead.append(peer)
                for d in dead:
                    rooms[room_id].discard(d)
            # Binary frames passthrough (not used by current client)
            elif msg.get("bytes") is not None:
                data_b = msg["bytes"]
                if len(data_b) > 1_600_000:
                    continue
                dead = []
                for peer in rooms[room_id]:
                    try:
                        if peer is ws:
                            continue
                        await peer.send_bytes(data_b)
                    except Exception:
                        dead.append(peer)
                for d in dead:
                    rooms[room_id].discard(d)
            online_counts[room_id] = len(rooms[room_id])
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        rooms[room_id].discard(ws)
        online_counts[room_id] = len(rooms[room_id])
        await broadcast_count(room_id)

async def broadcast_count(room_id: str):
    msg = '{"_control":"online","count":%d}' % online_counts[room_id]
    dead = []
    for peer in rooms[room_id]:
        try:
            await peer.send_text(msg)
        except Exception:
            dead.append(peer)
    for d in dead:
        rooms[room_id].discard(d)
    online_counts[room_id] = len(rooms[room_id])

if __name__ == "__main__":
    import uvicorn, os
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("app:app", host="127.0.0.1", port=port, reload=True)
