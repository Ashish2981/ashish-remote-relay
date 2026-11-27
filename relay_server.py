"""
Ashish PC Solutions - Direct Relay Server
=========================================
Central WebSocket relay server with SQLite device registry (fixed Support ID +
persistent static Access PIN per PC). No username/password login required.

Usage:
  Start server:
    python relay_server.py serve
    python relay_server.py serve --host 0.0.0.0 --port 8765

  Optional Device Management CLI (can run while server is live):
    python relay_server.py list-devices
    python relay_server.py set-pin --support-id 100-234-567 --pin 998877
    python relay_server.py suspend-device --support-id 100-234-567
    python relay_server.py activate-device --support-id 100-234-567
    python relay_server.py delete-device --support-id 100-234-567
"""

from __future__ import annotations

import argparse
import asyncio
from http import HTTPStatus
import json
import logging
import os
import secrets
import sqlite3
import ssl
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Set

import websockets
from websockets.exceptions import ConnectionClosed

# ==============================================================================
# SERVER CONFIGURATION (Edit these for your VPS / Cloud Server)
# ==============================================================================
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = int(os.environ.get("PORT", "8765"))
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "relay_devices.db")

# Set USE_SSL = True and provide valid certificate paths (e.g., Let's Encrypt)
# for encrypted WSS transport over the public internet.
USE_SSL = False
SSL_CERT = "/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
SSL_KEY = "/etc/letsencrypt/live/yourdomain.com/privkey.pem"

MAX_WS_MESSAGE_SIZE = 32 * 1024 * 1024  # 32 MB max frame size

# Binary frame magic bytes (must match client_app.py)
BIN_VIDEO_FRAME = 0x01
BIN_FILE_CHUNK = 0x02

# Whitelist of JSON message types allowed to be relayed between session peers
RELAYED_JSON_TYPES: Set[str] = {
    "screen_meta",
    "quality_set",
    "mouse_event",
    "key_event",
    "system_action",
    "clipboard_sync",
    "chat_message",
    "fs_list_req",
    "fs_list_resp",
    "fs_mkdir_req",
    "fs_mkdir_resp",
    "file_start",
    "file_pull_req",
    "file_end",
    "file_ack",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("AshishRelay")


# ==============================================================================
# DATABASE LAYER (SQLite Device Registry)
# ==============================================================================
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_support_id(raw_id: str) -> str:
    """Strip dashes and spaces and format 9 digits as XXX-XXX-XXX."""
    digits = "".join(ch for ch in raw_id.strip() if ch.isdigit())
    if len(digits) == 9:
        return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    return raw_id.strip()


def get_db_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_uid TEXT UNIQUE NOT NULL,
                support_id TEXT UNIQUE NOT NULL,
                access_pin TEXT NOT NULL,
                device_name TEXT NOT NULL DEFAULT '',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_seen TEXT
            );
            """
        )
        conn.commit()


def generate_unique_support_id(conn: sqlite3.Connection) -> str:
    for _ in range(100):
        num = secrets.randbelow(900_000_000) + 100_000_000
        s = str(num)
        formatted = f"{s[:3]}-{s[3:6]}-{s[6:]}"
        row = conn.execute(
            "SELECT 1 FROM devices WHERE support_id = ?", (formatted,)
        ).fetchone()
        if not row:
            return formatted
    raise RuntimeError("Failed to generate a unique Support ID.")


def register_or_load_device(
    machine_uid: str,
    access_pin: str,
    device_name: str,
    db_path: str = DB_PATH,
) -> tuple[Optional[dict], Optional[str]]:
    machine_uid = machine_uid.strip()
    if not machine_uid:
        return None, "Invalid machine identifier."

    pin = access_pin.strip() or f"{secrets.randbelow(900_000) + 100_000}"
    if len(pin) < 4:
        return None, "Access PIN must be at least 4 characters."

    init_db(db_path)
    with get_db_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE machine_uid = ?", (machine_uid,)
        ).fetchone()
        if row:
            if not row["is_active"]:
                return None, "This Support ID has been suspended by the administrator."
            conn.execute(
                "UPDATE devices SET device_name = ?, last_seen = ? WHERE id = ?",
                (device_name[:64], utc_now_iso(), row["id"]),
            )
            conn.commit()
            updated = conn.execute(
                "SELECT * FROM devices WHERE id = ?", (row["id"],)
            ).fetchone()
            return dict(updated), None

        sid = generate_unique_support_id(conn)
        now = utc_now_iso()
        conn.execute(
            """
            INSERT INTO devices (machine_uid, support_id, access_pin, device_name, is_active, created_at, last_seen)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (machine_uid, sid, pin, device_name[:64], now, now),
        )
        conn.commit()
        created = conn.execute(
            "SELECT * FROM devices WHERE machine_uid = ?", (machine_uid,)
        ).fetchone()
        return dict(created), None


def update_device_pin(
    support_id: str, new_pin: str, db_path: str = DB_PATH
) -> bool:
    sid = normalize_support_id(support_id)
    new_pin = new_pin.strip()
    if len(new_pin) < 4 or len(new_pin) > 20:
        raise ValueError("Access PIN must be 4 to 20 characters.")
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        cur = conn.execute(
            "UPDATE devices SET access_pin = ? WHERE support_id = ? AND is_active = 1",
            (new_pin, sid),
        )
        conn.commit()
        return cur.rowcount > 0


def set_device_active(
    support_id: str, active: bool, db_path: str = DB_PATH
) -> bool:
    sid = normalize_support_id(support_id)
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        cur = conn.execute(
            "UPDATE devices SET is_active = ? WHERE support_id = ?",
            (1 if active else 0, sid),
        )
        conn.commit()
        return cur.rowcount > 0


def delete_device(support_id: str, db_path: str = DB_PATH) -> bool:
    sid = normalize_support_id(support_id)
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        cur = conn.execute("DELETE FROM devices WHERE support_id = ?", (sid,))
        conn.commit()
        return cur.rowcount > 0


def list_devices(db_path: str = DB_PATH) -> list[dict]:
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT support_id, access_pin, device_name, is_active, created_at, last_seen
            FROM devices ORDER BY id ASC
            """
        ).fetchall()
        return [dict(r) for r in rows]


def get_device_by_support_id(
    support_id: str, db_path: str = DB_PATH
) -> Optional[dict]:
    sid = normalize_support_id(support_id)
    with get_db_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE support_id = ?", (sid,)
        ).fetchone()
        return dict(row) if row else None


def is_device_active(support_id: str, db_path: str = DB_PATH) -> bool:
    with get_db_connection(db_path) as conn:
        row = conn.execute(
            "SELECT is_active FROM devices WHERE support_id = ?", (support_id,)
        ).fetchone()
        return bool(row and row["is_active"])


# ==============================================================================
# WEBSOCKET RELAY STATE & HANDLERS
# ==============================================================================
@dataclass
class ConnectedClient:
    ws: websockets.WebSocketServerProtocol
    support_id: Optional[str] = None
    device_name: str = ""
    session_ids: Set[str] = field(default_factory=set)
    registered: bool = False


@dataclass
class ActiveSession:
    session_id: str
    controller: ConnectedClient
    host: ConnectedClient

    def get_peer(self, sender: ConnectedClient) -> Optional[ConnectedClient]:
        if sender is self.controller:
            return self.host
        if sender is self.host:
            return self.controller
        return None


class RelayServer:
    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        init_db(self.db_path)
        self.clients_by_ws: Dict[object, ConnectedClient] = {}
        self.clients_by_sid: Dict[str, ConnectedClient] = {}
        self.sessions: Dict[str, ActiveSession] = {}

    async def send_json(self, ws: object, payload: dict) -> bool:
        try:
            await ws.send(json.dumps(payload))
            return True
        except Exception:
            return False

    async def end_session(
        self, session_id: str, reason: str, notify: bool = True
    ) -> None:
        session = self.sessions.pop(session_id, None)
        if not session:
            return
        session.controller.session_ids.discard(session_id)
        session.host.session_ids.discard(session_id)
        logger.info(
            "Session ended [%s] (%s <-> %s): %s",
            session_id[:8],
            session.controller.support_id,
            session.host.support_id,
            reason,
        )
        if notify:
            msg = {"type": "session_ended", "session_id": session_id, "reason": reason}
            await asyncio.gather(
                self.send_json(session.controller.ws, msg),
                self.send_json(session.host.ws, msg),
                return_exceptions=True,
            )

    async def handle_json_message(self, client: ConnectedClient, data: dict) -> None:
        mtype = data.get("type", "")

        if mtype == "register_device":
            machine_uid = str(data.get("machine_uid", ""))
            access_pin = str(data.get("access_pin", ""))
            device_name = str(data.get("device_name", "")) or "Windows PC"

            dev, err = register_or_load_device(
                machine_uid, access_pin, device_name, db_path=self.db_path
            )
            if err or not dev:
                await self.send_json(
                    client.ws,
                    {"type": "register_error", "message": err or "Registration failed."},
                )
                return

            sid = dev["support_id"]
            old = self.clients_by_sid.get(sid)
            if old and old is not client:
                try:
                    await old.ws.close(code=4001, reason="Duplicate connection")
                except Exception:
                    pass

            client.support_id = sid
            client.device_name = device_name[:64]
            client.registered = True
            self.clients_by_sid[sid] = client

            await self.send_json(
                client.ws,
                {
                    "type": "registered",
                    "support_id": sid,
                    "access_pin": dev["access_pin"],
                    "device_name": client.device_name,
                },
            )
            logger.info(
                "Device online: id=%s name=%s", client.support_id, client.device_name
            )
            return

        if mtype == "ping":
            await self.send_json(client.ws, {"type": "pong"})
            return

        if not client.registered or not client.support_id:
            await self.send_json(
                client.ws,
                {"type": "error", "message": "Device not registered with relay yet."},
            )
            return

        if mtype == "update_pin":
            new_pin = str(data.get("new_pin", "")).strip()
            try:
                ok = update_device_pin(
                    client.support_id, new_pin, db_path=self.db_path
                )
                if ok:
                    await self.send_json(
                        client.ws, {"type": "pin_updated", "access_pin": new_pin}
                    )
                else:
                    await self.send_json(
                        client.ws,
                        {"type": "error", "message": "Unable to update PIN."},
                    )
            except ValueError as exc:
                await self.send_json(client.ws, {"type": "error", "message": str(exc)})
            return

        if mtype == "connect_request":
            target_id = normalize_support_id(str(data.get("target_id", "")))
            pin = str(data.get("pin", "")).strip()

            if not target_id:
                await self.send_json(
                    client.ws,
                    {"type": "connect_error", "message": "Please enter a Partner Support ID."},
                )
                return
            if target_id == client.support_id:
                await self.send_json(
                    client.ws,
                    {"type": "connect_error", "message": "You cannot connect to your own Support ID."},
                )
                return

            host_client = self.clients_by_sid.get(target_id)
            if not host_client or not host_client.registered:
                await self.send_json(
                    client.ws,
                    {
                        "type": "connect_error",
                        "message": f"Partner {target_id} is currently offline.",
                    },
                )
                return

            host_dev = get_device_by_support_id(target_id, db_path=self.db_path)
            if not host_dev or not host_dev["is_active"]:
                await self.send_json(
                    client.ws,
                    {"type": "connect_error", "message": "Partner device is suspended or unavailable."},
                )
                return

            if not secrets.compare_digest(pin, str(host_dev["access_pin"])):
                await self.send_json(
                    client.ws,
                    {"type": "connect_error", "message": "Invalid Partner Access PIN."},
                )
                return

            if host_client.session_ids:
                await self.send_json(
                    client.ws,
                    {
                        "type": "connect_error",
                        "message": "Partner already has an active remote support session.",
                    },
                )
                return

            session_id = str(uuid.uuid4())
            session = ActiveSession(
                session_id=session_id, controller=client, host=host_client
            )
            self.sessions[session_id] = session
            client.session_ids.add(session_id)
            host_client.session_ids.add(session_id)

            logger.info(
                "Session started [%s]: %s -> %s (%s)",
                session_id[:8],
                client.support_id,
                host_client.support_id,
                host_client.device_name,
            )

            await self.send_json(
                client.ws,
                {
                    "type": "session_started",
                    "session_id": session_id,
                    "role": "controller",
                    "peer_name": host_client.device_name,
                    "peer_id": host_client.support_id,
                },
            )
            await self.send_json(
                host_client.ws,
                {
                    "type": "session_started",
                    "session_id": session_id,
                    "role": "host",
                    "peer_name": client.device_name,
                    "peer_id": client.support_id,
                },
            )
            return

        if mtype == "end_session":
            session_id = str(data.get("session_id", ""))
            session = self.sessions.get(session_id)
            if session and session_id in client.session_ids:
                await self.end_session(
                    session_id,
                    reason=f"Ended by {client.device_name or client.support_id}",
                    notify=True,
                )
            return

        if mtype in RELAYED_JSON_TYPES:
            session_id = str(data.get("session_id", ""))
            session = self.sessions.get(session_id)
            if not session:
                return
            peer = session.get_peer(client)
            if peer:
                await self.send_json(peer.ws, data)
            return

    async def handle_binary_message(
        self, client: ConnectedClient, payload: bytes
    ) -> None:
        if not client.registered or len(payload) < 37:
            return
        try:
            session_id = payload[1:37].decode("ascii")
        except UnicodeDecodeError:
            return
        session = self.sessions.get(session_id)
        if not session:
            return
        peer = session.get_peer(client)
        if not peer:
            return
        try:
            await peer.ws.send(payload)
        except Exception:
            pass

    async def cleanup_client(self, client: ConnectedClient) -> None:
        if client.support_id and self.clients_by_sid.get(client.support_id) is client:
            self.clients_by_sid.pop(client.support_id, None)
        for sid in list(client.session_ids):
            await self.end_session(
                sid,
                reason=f"{client.device_name or client.support_id or 'Peer'} disconnected",
                notify=True,
            )

    async def ws_handler(self, websocket, path=None) -> None:
        client = ConnectedClient(ws=websocket)
        self.clients_by_ws[websocket] = client
        remote = getattr(websocket, "remote_address", None)
        try:
            async for message in websocket:
                if isinstance(message, bytes):
                    await self.handle_binary_message(client, message)
                else:
                    try:
                        data = json.loads(message)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(data, dict):
                        await self.handle_json_message(client, data)
        except ConnectionClosed:
            pass
        except Exception as exc:
            logger.warning("Client error (%s): %s", client.support_id or remote, exc)
        finally:
            self.clients_by_ws.pop(websocket, None)
            await self.cleanup_client(client)
            logger.info("Disconnected: id=%s", client.support_id or remote)

    async def revocation_watchdog(self) -> None:
        while True:
            await asyncio.sleep(10)
            for client in list(self.clients_by_ws.values()):
                if client.registered and client.support_id:
                    if not is_device_active(client.support_id, db_path=self.db_path):
                        await self.send_json(
                            client.ws,
                            {
                                "type": "register_error",
                                "message": "This Support ID was suspended or removed.",
                            },
                        )
                        try:
                            await client.ws.close(code=4003, reason="Device suspended")
                        except Exception:
                            pass


async def _health_check_process_request(arg1, arg2):
    """Respond 200 OK to HTTP health checks (e.g. Render.com / cloud load balancers)."""
    if hasattr(arg1, "respond") and hasattr(arg2, "headers"):
        if arg2.headers.get("Upgrade", "").lower() != "websocket":
            return arg1.respond(HTTPStatus.OK, "Ashish PC Solutions Relay OK\n")
        return None
    if isinstance(arg1, str):
        if arg2.get("Upgrade", "").lower() != "websocket":
            return (
                HTTPStatus.OK,
                [("Content-Type", "text/plain")],
                b"Ashish PC Solutions Relay OK\n",
            )
    return None


async def run_server(host: str, port: int, db_path: str) -> None:
    relay = RelayServer(db_path=db_path)
    ssl_ctx = None
    if USE_SSL:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(SSL_CERT, SSL_KEY)

    proto = "wss" if ssl_ctx else "ws"
    logger.info(
        "Ashish PC Solutions Relay Server listening on %s://%s:%d (DB: %s)",
        proto,
        host,
        port,
        db_path,
    )

    watchdog_task = asyncio.create_task(relay.revocation_watchdog())
    try:
        async with websockets.serve(
            relay.ws_handler,
            host,
            port,
            ssl=ssl_ctx,
            process_request=_health_check_process_request,
            max_size=MAX_WS_MESSAGE_SIZE,
            ping_interval=20,
            ping_timeout=20,
        ):
            await asyncio.Future()
    finally:
        watchdog_task.cancel()


# ==============================================================================
# ADMIN DEVICE CLI
# ==============================================================================
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ashish PC Solutions - Direct Relay Server"
    )
    parser.add_argument("--db", default=DB_PATH, help="Path to SQLite database file")
    sub = parser.add_subparsers(dest="command")

    p_serve = sub.add_parser("serve", help="Start the WebSocket relay server")
    p_serve.add_argument("--host", default=DEFAULT_HOST, help="Bind host")
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port")

    p_suspend = sub.add_parser("suspend-device", help="Suspend a Support ID")
    p_suspend.add_argument("--support-id", required=True)

    p_activate = sub.add_parser("activate-device", help="Reactivate a Support ID")
    p_activate.add_argument("--support-id", required=True)

    p_delete = sub.add_parser("delete-device", help="Delete a registered Support ID")
    p_delete.add_argument("--support-id", required=True)

    p_pin = sub.add_parser("set-pin", help="Update a device's persistent Access PIN")
    p_pin.add_argument("--support-id", required=True)
    p_pin.add_argument("--pin", required=True)

    sub.add_parser("list-devices", help="List all registered devices")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    db_path = args.db

    if args.command is None or args.command == "serve":
        host = getattr(args, "host", DEFAULT_HOST)
        port = getattr(args, "port", DEFAULT_PORT)
        try:
            asyncio.run(run_server(host, port, db_path))
        except KeyboardInterrupt:
            logger.info("Relay server stopped by user.")
        return

    if args.command == "suspend-device":
        if set_device_active(args.support_id, False, db_path=db_path):
            print(f"[OK] Support ID '{args.support_id}' suspended.")
        else:
            print(f"[ERROR] Support ID '{args.support_id}' not found.", file=sys.stderr)
            sys.exit(1)

    elif args.command == "activate-device":
        if set_device_active(args.support_id, True, db_path=db_path):
            print(f"[OK] Support ID '{args.support_id}' reactivated.")
        else:
            print(f"[ERROR] Support ID '{args.support_id}' not found.", file=sys.stderr)
            sys.exit(1)

    elif args.command == "delete-device":
        if delete_device(args.support_id, db_path=db_path):
            print(f"[OK] Support ID '{args.support_id}' deleted.")
        else:
            print(f"[ERROR] Support ID '{args.support_id}' not found.", file=sys.stderr)
            sys.exit(1)

    elif args.command == "set-pin":
        try:
            if update_device_pin(args.support_id, args.pin, db_path=db_path):
                print(f"[OK] Access PIN updated for '{args.support_id}'.")
            else:
                print(f"[ERROR] Support ID '{args.support_id}' not found or inactive.", file=sys.stderr)
                sys.exit(1)
        except ValueError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "list-devices":
        devices = list_devices(db_path=db_path)
        if not devices:
            print("No devices registered yet.")
            return
        print(
            f"{'SUPPORT ID':<14} {'PIN':<10} {'DEVICE NAME':<24} {'STATUS':<10} {'LAST SEEN'}"
        )
        print("-" * 82)
        for d in devices:
            status = "ACTIVE" if d["is_active"] else "SUSPENDED"
            last_seen = (d["last_seen"] or "-")[:19].replace("T", " ")
            print(
                f"{d['support_id']:<14} {d['access_pin']:<10} {d['device_name'][:23]:<24} "
                f"{status:<10} {last_seen}"
            )


if __name__ == "__main__":
    main()
