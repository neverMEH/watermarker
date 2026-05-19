"""
MVP agent: requests a session token from the backend and renders the
watermark onto an input PNG/JPG.

This is NOT the production agent. The real agent is a service that
intercepts the OS compositor and renders the overlay in real time
(DirectComposition / Metal / Wayland — BUILD_SPEC.md §4.1). This
command-line agent exercises the same code path (token request, payload
encoding, symbol overlay) on still images, so the rest of the system can
be validated end-to-end on a Linux dev workstation.

Usage:
    wm-agent enroll --tenant TENANT --user USER --host HOSTNAME --os OS
    wm-agent render --in clean.png --out watermarked.png

Configuration lives in $XDG_CONFIG_HOME/watermark-mvp/agent.json (or
~/.config/watermark-mvp/agent.json), keyed by backend URL.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from typing import Optional

import httpx
import numpy as np
from PIL import Image

from ..core import symbols


CONFIG_DIR = pathlib.Path(
    os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
) / "watermark-mvp"
CONFIG_PATH = CONFIG_DIR / "agent.json"


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text())
    return {}


def _save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def _client(backend: str, timeout: float = 30.0) -> httpx.Client:
    return httpx.Client(base_url=backend, timeout=timeout)


def cmd_enroll(args: argparse.Namespace) -> int:
    """Admin-side device provisioning. Calls /v1/tenants (if needed) and
    /v1/devices/enroll, then writes the resulting (device_id, secret) to
    the agent config so subsequent `render` calls can authenticate.
    """
    if not args.admin_token:
        print("error: --admin-token required for enroll", file=sys.stderr)
        return 2

    cfg = _load_config()
    with _client(args.backend) as c:
        tenant_id = args.tenant_id
        user_id = args.user_id

        if not tenant_id or not user_id:
            print(f"creating tenant '{args.tenant_name}' …")
            r = c.post(
                "/v1/tenants",
                headers={"Authorization": f"Bearer {args.admin_token}"},
                json={"tenant_name": args.tenant_name, "user_email": args.user_email},
            )
            r.raise_for_status()
            data = r.json()
            tenant_id = data["tenant_id"]
            user_id = data["user_id"]
            print(f"  tenant_id={tenant_id}")
            print(f"  user_id={user_id}")

        print(f"enrolling device '{args.host}' …")
        r = c.post(
            "/v1/devices/enroll",
            headers={"Authorization": f"Bearer {args.admin_token}"},
            json={
                "tenant_id": tenant_id,
                "user_id": user_id,
                "hostname": args.host,
                "os": args.os,
            },
        )
        r.raise_for_status()
        data = r.json()

    cfg.setdefault("backend", args.backend)
    cfg["device_id"] = data["device_id"]
    cfg["enroll_secret"] = data["enroll_secret"]
    cfg["tenant_id"] = tenant_id
    cfg["user_id"] = user_id
    cfg["hostname"] = args.host
    _save_config(cfg)
    print(f"saved config -> {CONFIG_PATH}")
    print(f"  device_id={cfg['device_id']}")
    return 0


def _request_session(backend: str, device_id: str, secret: str) -> dict:
    with _client(backend) as c:
        r = c.post(
            "/v1/sessions",
            headers={
                "Authorization": f"Bearer {secret}",
                "X-Device-Id": device_id,
            },
        )
        r.raise_for_status()
        return r.json()


def cmd_render(args: argparse.Namespace) -> int:
    cfg = _load_config()
    backend = args.backend or cfg.get("backend")
    device_id = cfg.get("device_id")
    secret = cfg.get("enroll_secret")
    if not (backend and device_id and secret):
        print("error: agent not enrolled; run `wm-agent enroll` first",
              file=sys.stderr)
        return 2

    src = pathlib.Path(args.input)
    if not src.exists():
        print(f"error: input file {src} not found", file=sys.stderr)
        return 2
    img = Image.open(src).convert("RGB")
    arr = np.array(img)
    H, W = arr.shape[:2]

    if W < symbols.WATERMARK_W or H < symbols.WATERMARK_H:
        print(
            f"error: input image {W}x{H} is smaller than the watermark "
            f"region {symbols.WATERMARK_W}x{symbols.WATERMARK_H}; pick a "
            f"larger source image or resize first",
            file=sys.stderr,
        )
        return 2

    print(f"requesting session from {backend} …")
    sess = _request_session(backend, device_id, secret)
    print(f"  token       : {sess['token_hex']}")
    print(f"  issued_at   : {sess['issued_at']}")
    print(f"  expires_at  : {sess['expires_at']}")

    mask = symbols.build_overlay(sess["encoded_symbols"], W, H,
                                 delta=args.delta)
    wm = symbols.apply_overlay(arr, mask)
    out = pathlib.Path(args.output)
    Image.fromarray(wm).save(out)
    print(f"wrote {out}  ({W}x{H}, delta={args.delta})")

    if args.amplified:
        amp = np.clip(128 + mask * 30, 0, 255).astype(np.uint8)
        amp_path = out.with_name(out.stem + "_overlay_amp" + out.suffix)
        Image.fromarray(amp).save(amp_path)
        print(f"wrote {amp_path}  (overlay alone, 30× amplified)")

    return 0


def cmd_show_config(args: argparse.Namespace) -> int:
    cfg = _load_config()
    # Redact the secret in display.
    redacted = dict(cfg)
    if "enroll_secret" in redacted:
        redacted["enroll_secret"] = redacted["enroll_secret"][:6] + "…"
    print(json.dumps(redacted, indent=2))
    print(f"\n(config path: {CONFIG_PATH})")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="wm-agent", description=__doc__.splitlines()[1] if __doc__ else None)
    ap.add_argument("--backend", default=os.environ.get("WATERMARK_BACKEND", "http://127.0.0.1:8765"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_enroll = sub.add_parser("enroll", help="provision tenant/user/device")
    ap_enroll.add_argument("--admin-token", default=os.environ.get("WATERMARK_ADMIN_TOKEN"))
    ap_enroll.add_argument("--tenant-id", help="reuse existing tenant id")
    ap_enroll.add_argument("--user-id", help="reuse existing user id")
    ap_enroll.add_argument("--tenant-name", default="Demo Tenant")
    ap_enroll.add_argument("--user-email", default="user@demo.test")
    ap_enroll.add_argument("--host", default=os.uname().nodename)
    ap_enroll.add_argument("--os", default=os.uname().sysname)
    ap_enroll.set_defaults(func=cmd_enroll)

    ap_render = sub.add_parser("render", help="apply watermark to an image")
    ap_render.add_argument("--in", dest="input", required=True)
    ap_render.add_argument("--out", dest="output", required=True)
    ap_render.add_argument("--delta", type=int, default=3,
                           help="per-channel luminance offset (default 3)")
    ap_render.add_argument("--amplified", action="store_true",
                           help="also save a 30x-amplified overlay-only image")
    ap_render.set_defaults(func=cmd_render)

    ap_show = sub.add_parser("config", help="show saved agent config")
    ap_show.set_defaults(func=cmd_show_config)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
