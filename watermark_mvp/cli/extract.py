"""
MVP forensic CLI — uploads a photo to the backend's /v1/extract endpoint
and prints the attribution result.

This is the Phase-1 "CLI extraction tool" called out in BUILD_SPEC.md §10.

Usage:
    wm-extract --image suspect.png --case CASE-123 \\
               --investigator inv@acme.test \\
               --screen-w 1280 --screen-h 720
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from typing import Optional

import httpx


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="wm-extract", description="Forensic watermark extraction.")
    ap.add_argument("--backend", default=os.environ.get("WATERMARK_BACKEND", "http://127.0.0.1:8765"))
    ap.add_argument("--admin-token", default=os.environ.get("WATERMARK_ADMIN_TOKEN"),
                    help="bearer token authorizing investigator access")
    ap.add_argument("--image", required=True, help="path to suspect image")
    ap.add_argument("--case", required=True, help="case ID (free-form, audit-logged)")
    ap.add_argument("--investigator", required=True, help="investigator email")
    ap.add_argument("--screen-w", type=int, required=True,
                    help="width of the original screen the image was taken from")
    ap.add_argument("--screen-h", type=int, required=True,
                    help="height of the original screen the image was taken from")
    ap.add_argument("--json", action="store_true", help="output machine-readable JSON")
    args = ap.parse_args(argv)

    if not args.admin_token:
        print("error: --admin-token (or $WATERMARK_ADMIN_TOKEN) required",
              file=sys.stderr)
        return 2
    img_path = pathlib.Path(args.image)
    if not img_path.exists():
        print(f"error: image {img_path} not found", file=sys.stderr)
        return 2

    with httpx.Client(base_url=args.backend, timeout=60.0) as c:
        with img_path.open("rb") as f:
            r = c.post(
                "/v1/extract",
                headers={"Authorization": f"Bearer {args.admin_token}"},
                data={
                    "case_id": args.case,
                    "investigator_email": args.investigator,
                    "screen_w": str(args.screen_w),
                    "screen_h": str(args.screen_h),
                },
                files={"image": (img_path.name, f, "application/octet-stream")},
            )

    if r.status_code != 200:
        try:
            err = r.json()
        except Exception:
            err = r.text
        print(f"error: HTTP {r.status_code}: {err}", file=sys.stderr)
        return 1

    result = r.json()
    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    if result.get("success"):
        print("=" * 60)
        print(" WATERMARK ATTRIBUTION")
        print("=" * 60)
        print(f"  token        : {result['token_hex']}")
        print(f"  tenant       : {result['tenant_id']}")
        print(f"  user         : {result['user_email']}")
        print(f"  device       : {result['device_hostname']}")
        print(f"  time window  : {result['time_window_start']}")
        print(f"                 → {result['time_window_end']}")
        print(f"  decode path  : {result['strategy']}")
        print(f"  audit id     : {result['audit_id']}")
        return 0
    else:
        print("=" * 60)
        print(" NO WATERMARK DETECTED")
        print("=" * 60)
        print(f"  strategy     : {result['strategy']}")
        print(f"  reason       : {result['failure_reason']}")
        print(f"  audit id     : {result['audit_id']}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
