"""Entrypoint: `python -m watermark_mvp.backend.run` or `wm-backend`."""

from __future__ import annotations

import argparse
import os

import uvicorn

from .app import ADMIN_TOKEN_ENV, create_app


def main() -> None:
    ap = argparse.ArgumentParser(description="Watermark MVP backend")
    # Railway (and most PaaS) sets $PORT and expects the app to bind 0.0.0.0.
    # Local default stays loopback so a dev run doesn't expose to LAN by accident.
    default_host = os.environ.get("HOST", "127.0.0.1")
    default_port = int(os.environ.get("PORT", "8765"))
    ap.add_argument("--host", default=default_host,
                    help="bind address (default: $HOST or 127.0.0.1)")
    ap.add_argument("--port", type=int, default=default_port,
                    help="listen port (default: $PORT or 8765)")
    ap.add_argument("--db-url", help="SQLAlchemy DB URL (default: env WATERMARK_DB_URL)")
    args = ap.parse_args()

    if args.db_url:
        os.environ["WATERMARK_DB_URL"] = args.db_url
    # Railway provides DATABASE_URL when a Postgres plugin is attached; honor
    # it transparently. (Railway's URL starts with "postgres://" — SQLAlchemy
    # 2.x needs "postgresql://", so normalize.)
    if "WATERMARK_DB_URL" not in os.environ:
        db_url = os.environ.get("DATABASE_URL")
        if db_url:
            if db_url.startswith("postgres://"):
                db_url = "postgresql://" + db_url[len("postgres://"):]
            os.environ["WATERMARK_DB_URL"] = db_url

    if not os.environ.get(ADMIN_TOKEN_ENV):
        raise SystemExit(
            f"Set {ADMIN_TOKEN_ENV} before starting the backend, e.g.:\n"
            f"  export {ADMIN_TOKEN_ENV}=$(openssl rand -hex 16)"
        )

    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
