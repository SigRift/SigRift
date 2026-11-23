"""Run The Bridge with configurable worker count."""

import os

import uvicorn


def main() -> None:
    workers = int(os.environ.get("BRIDGE_WORKERS", "1"))
    host = os.environ.get("BRIDGE_HOST", "0.0.0.0")
    port = int(os.environ.get("BRIDGE_PORT", "8000"))
    uvicorn.run(
        "sigrift.bridge.app:app",
        host=host,
        port=port,
        workers=workers,
        log_level="info",
    )


if __name__ == "__main__":
    main()
