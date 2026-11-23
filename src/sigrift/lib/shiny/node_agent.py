#!/usr/bin/env python3
"""Compatibility alias for :mod:`sigrift.edge.node_agent`.

This file used to be a separately maintained copy of the edge heartbeat
agent, and it drifted: it turned off TLS certificate and hostname
verification whenever MLRF_CA_CERT was unset or missing, but still ran
the remote commands carried in heartbeat responses (``update`` does a
``git pull`` and restarts services, ``iq_capture``). Anyone on the network
path could impersonate the bridge and run code on the node.

There is now one implementation. Importing this module gives you the
canonical ``sigrift.edge.node_agent`` module object itself, with the same
functions and module state. Running it (``python -m
sigrift.lib.shiny.node_agent``, or ``python3 .../node_agent.py`` from a
source checkout) runs that agent's ``main()``. The TLS policy therefore
cannot drift again: the bridge is verified by default against
MLRF_CA_CERT / MLRF_CA_BUNDLE or the system trust store, a CA file that
exists but cannot be loaded is a fatal startup error, and verification is
skipped only when MLRF_INSECURE_TLS=1 is set.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from sigrift.edge import node_agent as _node_agent
except ModuleNotFoundError as exc:
    if exc.name != "sigrift" or __name__ != "__main__":
        raise
    # Run as a plain script from a source checkout without the package on
    # sys.path: put this checkout's src/ directory first and retry.
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from sigrift.edge import node_agent as _node_agent

if __name__ == "__main__":
    _node_agent.main()
else:
    sys.modules[__name__] = _node_agent
