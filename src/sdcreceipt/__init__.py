#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
sdcreceipt - verify and settle VSL Settlement Receipts.

Three verbs and no more: `verify`, `init`, `trigger`. It is a client, not a
product; the value is in it being small enough to read.

`verify` requires no network, no account, and nothing from the issuer.
"""

__version__ = "0.1.0"

from sdcreceipt.verify import Result, verify  # noqa: F401

__all__ = ["verify", "Result", "__version__"]
