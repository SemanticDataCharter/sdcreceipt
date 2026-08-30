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

#: SDC ecosystem versioning: MAJOR tracks the reference model, so a 4.x.x
#: release targets SDC4. It starts at 4 rather than 0 for that reason, not
#: because there were three earlier versions. MINOR is features, PATCH is
#: fixes. An SDC5 reference model would make this 5.x.x.
__version__ = "4.0.1"

from sdcreceipt.verify import Result, verify  # noqa: F401

__all__ = ["verify", "Result", "__version__"]
