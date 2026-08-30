#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
RFC 8785 canonicalization.

★ Deliberately a thin re-export rather than an implementation.

A second implementation of a canonicalization scheme can disagree with the
first, and the disagreement is silent: the bytes differ, so the hash differs,
and the artifact reads as tampered with rather than misencoded. That converts
a structural guarantee into a testing problem defended forever.

`sdcgovernance` is Apache-2.0, on PyPI, and differential-tested against a real
ECMAScript engine, which matters because RFC 8785 defines number formatting in
terms of ECMAScript `Number::toString`. Reusing it means this tool and the
issuer cannot disagree about bytes.

This is a library dependency, not a service dependency. Nothing here calls
out to anything at runtime.
"""

from sdcgovernance.jcs import canonicalize, canonicalize_bytes  # noqa: F401

__all__ = ["canonicalize", "canonicalize_bytes"]
