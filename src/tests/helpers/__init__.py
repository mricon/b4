# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Shared test fixtures-as-functions.

Import from test modules with a relative import::

    from .helpers.tracking import create_review_branch, seed_db

The package is split so that modules which never touch the TUI do not
pull in textual: ``tracking`` and ``mail`` are pure, ``tui`` is for the
Textual-based suites.
"""
