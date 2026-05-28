# SPDX-License-Identifier: GPL-2.0-or-later
"""TUI components for ``b4 review``.

The submodules import the optional ``textual`` dependency at module load
time.  Exposing the public API through :pep:`562` ``__getattr__`` keeps
``import b4.review_tui`` working even when the ``[tui]`` extra is not
installed -- needed so downstream packaging tools that probe importability
of every shipped module (e.g. Fedora's ``import_all_modules.py``) don't
fail when ``textual`` is absent.
"""

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from b4.review_tui._common import (
        PATCH_STATE_MARKERS,
        _addrs_to_lines,
        _lines_to_header,
        _validate_addrs,
        gather_attestation_info,
        logger,
        resolve_styles,
        reviewer_colours,
    )
    from b4.review_tui._entry import (
        run_branch_tui,
        run_pw_tui,
        run_tracking_tui,
    )
    from b4.review_tui._pw_app import PwApp
    from b4.review_tui._review_app import ReviewApp
    from b4.review_tui._tracking_app import TrackingApp

__all__ = [
    'PATCH_STATE_MARKERS',
    'PwApp',
    'ReviewApp',
    'TrackingApp',
    '_addrs_to_lines',
    '_lines_to_header',
    '_validate_addrs',
    'gather_attestation_info',
    'logger',
    'resolve_styles',
    'reviewer_colours',
    'run_branch_tui',
    'run_pw_tui',
    'run_tracking_tui',
]

_LAZY_ATTRS: dict[str, str] = {
    'PATCH_STATE_MARKERS': '_common',
    '_addrs_to_lines': '_common',
    '_lines_to_header': '_common',
    '_validate_addrs': '_common',
    'gather_attestation_info': '_common',
    'logger': '_common',
    'resolve_styles': '_common',
    'reviewer_colours': '_common',
    'run_branch_tui': '_entry',
    'run_pw_tui': '_entry',
    'run_tracking_tui': '_entry',
    'PwApp': '_pw_app',
    'ReviewApp': '_review_app',
    'TrackingApp': '_tracking_app',
}


def __getattr__(name: str) -> Any:
    submodule = _LAZY_ATTRS.get(name)
    if submodule is None:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
    mod = importlib.import_module(f'b4.review_tui.{submodule}')
    return getattr(mod, name)
