# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared TUI utilities and widgets for b4 Textual apps.

The submodules import the optional ``textual`` dependency at module load
time.  Exposing the public API through :pep:`562` ``__getattr__`` keeps
``import b4.tui`` working even when the ``[tui]`` extra is not installed
-- needed so downstream packaging tools that probe importability of every
shipped module don't fail when ``textual`` is absent.
"""

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from b4.tui._common import (
        JKListNavMixin,
        SeparatedFooter,
        _addrs_to_lines,
        _fix_ansi_theme,
        _lines_to_header,
        _quiet_worker,
        _suspend_to_shell,
        _to_rich_color,
        _validate_addrs,
        _wait_for_enter,
        ci_check_styles,
        ci_markup,
        ci_styles,
        display_width,
        pad_display,
        resolve_styles,
        reviewer_colours,
    )
    from b4.tui._modals import (
        ActionItem,
        ActionScreen,
        ConfirmScreen,
        LimitScreen,
        ToCcScreen,
    )

__all__ = [
    'ActionItem',
    'ActionScreen',
    'ConfirmScreen',
    'JKListNavMixin',
    'LimitScreen',
    'SeparatedFooter',
    'ToCcScreen',
    '_addrs_to_lines',
    '_fix_ansi_theme',
    '_lines_to_header',
    '_quiet_worker',
    '_suspend_to_shell',
    '_to_rich_color',
    '_validate_addrs',
    '_wait_for_enter',
    'ci_check_styles',
    'ci_markup',
    'ci_styles',
    'display_width',
    'pad_display',
    'resolve_styles',
    'reviewer_colours',
]

_LAZY_ATTRS: dict[str, str] = {
    'JKListNavMixin': '_common',
    'SeparatedFooter': '_common',
    '_addrs_to_lines': '_common',
    '_fix_ansi_theme': '_common',
    '_lines_to_header': '_common',
    '_quiet_worker': '_common',
    '_suspend_to_shell': '_common',
    '_to_rich_color': '_common',
    '_validate_addrs': '_common',
    '_wait_for_enter': '_common',
    'ci_check_styles': '_common',
    'ci_markup': '_common',
    'ci_styles': '_common',
    'display_width': '_common',
    'pad_display': '_common',
    'resolve_styles': '_common',
    'reviewer_colours': '_common',
    'ActionItem': '_modals',
    'ActionScreen': '_modals',
    'ConfirmScreen': '_modals',
    'LimitScreen': '_modals',
    'ToCcScreen': '_modals',
}


def __getattr__(name: str) -> Any:
    submodule = _LAZY_ATTRS.get(name)
    if submodule is None:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
    mod = importlib.import_module(f'b4.tui.{submodule}')
    return getattr(mod, name)
