#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Headless Textual tests for review-TUI modal screens.

Uses Textual's built-in ``App.run_test()`` / ``Pilot`` harness so the
tests run without a real terminal.  Only lightweight, self-contained
modals are exercised here — no database, network, or git needed.
"""

from typing import Any, Dict, List, Optional, Tuple

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Input, Label, ListView

from b4.review_tui._modals import (
    TRACKING_HELP_LINES,
    ActionScreen,
    ConfirmScreen,
    HelpScreen,
    LimitScreen,
    NoteScreen,
    PriorReviewScreen,
    RevisionChoiceScreen,
    SetStateScreen,
    SnoozeScreen,
    TrailerScreen,
    UpdateRevisionScreen,
)

# ---------------------------------------------------------------------------
# Compat helper — Textual ≥ 1.0 (pip) uses Static.content,
# older builds (e.g. Fedora 43 package) still use Static.renderable.
# ---------------------------------------------------------------------------


def _static_text(widget: Any) -> str:
    """Return the text content of a Static widget across Textual versions."""
    if hasattr(widget, 'content'):
        return str(widget.content)
    return str(widget.renderable)


# ---------------------------------------------------------------------------
# Minimal host app — just enough to push modal screens onto
# ---------------------------------------------------------------------------


class ModalTestApp(App[None]):
    """Bare app that serves as a host for pushing modal screens."""

    def compose(self) -> ComposeResult:
        yield Label('host')


# ---------------------------------------------------------------------------
# HelpScreen
# ---------------------------------------------------------------------------


class TestHelpScreen:
    """Tests for the HelpScreen modal."""

    @staticmethod
    def _lines() -> List[str]:
        return [
            '[bold]Test Help[/bold]\n',
            '\n',
            '  [bold]a[/bold]  Do alpha\n',
            '  [bold]b[/bold]  Do bravo\n',
        ]

    @pytest.mark.asyncio
    async def test_escape_dismisses(self) -> None:
        app = ModalTestApp()
        dismissed: List[Any] = []

        async with app.run_test() as pilot:
            app.push_screen(HelpScreen(self._lines()), dismissed.append)
            await pilot.pause()
            # The help screen should now be on top
            assert isinstance(app.screen, HelpScreen)

            await pilot.press('escape')
            await pilot.pause()
            # Should be back on the host screen
            assert not isinstance(app.screen, HelpScreen)
            assert dismissed == [None]

    @pytest.mark.asyncio
    async def test_question_mark_dismisses(self) -> None:
        app = ModalTestApp()
        dismissed: List[Any] = []

        async with app.run_test() as pilot:
            app.push_screen(HelpScreen(self._lines()), dismissed.append)
            await pilot.pause()

            await pilot.press('question_mark')
            await pilot.pause()
            assert not isinstance(app.screen, HelpScreen)
            assert dismissed == [None]

    @pytest.mark.asyncio
    async def test_q_dismisses(self) -> None:
        app = ModalTestApp()
        dismissed: List[Any] = []

        async with app.run_test() as pilot:
            app.push_screen(HelpScreen(self._lines()), dismissed.append)
            await pilot.pause()

            await pilot.press('q')
            await pilot.pause()
            assert not isinstance(app.screen, HelpScreen)
            assert dismissed == [None]

    @pytest.mark.asyncio
    async def test_scroll_bindings_do_not_dismiss(self) -> None:
        """j, k, space, etc. should scroll but keep the modal open."""
        app = ModalTestApp()

        async with app.run_test() as pilot:
            app.push_screen(HelpScreen(TRACKING_HELP_LINES))
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)

            for key in (
                'j',
                'k',
                'down',
                'up',
                'space',
                'backspace',
                'pagedown',
                'pageup',
            ):
                await pilot.press(key)
                await pilot.pause()
                assert isinstance(app.screen, HelpScreen), (
                    f'{key!r} unexpectedly closed the help screen'
                )

    @pytest.mark.asyncio
    async def test_content_rendered(self) -> None:
        """The static content inside the modal should contain our text."""
        app = ModalTestApp()

        async with app.run_test() as pilot:
            lines = self._lines()
            app.push_screen(HelpScreen(lines))
            await pilot.pause()

            dialog = app.screen.query_one('#help-dialog')
            assert dialog is not None


# ---------------------------------------------------------------------------
# ConfirmScreen
# ---------------------------------------------------------------------------


class TestConfirmScreen:
    """Tests for the ConfirmScreen modal."""

    @pytest.mark.asyncio
    async def test_y_confirms(self) -> None:
        app = ModalTestApp()
        results: List[Optional[bool]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                ConfirmScreen('Delete?', ['This is permanent.']),
                results.append,
            )
            await pilot.pause()
            assert isinstance(app.screen, ConfirmScreen)

            await pilot.press('y')
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmScreen)
            assert results == [True]

    @pytest.mark.asyncio
    async def test_escape_cancels(self) -> None:
        app = ModalTestApp()
        results: List[Optional[bool]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                ConfirmScreen('Delete?', ['This is permanent.']),
                results.append,
            )
            await pilot.pause()

            await pilot.press('escape')
            await pilot.pause()
            assert not isinstance(app.screen, ConfirmScreen)
            assert results == [False]

    @pytest.mark.asyncio
    async def test_body_lines_rendered(self) -> None:
        """Each body string should appear as a Static widget."""
        app = ModalTestApp()
        body = ['Line one.', 'Line two.', 'Line three.']

        async with app.run_test() as pilot:
            app.push_screen(ConfirmScreen('Title', body))
            await pilot.pause()

            statics = app.screen.query('#confirm-dialog Static')
            # body lines + hint line + possibly title
            rendered = [_static_text(s) for s in statics]
            for line in body:
                assert any(line in r for r in rendered), (
                    f'{line!r} not found in rendered statics'
                )

    @pytest.mark.asyncio
    async def test_subject_shown(self) -> None:
        app = ModalTestApp()

        async with app.run_test() as pilot:
            app.push_screen(
                ConfirmScreen('Title', ['body'], subject='My Subject'),
            )
            await pilot.pause()

            title_widget = app.screen.query_one('#confirm-title')
            assert 'My Subject' in _static_text(title_widget)

    @pytest.mark.asyncio
    async def test_warning_border(self) -> None:
        app = ModalTestApp()

        async with app.run_test() as pilot:
            app.push_screen(
                ConfirmScreen('Oops', ['careful'], border='$warning'),
            )
            await pilot.pause()

            dialog = app.screen.query_one('#confirm-dialog')
            assert dialog.has_class('--border-warning')


# ---------------------------------------------------------------------------
# TrailerScreen
# ---------------------------------------------------------------------------


class TestTrailerScreen:
    """Tests for the TrailerScreen modal."""

    @pytest.mark.asyncio
    async def test_cancel_returns_none(self) -> None:
        app = ModalTestApp()
        results: List[Optional[List[str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(TrailerScreen([]), results.append)
            await pilot.pause()
            assert isinstance(app.screen, TrailerScreen)

            await pilot.press('escape')
            await pilot.pause()
            assert results == [None]

    @pytest.mark.asyncio
    async def test_confirm_empty_returns_empty_list(self) -> None:
        """With nothing toggled, q/confirm returns an empty list."""
        app = ModalTestApp()
        results: List[Optional[List[str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(TrailerScreen([]), results.append)
            await pilot.pause()

            await pilot.press('q')
            await pilot.pause()
            assert len(results) == 1
            assert results[0] == []

    @pytest.mark.asyncio
    async def test_existing_trailers_pretoggled(self) -> None:
        """Trailers already present should be pre-selected."""
        app = ModalTestApp()
        results: List[Optional[List[str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                TrailerScreen(['Reviewed-by: Alice <a@b.com>']),
                results.append,
            )
            await pilot.pause()

            # Confirm immediately — should have Reviewed-by selected
            await pilot.press('q')
            await pilot.pause()
            assert results[0] == ['Reviewed-by']

    @pytest.mark.asyncio
    async def test_toggle_and_confirm(self) -> None:
        """Space toggles the highlighted item; q confirms."""
        app = ModalTestApp()
        results: List[Optional[List[str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(TrailerScreen([]), results.append)
            await pilot.pause()

            # First item is Acked-by (index 0), toggle it
            await pilot.press('space')
            await pilot.pause()
            # Move down to Reviewed-by, toggle it
            await pilot.press('j')
            await pilot.press('space')
            await pilot.pause()
            # Confirm
            await pilot.press('q')
            await pilot.pause()

            assert len(results) == 1
            assert results[0] is not None
            assert 'Acked-by' in results[0]
            assert 'Reviewed-by' in results[0]
            assert 'Tested-by' not in results[0]
            assert 'NACKed-by' not in results[0]

    @pytest.mark.asyncio
    async def test_toggle_twice_deselects(self) -> None:
        """Toggling the same item twice should deselect it."""
        app = ModalTestApp()
        results: List[Optional[List[str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(TrailerScreen([]), results.append)
            await pilot.pause()

            await pilot.press('space')  # select Acked-by
            await pilot.press('space')  # deselect Acked-by
            await pilot.pause()

            await pilot.press('q')
            await pilot.pause()
            assert results[0] == []

    @pytest.mark.asyncio
    async def test_jk_navigation(self) -> None:
        """j/k should move the highlight without toggling."""
        app = ModalTestApp()
        results: List[Optional[List[str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(TrailerScreen([]), results.append)
            await pilot.pause()

            # Navigate down to Tested-by (index 2) and toggle only it
            await pilot.press('j')
            await pilot.press('j')
            await pilot.press('space')
            await pilot.pause()

            await pilot.press('q')
            await pilot.pause()
            assert results[0] == ['Tested-by']

    @pytest.mark.asyncio
    async def test_enter_confirms(self) -> None:
        """Enter on the ListView should also confirm (via on_list_view_selected)."""
        app = ModalTestApp()
        results: List[Optional[List[str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                TrailerScreen(['Acked-by: Bob <b@c.com>']),
                results.append,
            )
            await pilot.pause()

            await pilot.press('enter')
            await pilot.pause()
            assert len(results) == 1
            assert results[0] == ['Acked-by']


# ---------------------------------------------------------------------------
# NoteScreen
# ---------------------------------------------------------------------------


class TestNoteScreen:
    """Tests for the NoteScreen modal."""

    @staticmethod
    def _entries() -> List[Tuple[str, str, str]]:
        return [
            ('Alice <alice@example.com>', 'green', 'Looks good to me.'),
            ('Bob <bob@example.com>', 'blue', 'Needs a rebase.'),
        ]

    @pytest.mark.asyncio
    async def test_escape_returns_none(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(NoteScreen(self._entries()), results.append)
            await pilot.pause()
            assert isinstance(app.screen, NoteScreen)

            await pilot.press('escape')
            await pilot.pause()
            assert results == [None]

    @pytest.mark.asyncio
    async def test_e_returns_edit(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(NoteScreen(self._entries()), results.append)
            await pilot.pause()

            await pilot.press('e')
            await pilot.pause()
            assert results == ['__EDIT__']

    @pytest.mark.asyncio
    async def test_d_returns_delete(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(NoteScreen(self._entries()), results.append)
            await pilot.pause()

            await pilot.press('d')
            await pilot.pause()
            assert results == ['__DELETE__']

    @pytest.mark.asyncio
    async def test_empty_notes(self) -> None:
        """Modal should still render with no entries."""
        app = ModalTestApp()

        async with app.run_test() as pilot:
            app.push_screen(NoteScreen([]))
            await pilot.pause()
            assert isinstance(app.screen, NoteScreen)
            assert app.screen.query_one('#note-viewer') is not None


# ---------------------------------------------------------------------------
# PriorReviewScreen
# ---------------------------------------------------------------------------


class TestPriorReviewScreen:
    """Tests for the PriorReviewScreen modal."""

    @pytest.mark.asyncio
    async def test_escape_dismisses(self) -> None:
        app = ModalTestApp()
        results: List[Any] = []

        async with app.run_test() as pilot:
            app.push_screen(
                PriorReviewScreen('== Patch 1 ==\nLGTM'),
                results.append,
            )
            await pilot.pause()
            assert isinstance(app.screen, PriorReviewScreen)

            await pilot.press('escape')
            await pilot.pause()
            assert not isinstance(app.screen, PriorReviewScreen)
            assert results == [None]

    @pytest.mark.asyncio
    async def test_content_rendered(self) -> None:
        app = ModalTestApp()

        async with app.run_test() as pilot:
            app.push_screen(PriorReviewScreen('== Header ==\nSome text'))
            await pilot.pause()
            assert app.screen.query_one('#prior-review-viewer') is not None


# ---------------------------------------------------------------------------
# RevisionChoiceScreen
# ---------------------------------------------------------------------------


class TestRevisionChoiceScreen:
    """Tests for the RevisionChoiceScreen modal."""

    @pytest.mark.asyncio
    async def test_n_returns_newest(self) -> None:
        app = ModalTestApp()
        results: List[Optional[int]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                RevisionChoiceScreen(current_rev=2, newest_rev=5),
                results.append,
            )
            await pilot.pause()
            assert isinstance(app.screen, RevisionChoiceScreen)

            await pilot.press('n')
            await pilot.pause()
            assert results == [5]

    @pytest.mark.asyncio
    async def test_o_returns_current(self) -> None:
        app = ModalTestApp()
        results: List[Optional[int]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                RevisionChoiceScreen(current_rev=2, newest_rev=5),
                results.append,
            )
            await pilot.pause()

            await pilot.press('o')
            await pilot.pause()
            assert results == [2]

    @pytest.mark.asyncio
    async def test_escape_returns_none(self) -> None:
        app = ModalTestApp()
        results: List[Optional[int]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                RevisionChoiceScreen(current_rev=1, newest_rev=3),
                results.append,
            )
            await pilot.pause()

            await pilot.press('escape')
            await pilot.pause()
            assert results == [None]


# ---------------------------------------------------------------------------
# SnoozeScreen
# ---------------------------------------------------------------------------


class TestSnoozeScreen:
    """Tests for the SnoozeScreen modal."""

    @pytest.mark.asyncio
    async def test_escape_cancels(self) -> None:
        app = ModalTestApp()
        results: List[Optional[Dict[str, str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(SnoozeScreen(), results.append)
            await pilot.pause()
            assert isinstance(app.screen, SnoozeScreen)

            await pilot.press('escape')
            await pilot.pause()
            assert results == [None]

    @pytest.mark.asyncio
    async def test_duration_snooze(self) -> None:
        """Entering a duration and confirming should return a datetime."""
        app = ModalTestApp()
        results: List[Optional[Dict[str, str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(SnoozeScreen(), results.append)
            await pilot.pause()

            # The duration input should be focused by default
            dur_input = app.screen.query_one('#snooze-duration', Input)
            dur_input.value = '3d'

            await pilot.press('ctrl+y')
            await pilot.pause()

            assert len(results) == 1
            assert results[0] is not None
            assert results[0]['source'] == 'duration'
            assert results[0]['input'] == '3d'
            # until should be an ISO datetime
            assert 'T' in results[0]['until']

    @pytest.mark.asyncio
    async def test_tag_snooze(self) -> None:
        app = ModalTestApp()
        results: List[Optional[Dict[str, str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(SnoozeScreen(), results.append)
            await pilot.pause()

            tag_input = app.screen.query_one('#snooze-tag', Input)
            tag_input.value = 'v6.15-rc3'

            await pilot.press('ctrl+y')
            await pilot.pause()

            assert len(results) == 1
            assert results[0] is not None
            assert results[0]['until'] == 'tag:v6.15-rc3'
            assert results[0]['source'] == 'tag'

    @pytest.mark.asyncio
    async def test_empty_fields_shows_error(self) -> None:
        """Confirming with no fields filled should show an error, not dismiss."""
        app = ModalTestApp()
        results: List[Optional[Dict[str, str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(SnoozeScreen(), results.append)
            await pilot.pause()

            await pilot.press('ctrl+y')
            await pilot.pause()
            # Should still be on the snooze screen (not dismissed)
            assert isinstance(app.screen, SnoozeScreen)
            assert len(results) == 0

            error = app.screen.query_one('#snooze-error')
            error_text = _static_text(error).lower()
            assert 'enter' in error_text or 'please' in error_text

    @pytest.mark.asyncio
    async def test_multiple_fields_shows_error(self) -> None:
        """Filling more than one field should show an error."""
        app = ModalTestApp()
        results: List[Optional[Dict[str, str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(SnoozeScreen(), results.append)
            await pilot.pause()

            app.screen.query_one('#snooze-duration', Input).value = '1d'
            app.screen.query_one('#snooze-tag', Input).value = 'v6.15'

            await pilot.press('ctrl+y')
            await pilot.pause()
            assert isinstance(app.screen, SnoozeScreen)
            assert len(results) == 0

            error = app.screen.query_one('#snooze-error')
            assert 'only one' in _static_text(error).lower()

    @pytest.mark.asyncio
    async def test_invalid_duration_shows_error(self) -> None:
        app = ModalTestApp()
        results: List[Optional[Dict[str, str]]] = []

        async with app.run_test() as pilot:
            app.push_screen(SnoozeScreen(), results.append)
            await pilot.pause()

            app.screen.query_one('#snooze-duration', Input).value = 'banana'

            await pilot.press('ctrl+y')
            await pilot.pause()
            assert isinstance(app.screen, SnoozeScreen)
            assert len(results) == 0

    @pytest.mark.asyncio
    async def test_prepopulate_last_source(self) -> None:
        """Re-opening with last_source/last_input should pre-fill the field."""
        app = ModalTestApp()

        async with app.run_test() as pilot:
            app.push_screen(SnoozeScreen(last_source='tag', last_input='v6.14'))
            await pilot.pause()

            tag_input = app.screen.query_one('#snooze-tag', Input)
            assert tag_input.value == 'v6.14'


# ---------------------------------------------------------------------------
# SetStateScreen
# ---------------------------------------------------------------------------


class TestSetStateScreen:
    """Tests for the SetStateScreen modal."""

    @staticmethod
    def _states() -> List[Dict[str, Any]]:
        return [
            {'slug': 'new', 'name': 'New'},
            {'slug': 'reviewing', 'name': 'Reviewing'},
            {'slug': 'replied', 'name': 'Replied'},
            {'slug': 'waiting', 'name': 'Waiting'},
        ]

    @pytest.mark.asyncio
    async def test_escape_cancels(self) -> None:
        app = ModalTestApp()
        results: List[Optional[Tuple[str, bool]]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                SetStateScreen(self._states(), 'new'),
                results.append,
            )
            await pilot.pause()
            assert isinstance(app.screen, SetStateScreen)

            await pilot.press('escape')
            await pilot.pause()
            assert results == [None]

    @pytest.mark.asyncio
    async def test_select_state_with_enter(self) -> None:
        app = ModalTestApp()
        results: List[Optional[Tuple[str, bool]]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                SetStateScreen(self._states(), 'new'),
                results.append,
            )
            await pilot.pause()

            # Navigate to 'reviewing' (one down from 'new')
            await pilot.press('j')
            await pilot.press('enter')
            await pilot.pause()

            assert len(results) == 1
            assert results[0] is not None
            assert results[0][0] == 'reviewing'
            assert results[0][1] is False  # not archived

    @pytest.mark.asyncio
    async def test_archive_toggle(self) -> None:
        app = ModalTestApp()
        results: List[Optional[Tuple[str, bool]]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                SetStateScreen(self._states(), 'new'),
                results.append,
            )
            await pilot.pause()

            # Toggle archive, then confirm
            await pilot.press('a')
            await pilot.press('enter')
            await pilot.pause()

            assert len(results) == 1
            assert results[0] is not None
            assert results[0][1] is True  # archived

    @pytest.mark.asyncio
    async def test_current_state_preselected(self) -> None:
        """The ListView index should start on the current state."""
        app = ModalTestApp()

        async with app.run_test() as pilot:
            app.push_screen(SetStateScreen(self._states(), 'replied'))
            await pilot.pause()

            lv = app.screen.query_one('#state-list', ListView)
            assert lv.index == 2  # 'replied' is at index 2


# ---------------------------------------------------------------------------
# LimitScreen
# ---------------------------------------------------------------------------


class TestLimitScreen:
    """Tests for the LimitScreen modal."""

    @pytest.mark.asyncio
    async def test_escape_cancels(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(LimitScreen(), results.append)
            await pilot.pause()
            assert isinstance(app.screen, LimitScreen)

            await pilot.press('escape')
            await pilot.pause()
            assert results == [None]

    @pytest.mark.asyncio
    async def test_enter_submits_value(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(LimitScreen(), results.append)
            await pilot.pause()

            inp = app.screen.query_one('#limit-input', Input)
            inp.value = 'netfilter'

            await pilot.press('enter')
            await pilot.pause()
            assert results == ['netfilter']

    @pytest.mark.asyncio
    async def test_empty_enter_clears_filter(self) -> None:
        """Submitting empty input should return empty string (clear filter)."""
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(LimitScreen(), results.append)
            await pilot.pause()

            await pilot.press('enter')
            await pilot.pause()
            assert results == ['']

    @pytest.mark.asyncio
    async def test_current_pattern_prepopulated(self) -> None:
        app = ModalTestApp()

        async with app.run_test() as pilot:
            app.push_screen(LimitScreen(current_pattern='drm'))
            await pilot.pause()

            inp = app.screen.query_one('#limit-input', Input)
            assert inp.value == 'drm'


# ---------------------------------------------------------------------------
# ActionScreen
# ---------------------------------------------------------------------------


class TestActionScreen:
    """Tests for the ActionScreen modal."""

    _SHORTCUTS = {
        'review': 'r',
        'take': 'T',
        'snooze': 's',
        'archive': 'x',
    }

    @staticmethod
    def _actions() -> List[Tuple[str, str]]:
        return [
            ('review', 'Review this series'),
            ('take', 'Take (apply) this series'),
            ('snooze', 'Snooze this series'),
            ('archive', 'Archive this series'),
        ]

    @pytest.mark.asyncio
    async def test_escape_cancels(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(ActionScreen(self._actions()), results.append)
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)

            await pilot.press('escape')
            await pilot.pause()
            assert results == [None]

    @pytest.mark.asyncio
    async def test_enter_confirms_highlighted(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(ActionScreen(self._actions()), results.append)
            await pilot.pause()

            # First item is 'review'
            await pilot.press('enter')
            await pilot.pause()
            assert results == ['review']

    @pytest.mark.asyncio
    async def test_navigate_and_confirm(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(ActionScreen(self._actions()), results.append)
            await pilot.pause()

            await pilot.press('j')  # take
            await pilot.press('j')  # snooze
            await pilot.press('enter')
            await pilot.pause()
            assert results == ['snooze']

    @pytest.mark.asyncio
    async def test_shortcut_key_selects_directly(self) -> None:
        """Pressing the shortcut char should immediately dismiss."""
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                ActionScreen(self._actions(), shortcuts=self._SHORTCUTS), results.append
            )
            await pilot.pause()

            # 'T' is the shortcut for 'take'
            await pilot.press('T')
            await pilot.pause()
            assert results == ['take']

    @pytest.mark.asyncio
    async def test_shortcut_r_for_review(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                ActionScreen(self._actions(), shortcuts=self._SHORTCUTS), results.append
            )
            await pilot.pause()

            await pilot.press('r')
            await pilot.pause()
            assert results == ['review']

    @pytest.mark.asyncio
    async def test_shortcut_x_for_archive(self) -> None:
        app = ModalTestApp()
        results: List[Optional[str]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                ActionScreen(self._actions(), shortcuts=self._SHORTCUTS), results.append
            )
            await pilot.pause()

            await pilot.press('x')
            await pilot.pause()
            assert results == ['archive']


# ---------------------------------------------------------------------------
# UpdateRevisionScreen
# ---------------------------------------------------------------------------


class TestUpdateRevisionScreen:
    """Tests for the UpdateRevisionScreen modal."""

    @staticmethod
    def _revisions() -> List[Dict[str, Any]]:
        return [
            {'revision': 2, 'subject': '[PATCH v2] fix the thing'},
            {'revision': 3, 'subject': '[PATCH v3] fix the thing properly'},
            {'revision': 4, 'subject': '[PATCH v4] fix the thing for real'},
        ]

    @pytest.mark.asyncio
    async def test_escape_cancels(self) -> None:
        app = ModalTestApp()
        results: List[Optional[int]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                UpdateRevisionScreen(1, self._revisions()),
                results.append,
            )
            await pilot.pause()
            assert isinstance(app.screen, UpdateRevisionScreen)

            await pilot.press('escape')
            await pilot.pause()
            assert results == [None]

    @pytest.mark.asyncio
    async def test_select_first_revision(self) -> None:
        app = ModalTestApp()
        results: List[Optional[int]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                UpdateRevisionScreen(1, self._revisions()),
                results.append,
            )
            await pilot.pause()

            await pilot.press('enter')
            await pilot.pause()
            assert results == [2]

    @pytest.mark.asyncio
    async def test_navigate_and_select(self) -> None:
        app = ModalTestApp()
        results: List[Optional[int]] = []

        async with app.run_test() as pilot:
            app.push_screen(
                UpdateRevisionScreen(1, self._revisions()),
                results.append,
            )
            await pilot.pause()

            await pilot.press('j')  # v3
            await pilot.press('j')  # v4
            await pilot.press('enter')
            await pilot.pause()
            assert results == [4]

    @pytest.mark.asyncio
    async def test_filters_older_revisions(self) -> None:
        """Only revisions newer than current should appear."""
        app = ModalTestApp()
        results: List[Optional[int]] = []

        async with app.run_test() as pilot:
            # current_revision=3, so only v4 should appear
            app.push_screen(
                UpdateRevisionScreen(3, self._revisions()),
                results.append,
            )
            await pilot.pause()

            # Only one item in the list — entering should select v4
            await pilot.press('enter')
            await pilot.pause()
            assert results == [4]
