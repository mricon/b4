#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared Patchwork single-patch state flow for review TUI screens."""

from typing import Any, Dict, List, Optional, Sequence, Tuple

from textual.worker import Worker, WorkerState

import b4
import b4.review
from b4.review_tui._modals import ApplyStateModal, SetStateScreen


class PatchworkStateMixin:
    """Resolve Patchwork patches and apply state choices one at a time.

    The mixin deliberately uses workers for lookup: a cache miss needs a REST
    request and must not stall the Textual event loop.  Hosts call
    :meth:`begin_patchwork_state` after a manual patch action or after mail was
    successfully sent, and delegate worker events to
    :meth:`handle_patchwork_worker`.
    """

    _pw_state_queue: List[Dict[str, Any]]
    _pw_state_config: Optional[Tuple[str, str, str]]
    _pw_state_default: Optional[str]
    _pw_state_notify_empty: bool
    _pw_state_active: bool

    def begin_patchwork_state(
        self,
        msgids: Sequence[str],
        default_state: Optional[str] = None,
        notify_empty: bool = False,
    ) -> None:
        """Offer a state chooser for each unique Patchwork patch in *msgids*.

        ``default_state=None`` selects each patch's current remote state,
        which is used for the explicit ``s`` action.  Reply flows pass the
        configured review default instead.
        """
        if getattr(self, '_pw_state_active', False):
            self.app.notify(
                'Patchwork state update already in progress', severity='warning'
            )
            return
        config = b4.get_main_config()
        pwkey = str(config.get('pw-key', ''))
        pwurl = str(config.get('pw-url', ''))
        pwproj = str(config.get('pw-project', ''))
        if not (pwkey and pwurl and pwproj):
            if notify_empty:
                self.app.notify(
                    'Patchwork not configured '
                    '(need b4.pw-key, b4.pw-url, b4.pw-project)',
                    severity='warning',
                )
            return

        unique_msgids = list(dict.fromkeys(mid for mid in msgids if mid))
        if not unique_msgids:
            if notify_empty:
                self.app.notify('No Patchwork patch selected', severity='warning')
            return
        self._pw_state_config = (pwkey, pwurl, pwproj)
        self._pw_state_default = default_state
        self._pw_state_notify_empty = notify_empty
        self._pw_state_active = True
        self.run_worker(
            lambda: self._lookup_patchwork_targets(unique_msgids),
            name='_pw_state_lookup',
            thread=True,
            exit_on_error=False,
        )

    @staticmethod
    def _lookup_patchwork_targets(msgids: Sequence[str]) -> List[Dict[str, Any]]:
        targets: List[Dict[str, Any]] = []
        for msgid in msgids:
            try:
                data = b4.LoreMessage.get_patchwork_data_by_msgid(msgid)
            except LookupError:
                continue
            patch_id = data.get('id')
            if patch_id:
                targets.append(
                    {
                        'id': int(patch_id),
                        'msgid': msgid,
                        'name': data.get('name') or '(no subject)',
                        'state': data.get('state') or 'new',
                    }
                )
        return targets

    async def handle_patchwork_worker(self, event: Worker.StateChanged) -> bool:
        """Handle our lookup worker, returning whether *event* was consumed."""
        if event.worker.name != '_pw_state_lookup':
            return False
        if event.state == WorkerState.ERROR:
            self.app.notify('Could not look up Patchwork patch', severity='warning')
            self._finish_patchwork_state_flow()
            return True
        if event.state == WorkerState.CANCELLED:
            self._finish_patchwork_state_flow()
            return True
        if event.state != WorkerState.SUCCESS:
            return True
        self._pw_state_queue = event.worker.result or []
        if not self._pw_state_queue:
            if self._pw_state_notify_empty:
                self.app.notify(
                    'Selected message is not a Patchwork patch', severity='warning'
                )
            self._finish_patchwork_state_flow()
            return True
        self._show_next_patchwork_state()
        return True

    def _show_next_patchwork_state(self) -> None:
        if not self._pw_state_queue:
            self._finish_patchwork_state_flow()
            return
        if self._pw_state_config is None:
            self._finish_patchwork_state_flow()
            return
        target = self._pw_state_queue.pop(0)
        pwkey, pwurl, _pwproj = self._pw_state_config
        states = b4.review.pw_fetch_states(pwkey, pwurl, _pwproj)
        default = self._pw_state_default or str(target['state'])
        self.app.push_screen(
            SetStateScreen(states, default, allow_archived=False),
            callback=lambda result: self._on_patchwork_state_selected(result, target),
        )

    def _on_patchwork_state_selected(
        self, result: Optional[Tuple[str, bool]], target: Dict[str, Any]
    ) -> None:
        if result is None:
            self._show_next_patchwork_state()
            return
        new_state, _archived = result
        assert self._pw_state_config is not None
        pwkey, pwurl, _pwproj = self._pw_state_config
        self.app.push_screen(
            ApplyStateModal(
                pwkey, pwurl, [target['id']], new_state, False, target['name']
            ),
            callback=lambda applied: self._on_patchwork_state_applied(applied, target),
        )

    def _on_patchwork_state_applied(
        self, result: Optional[Tuple[int, int, str]], target: Dict[str, Any]
    ) -> None:
        if result is not None:
            ok, fail, new_state = result
            if ok and self._pw_state_config is not None:
                _pwkey, pwurl, pwproj = self._pw_state_config
                b4.clear_cache(pwurl + pwproj + str(target['msgid']), suffix='lookup')
                self.app.notify(
                    f'Patchwork patch set to {new_state}', severity='information'
                )
            elif fail:
                self.app.notify('Could not update Patchwork patch', severity='warning')
        self._show_next_patchwork_state()

    def _finish_patchwork_state_flow(self) -> None:
        """Release this screen for the next Patchwork state request."""
        self._pw_state_queue = []
        self._pw_state_config = None
        self._pw_state_default = None
        self._pw_state_notify_empty = False
        self._pw_state_active = False
