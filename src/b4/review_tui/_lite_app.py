#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import email.utils
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Label, ListItem, ListView, LoadingIndicator, RichLog, Static
from textual.worker import Worker, WorkerState

import b4
import b4.review
import b4.review.tracking
from b4.review_tui._common import (
    _fix_ansi_theme,
    _quiet_worker,
    _write_diff_line,
    display_width,
    pad_display,
    resolve_styles,
)
from b4.review_tui._modals import FollowupReplyPreviewScreen


@dataclass
class ThreadNode:
    """A single message in the thread tree."""

    lmsg: b4.LoreMessage
    children: List['ThreadNode'] = field(default_factory=list)
    depth: int = 0
    tree_art: str = ''
    is_patch: bool = False
    attestation: List[Dict[str, Any]] = field(default_factory=list)
    att_passing: bool = True
    is_unseen: bool = False
    is_flagged: bool = False
    is_answered: bool = False


def _flatten_tree(
    roots: List[ThreadNode],
    prefix: str = '',
    is_root: bool = True,
) -> List[ThreadNode]:
    """DFS-flatten a list of roots into a list with tree_art set."""
    result: List[ThreadNode] = []
    for i, node in enumerate(roots):
        is_last = i == len(roots) - 1
        if is_root:
            node.tree_art = ''
        else:
            node.tree_art = prefix + ('\u2514\u2500>' if is_last else '\u251c\u2500>')
        result.append(node)
        if node.children:
            if is_root:
                child_prefix = ''
            else:
                child_prefix = prefix + ('  ' if is_last else '\u2502 ')
            result.extend(_flatten_tree(node.children, child_prefix, is_root=False))
    return result


def build_thread_tree(lmbx: b4.LoreMailbox) -> List[ThreadNode]:
    """Build a flat, DFS-ordered thread list from a LoreMailbox.

    Creates ThreadNode for every message, links children to parents
    via in_reply_to, sorts by date, flattens with tree art, and
    checks attestation status for each message.
    """
    config = b4.get_main_config()
    attpolicy = str(config.get('attestation-policy', 'softfail'))
    try:
        maxdays = int(str(config.get('attestation-staleness-days', '0')))
    except ValueError:
        maxdays = 0

    nodes: Dict[str, ThreadNode] = {}
    for msgid, lmsg in lmbx.msgid_map.items():
        att_list: List[Dict[str, Any]] = []
        att_passing = True
        if attpolicy != 'off':
            att_list, att_passing, _critical = lmsg.get_attestation_status(
                attpolicy, maxdays
            )
        nodes[msgid] = ThreadNode(
            lmsg=lmsg,
            is_patch=lmsg.has_diff,
            attestation=att_list,
            att_passing=att_passing,
        )

    roots: List[ThreadNode] = []
    for node in nodes.values():
        parent_id = node.lmsg.in_reply_to
        if parent_id and parent_id in nodes:
            nodes[parent_id].children.append(node)
        else:
            roots.append(node)

    def _sort_key(n: ThreadNode) -> Any:
        return n.lmsg.date

    def _sort_recursive(node_list: List[ThreadNode]) -> None:
        node_list.sort(key=_sort_key)
        for n in node_list:
            if n.children:
                _sort_recursive(n.children)

    _sort_recursive(roots)

    flat = _flatten_tree(roots)
    for i, node in enumerate(flat):
        node.depth = i  # store position for reference
    return flat


def _build_thread_label(node: ThreadNode, ts: Optional[Dict[str, str]] = None) -> Text:
    """Build the Text label for a thread index row."""
    lmsg = node.lmsg
    if lmsg.date:
        date_str = lmsg.date.strftime('%d %b')
    else:
        date_str = '     '
    author = lmsg.fromname or lmsg.fromemail
    if display_width(author) > 20:
        while display_width(author) > 19:
            author = author[:-1]
        author += '\u2026'
    author = pad_display(author, 20)
    is_unseen = node.is_unseen
    unseen_style = f'bold {ts["warning"]}' if ts else 'bold'
    flag_style = f'bold {ts["accent"]}' if ts else 'bold'
    answered_style = ts['success'] if ts else ''
    if node.is_answered:
        row_style = f'dim {ts["success"]}' if ts else 'dim'
    elif is_unseen:
        row_style = ''
    elif node.is_flagged:
        row_style = f'bold {ts["accent"]}' if ts else 'bold'
    else:
        row_style = 'dim'
    text = Text(no_wrap=True, overflow='ellipsis')
    if node.is_answered:
        text.append('\u21a9 ', style=answered_style)
    elif is_unseen:
        text.append('N ', style=unseen_style)
    elif node.is_flagged:
        text.append('\u2605 ', style=flag_style)
    else:
        text.append('  ', style=row_style)
    text.append(f'{date_str} ', style=row_style)
    text.append(f'{author} ', style=row_style)
    if node.tree_art:
        text.append(node.tree_art, style='dim' if not node.is_flagged else row_style)
    text.append(lmsg.full_subject, style=row_style)
    return text


class ThreadIndexItem(ListItem):
    """A single row in the thread index showing date, author, tree art and subject."""

    def __init__(self, node: ThreadNode) -> None:
        super().__init__()
        self.node = node

    def compose(self) -> ComposeResult:
        ts = resolve_styles(self.app)
        yield Label(_build_thread_label(self.node, ts))


class MessageViewScreen(ModalScreen[None]):
    """Full message view with headers and body."""

    BINDINGS = [
        Binding('r', 'reply', 'reply'),
        Binding('F', 'toggle_flag', 'flag', key_display='F'),
        Binding('S', 'skip_quoted', 'skip quoted'),
        Binding('j', 'next_message', 'next msg'),
        Binding('k', 'prev_message', 'prev msg'),
        Binding('q', 'back', 'back'),
        Binding('escape', 'back', 'back', show=False),
        Binding('enter', 'scroll_down', 'scroll down', show=False),
        Binding('backspace', 'scroll_up', 'scroll up', show=False),
        Binding('space', 'page_down', 'page down', show=False),
        Binding('minus', 'page_up', 'page up', show=False),
        Binding('circumflex_accent', 'scroll_top', 'top', show=False),
        Binding('dollar_sign', 'scroll_bottom', 'bottom', show=False),
    ]

    DEFAULT_CSS = """
    MessageViewScreen {
        align: center middle;
    }
    #msg-dialog {
        width: 92%;
        height: 90%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #msg-title {
        text-style: bold;
    }
    #msg-viewer {
        height: 1fr;
    }
    #msg-hint {
        height: 1;
        dock: bottom;
        color: $text-muted;
    }
    """

    def __init__(self, node: ThreadNode, lite_screen: 'LiteThreadScreen') -> None:
        super().__init__()
        self._node = node
        self._lite_screen = lite_screen

    def compose(self) -> ComposeResult:
        with Vertical(id='msg-dialog'):
            yield Static(
                f'Subject: {self._node.lmsg.full_subject}', id='msg-title', markup=False
            )
            yield RichLog(
                id='msg-viewer',
                highlight=False,
                wrap=True,
                markup=False,
                auto_scroll=False,
            )
            yield Static(
                'r reply  |  F flag  |  S skip quoted  |  j/k prev/next msg  |  q back',
                id='msg-hint',
            )

    def on_mount(self) -> None:
        self._render_message()
        self._update_title()
        self._lite_screen.mark_seen(self._node)

    def _update_title(self) -> None:
        """Update the subject title bar, reflecting flagged state."""
        subject = self._node.lmsg.full_subject
        title = self.query_one('#msg-title', Static)
        if self._node.is_flagged:
            ts = resolve_styles(self.app)
            text = Text()
            text.append(f'Subject: {subject} \u2605', style=f'bold {ts["accent"]}')
            title.update(text)
        else:
            title.update(f'Subject: {subject}')

    def _render_message(self) -> None:
        """Render the current node's message into the viewer."""
        lmsg = self._node.lmsg
        msg = lmsg.msg
        viewer = self.query_one('#msg-viewer', RichLog)
        viewer.clear()
        ts = resolve_styles(self.app)

        # Content width: 92% of terminal minus border (2) and padding (4)
        content_width = max(40, int(self.app.size.width * 0.92) - 6)

        # Render headers — dim so the body draws the eye
        addr_hdrs = {'to', 'cc'}
        for hdr_name in ('Date', 'From', 'To', 'Cc'):
            val = msg.get(hdr_name)
            if not val:
                continue
            val = str(val)
            if hdr_name.lower() in addr_hdrs:
                pairs = email.utils.getaddresses([val])
                if pairs:
                    self._write_addr_header(viewer, hdr_name, pairs, content_width)
            else:
                hdr_text = Text()
                hdr_text.append(f'{hdr_name}: ', style='dim bold')
                hdr_text.append(val, style='dim')
                viewer.write(hdr_text)

        # Link header — more useful to maintainers than raw Message-ID
        config = b4.get_main_config()
        linkmask = str(config.get('linkmask', ''))
        if '%s' in linkmask and lmsg.msgid:
            linkurl = linkmask % lmsg.msgid
            hdr_text = Text()
            hdr_text.append('Link: ', style='dim bold')
            hdr_text.append(linkurl, style=f'dim link {linkurl}')
            viewer.write(hdr_text)

        # Attestation status
        node = self._node
        if node.attestation:
            att_text = Text()
            att_text.append('Attestation: ', style='dim bold')
            for i, att in enumerate(node.attestation):
                if i > 0:
                    att_text.append(', ', style='dim')
                status = att.get('status', 'unknown')
                identity = att.get('identity', 'unknown')
                if att.get('passing'):
                    att_text.append(f'\u2713 {identity}', style=ts['success'])
                    if 'mismatch' in att:
                        att_text.append(
                            f' (From: {att["mismatch"]})', style=ts['warning']
                        )
                else:
                    if status == 'badsig':
                        att_text.append(f'\u2717 BADSIG: {identity}', style=ts['error'])
                    elif status == 'nokey':
                        att_text.append(
                            f'\u2717 No key: {identity}', style=ts['warning']
                        )
                    else:
                        att_text.append(
                            f'\u2717 {status}: {identity}', style=ts['error']
                        )
            viewer.write(att_text)

        viewer.write('')

        # Render body
        body = lmsg.body or ''
        in_diff = False
        for line in body.splitlines():
            if line.startswith('diff --git '):
                in_diff = True
            if in_diff:
                _write_diff_line(viewer, line, ts=ts)
            elif line.startswith('>'):
                viewer.write(Text(line, style=f'dim {ts["accent"]}'))
            elif line.startswith('---'):
                viewer.write(Text(line, style='dim'))
            else:
                viewer.write(Text(line))

    @staticmethod
    def _write_addr_header(
        viewer: RichLog,
        hdr_name: str,
        pairs: List[Any],
        width: int,
    ) -> None:
        """Write an address header, packing addresses to fill each line."""
        indent_len = len(hdr_name) + 2  # "Cc: "
        indent = ' ' * indent_len
        formatted = [b4.format_addrs([p], clean=True) for p in pairs]

        line = Text()
        line.append(f'{hdr_name}: ', style='dim bold')
        line_len = indent_len

        for i, addr in enumerate(formatted):
            sep = ', ' if i > 0 else ''
            needed = len(sep) + len(addr)
            if i > 0 and line_len + needed > width:
                # Finish current line and start a new indented one
                viewer.write(line)
                line = Text()
                line.append(indent, style='dim')
                line_len = indent_len
                sep = ''
                needed = len(addr)
            if sep:
                line.append(sep, style='dim')
            line.append(addr, style='dim')
            line_len += needed

        if line.plain.strip():
            viewer.write(line)

    def action_reply(self) -> None:
        self._lite_screen.compose_reply(self._node)

    def action_toggle_flag(self) -> None:
        self._lite_screen.toggle_flag(self._node)
        self._update_title()

    def _switch_to_node(self, offset: int) -> None:
        """Switch to the message at offset from current in the thread list."""
        nodes = self._lite_screen._thread_nodes
        try:
            idx = nodes.index(self._node)
        except ValueError:
            return
        new_idx = idx + offset
        if 0 <= new_idx < len(nodes):
            self._node = nodes[new_idx]
            self._update_title()
            self._render_message()
            self.query_one('#msg-viewer', RichLog).scroll_home()
            self._lite_screen.mark_seen(self._node)

    def action_next_message(self) -> None:
        self._switch_to_node(1)

    def action_prev_message(self) -> None:
        self._switch_to_node(-1)

    def action_skip_quoted(self) -> None:
        """Skip past the next block of quoted lines (mutt-style S)."""
        viewer = self.query_one('#msg-viewer', RichLog)
        lines = viewer.lines
        if not lines:
            return
        cur = int(viewer.scroll_y)
        total = len(lines)
        # Phase 1: find start of a quoted block at or after current pos
        i = cur
        while i < total and not lines[i].text.lstrip().startswith('>'):
            i += 1
        if i >= total:
            return  # no quoted block ahead
        # Phase 2: skip past the quoted block
        while i < total and lines[i].text.lstrip().startswith('>'):
            i += 1
        if i < total:
            # Show a couple of trailing quote lines for context
            target = max(0, i - 2)
            viewer.scroll_to(y=target)

    def action_back(self) -> None:
        self.dismiss(None)

    def action_scroll_down(self) -> None:
        self.query_one('#msg-viewer', RichLog).scroll_down()

    def action_scroll_up(self) -> None:
        self.query_one('#msg-viewer', RichLog).scroll_up()

    def action_page_down(self) -> None:
        self.query_one('#msg-viewer', RichLog).scroll_page_down()

    def action_page_up(self) -> None:
        self.query_one('#msg-viewer', RichLog).scroll_page_up()

    def action_scroll_top(self) -> None:
        self.query_one('#msg-viewer', RichLog).scroll_home()

    def action_scroll_bottom(self) -> None:
        self.query_one('#msg-viewer', RichLog).scroll_end()


class LiteThreadScreen(ModalScreen[None]):
    """Mutt-style lite thread viewer for browsing a mail thread."""

    DEFAULT_CSS = """
    LiteThreadScreen {
        align: center middle;
    }
    #lite-dialog {
        width: 92%;
        height: 90%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #lite-list {
        height: 1fr;
    }
    #lite-loading {
        height: 1fr;
        content-align: center middle;
    }
    #lite-hint {
        height: 1;
        dock: bottom;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding('j', 'cursor_down', 'down', show=False),
        Binding('k', 'cursor_up', 'up', show=False),
        Binding('q', 'back', 'back'),
        Binding('escape', 'back', 'back', show=False),
    ]

    def __init__(
        self,
        message_id: str,
        email_dryrun: bool = False,
        patatt_sign: bool = True,
        tracking_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__()
        self._message_id = message_id
        self._email_dryrun = email_dryrun
        self._patatt_sign = patatt_sign
        self._tracking_info = tracking_info
        self._thread_nodes: List[ThreadNode] = []

    def compose(self) -> ComposeResult:
        with Vertical(id='lite-dialog'):
            yield LoadingIndicator(id='lite-loading')
            yield Static(
                'Enter view  |  j/k navigate  |  q back',
                id='lite-hint',
            )

    def on_mount(self) -> None:
        _fix_ansi_theme(self.app)
        self.run_worker(self._fetch_thread, name='_fetch_thread', thread=True)

    def _refresh_msg_count(self, total_messages: int) -> None:
        """Opportunistically refresh message count from fetched messages."""
        if not self._tracking_info:
            return
        try:
            b4.review.tracking.refresh_message_count(
                self._tracking_info['identifier'],
                self._tracking_info['change_id'],
                self._tracking_info['revision'],
                total_messages,
            )
        except Exception:
            pass

    def _sync_unseen(self, unseen_count: int) -> None:
        """Sync seen_message_count in the tracking DB from unseen count."""
        if not self._tracking_info:
            return
        try:
            b4.review.tracking.sync_seen_from_unseen_count(
                self._tracking_info['identifier'],
                self._tracking_info['change_id'],
                self._tracking_info['revision'],
                unseen_count,
            )
        except Exception:
            pass

    def _fetch_thread(self) -> List[ThreadNode]:
        with _quiet_worker():
            ti = self._tracking_info or {}
            series_dict: Dict[str, Any] = {
                'message_id': self._message_id,
                'change_id': ti.get('change_id', ''),
                'revision': ti.get('revision'),
            }
            identifier = ti.get('identifier', '')
            if identifier:
                msgs = b4.review.retrieve_series_messages(series_dict, identifier)
            else:
                msgs = b4.review._retrieve_messages(self._message_id)
            self._refresh_msg_count(len(msgs))
            lmbx = b4.LoreMailbox()
            for msg in msgs:
                lmbx.add_message(msg)
            return build_thread_tree(lmbx)

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != '_fetch_thread':
            return
        if event.state == WorkerState.SUCCESS:
            if event.worker.result is None:
                return
            self._thread_nodes = event.worker.result
            await self._populate()
        elif event.state == WorkerState.ERROR:
            await self.query_one('#lite-loading', LoadingIndicator).remove()
            self.app.notify(str(event.worker.error), severity='error')

    async def _populate(self) -> None:
        await self.query_one('#lite-loading', LoadingIndicator).remove()
        if not self._thread_nodes:
            self.app.notify('No messages found', severity='warning')
            return
        try:
            from b4.review import messages

            conn = messages.get_db()
            msgids = [n.lmsg.msgid for n in self._thread_nodes if n.lmsg.msgid]
            flags_map = messages.get_flags_bulk(conn, msgids)
            conn.close()
            unseen_count = 0
            for node in self._thread_nodes:
                flags = flags_map.get(node.lmsg.msgid, '').split()
                node.is_unseen = 'Seen' not in flags
                node.is_flagged = 'Flagged' in flags
                node.is_answered = 'Answered' in flags
                if node.is_unseen:
                    unseen_count += 1
            # Sync the tracking DB so the Fups column matches the N markers
            self._sync_unseen(unseen_count)
        except Exception:
            pass
        self._detect_maintainer_replies()
        items = [ThreadIndexItem(node) for node in self._thread_nodes]
        lv = ListView(*items, id='lite-list')
        await self.mount(lv, before=self.query_one('#lite-hint', Static))
        lv.focus()

    @staticmethod
    def _msg_date(node: ThreadNode) -> Optional[str]:
        return node.lmsg.date.isoformat() if node.lmsg.date else None

    def mark_seen(self, node: ThreadNode) -> None:
        """Mark a single message as Seen in the messages DB."""
        if not node.is_unseen:
            return
        node.is_unseen = False
        msgid = node.lmsg.msgid
        if not msgid:
            return
        try:
            from b4.review import messages

            conn = messages.get_db()
            messages.set_flag(conn, msgid, 'Seen', self._msg_date(node))
            conn.close()
        except Exception:
            pass

    def _mark_answered(self, node: ThreadNode) -> None:
        """Mark a message as Answered in the messages DB."""
        node.is_answered = True
        msgid = node.lmsg.msgid
        if not msgid:
            return
        try:
            from b4.review import messages

            conn = messages.get_db()
            messages.set_flag(conn, msgid, 'Answered', self._msg_date(node))
            conn.close()
        except Exception:
            pass

    def _detect_maintainer_replies(self) -> None:
        """Detect messages sent by the maintainer and infer flags.

        When the maintainer replied via their own email client:
        - their own messages are marked Seen
        - the immediate parent is marked Answered
        - all ancestor messages are marked Seen
        """
        try:
            _, maintainer_email = b4.get_mailfrom()
        except Exception:
            return
        if not maintainer_email:
            return
        maintainer_email = maintainer_email.lower()
        node_map = {n.lmsg.msgid: n for n in self._thread_nodes if n.lmsg.msgid}
        seen_entries: List[Dict[str, Optional[str]]] = []
        answered_entries: List[Dict[str, Optional[str]]] = []

        for node in self._thread_nodes:
            if not node.lmsg.fromemail:
                continue
            if node.lmsg.fromemail.lower() != maintainer_email:
                continue
            # Maintainer's own message → Seen
            if node.is_unseen:
                node.is_unseen = False
                seen_entries.append(
                    {'msgid': node.lmsg.msgid, 'msg_date': self._msg_date(node)}
                )
            # Immediate parent → Answered
            parent_id = node.lmsg.in_reply_to
            if parent_id and parent_id in node_map:
                parent = node_map[parent_id]
                if not parent.is_answered:
                    parent.is_answered = True
                    answered_entries.append(
                        {'msgid': parent_id, 'msg_date': self._msg_date(parent)}
                    )
            # All ancestors → Seen
            ancestor_id = node.lmsg.in_reply_to
            while ancestor_id and ancestor_id in node_map:
                ancestor = node_map[ancestor_id]
                if ancestor.is_unseen:
                    ancestor.is_unseen = False
                    seen_entries.append(
                        {'msgid': ancestor_id, 'msg_date': self._msg_date(ancestor)}
                    )
                ancestor_id = ancestor.lmsg.in_reply_to

        if not seen_entries and not answered_entries:
            return
        try:
            from b4.review import messages

            conn = messages.get_db()
            if seen_entries:
                messages.set_flags_bulk(conn, seen_entries, 'Seen')
            if answered_entries:
                messages.set_flags_bulk(conn, answered_entries, 'Answered')
            conn.close()
        except Exception:
            pass

    def toggle_flag(self, node: ThreadNode) -> None:
        """Toggle the Flagged state on a message."""
        node.is_flagged = not node.is_flagged
        msgid = node.lmsg.msgid
        if not msgid:
            return
        try:
            from b4.review import messages

            conn = messages.get_db()
            if node.is_flagged:
                messages.set_flag(conn, msgid, 'Flagged', self._msg_date(node))
            else:
                messages.remove_flag(conn, msgid, 'Flagged')
            conn.close()
        except Exception:
            pass

    def action_cursor_down(self) -> None:
        try:
            self.query_one('#lite-list', ListView).action_cursor_down()
        except Exception:
            pass

    def action_cursor_up(self) -> None:
        try:
            self.query_one('#lite-list', ListView).action_cursor_up()
        except Exception:
            pass

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle Enter on thread index — open message view."""
        event.stop()
        if isinstance(event.item, ThreadIndexItem):
            self.app.push_screen(
                MessageViewScreen(event.item.node, self),
                callback=lambda _: self._refresh_labels(),
            )

    def _refresh_labels(self) -> None:
        """Refresh thread index labels to reflect flag/seen changes."""
        try:
            lv = self.query_one('#lite-list', ListView)
        except Exception:
            return
        ts = resolve_styles(self.app)
        for item in lv.query(ThreadIndexItem):
            item.query_one(Label).update(_build_thread_label(item.node, ts))

    def compose_reply(
        self, node: ThreadNode, initial_text: Optional[str] = None
    ) -> None:
        """Compose a reply to the given thread node using external editor."""
        lmsg = node.lmsg
        if initial_text is not None:
            editor_text = initial_text
        else:
            orig_date = lmsg.date.strftime('%Y-%m-%d %H:%M %z') if lmsg.date else ''
            orig_author = lmsg.fromname or lmsg.fromemail
            body = lmsg.body or ''
            quoted = '\n'.join(f'> {line}' for line in body.splitlines())
            editor_text = f'On {orig_date}, {orig_author} wrote:\n{quoted}\n\n'

        with self.app.suspend():
            result = b4.edit_in_editor(editor_text.encode(), filehint='reply.eml')
        reply_text = result.decode(errors='replace')
        if reply_text == editor_text:
            self.app.notify('No changes made')
            return

        # Build entry dict that FollowupReplyPreviewScreen expects
        entry: Dict[str, Any] = {
            'lmsg': lmsg,
            'fromname': lmsg.fromname,
            'fromemail': lmsg.fromemail,
            'date': lmsg.date,
            'body': lmsg.body or '',
        }

        def _on_preview(action: Optional[str]) -> None:
            if action == 'send':
                self._send_reply(node, reply_text)
            elif action == 'edit':
                self.compose_reply(node, reply_text)

        self.app.push_screen(FollowupReplyPreviewScreen(entry, reply_text), _on_preview)

    def _send_reply(self, node: ThreadNode, text: str) -> None:
        """Build and send a reply to the given thread node."""
        lmsg = node.lmsg
        msg = lmsg.make_reply(text)
        try:
            with self.app.suspend():
                smtp, fromaddr = b4.get_smtp(dryrun=self._email_dryrun)
                sent = b4.send_mail(
                    smtp,
                    [msg],
                    fromaddr=fromaddr,
                    patatt_sign=self._patatt_sign,
                    dryrun=self._email_dryrun,
                    output_dir=None,
                    reflect=False,
                )
            if sent is None:
                self.app.notify('Failed to send reply.', severity='error')
            elif self._email_dryrun:
                self.app.notify(f'Dry-run: reply to {lmsg.fromemail} logged, not sent')
                self._mark_answered(node)
            else:
                self.app.notify(f'Reply sent to {lmsg.fromemail}')
                self._mark_answered(node)
        except Exception as ex:
            self.app.notify(f'Send failed: {ex}', severity='error')

    def action_back(self) -> None:
        if self._thread_nodes:
            unseen = sum(1 for n in self._thread_nodes if n.is_unseen)
            self._sync_unseen(unseen)
        self.dismiss(None)
