#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Tests for ``b4 review show-info``."""

import json

import pytest

from b4.review._review import (
    get_review_info,
    list_review_branches,
    show_review_info,
)

from .helpers.tracking import create_review_branch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# TestGetReviewInfo
# ---------------------------------------------------------------------------


class TestGetReviewInfo:
    def test_basic_info(self, gitdir: str) -> None:
        branch = create_review_branch(
            gitdir, 'basic-change-id', subject='Basic test series', status='reviewing'
        )
        info = get_review_info(gitdir, branch)

        assert info['branch'] == branch
        assert info['change-id'] == 'basic-change-id'
        assert info['status'] == 'reviewing'
        assert info['subject'] == 'Basic test series'
        assert info['revision'] == 1
        assert info['complete'] is True
        assert info['num-prereqs'] == 0
        assert info['base-commit'] is not None
        assert info['first-patch-commit'] is not None

    def test_sender_format(self, gitdir: str) -> None:
        branch = create_review_branch(
            gitdir,
            'sender-test',
            sender_name='Alice Author',
            sender_email='alice@example.com',
        )
        info = get_review_info(gitdir, branch)
        assert info['sender'] == 'Alice Author <alice@example.com>'

    def test_commit_keys(self, gitdir: str) -> None:
        branch = create_review_branch(gitdir, 'commit-keys-test', num_real_commits=3)
        info = get_review_info(gitdir, branch)

        assert info['num-patches'] == 3
        commit_keys = [k for k in info if k.startswith('commit-')]
        assert len(commit_keys) == 3
        # Each commit key should have a subject value
        for k in commit_keys:
            val = info[k]
            assert isinstance(val, str)
            assert len(val) > 0


# ---------------------------------------------------------------------------
# TestShowReviewInfo
# ---------------------------------------------------------------------------


class TestShowReviewInfo:
    def test_all_keys(self, gitdir: str, capsys: pytest.CaptureFixture[str]) -> None:
        create_review_branch(gitdir, 'show-all-test', subject='All keys test')
        show_review_info('b4/review/show-all-test:_all')
        out = capsys.readouterr().out
        assert 'branch: b4/review/show-all-test' in out
        assert 'change-id: show-all-test' in out
        assert 'subject: All keys test' in out

    def test_single_key(self, gitdir: str, capsys: pytest.CaptureFixture[str]) -> None:
        create_review_branch(gitdir, 'single-key-test', status='applied')
        show_review_info('b4/review/single-key-test:status')
        out = capsys.readouterr().out
        assert out.strip() == 'applied'

    def test_named_branch(
        self, gitdir: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        branch = create_review_branch(gitdir, 'named-branch-test')
        show_review_info(branch)
        out = capsys.readouterr().out
        assert 'branch: b4/review/named-branch-test' in out

    def test_shorthand(self, gitdir: str, capsys: pytest.CaptureFixture[str]) -> None:
        create_review_branch(gitdir, 'shorthand-test')
        show_review_info('shorthand-test:status')
        out = capsys.readouterr().out
        assert out.strip() == 'reviewing'

    def test_branch_not_found(self, gitdir: str) -> None:
        with pytest.raises(SystemExit):
            show_review_info('nonexistent-branch:status')

    def test_not_review_branch(self, gitdir: str) -> None:
        with pytest.raises(SystemExit):
            show_review_info('master:status')

    def test_json_output(self, gitdir: str, capsys: pytest.CaptureFixture[str]) -> None:
        create_review_branch(gitdir, 'json-test', subject='JSON output test')
        show_review_info('b4/review/json-test:_all', as_json=True)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data['change-id'] == 'json-test'
        assert data['subject'] == 'JSON output test'


# ---------------------------------------------------------------------------
# TestListReviewBranches
# ---------------------------------------------------------------------------


class TestListReviewBranches:
    def test_list_multiple(
        self, gitdir: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        create_review_branch(gitdir, 'list-alpha', subject='Alpha series')
        create_review_branch(gitdir, 'list-bravo', subject='Bravo series')
        list_review_branches()
        out = capsys.readouterr().out
        assert 'list-alpha' in out
        assert 'list-bravo' in out

    def test_list_empty(self, gitdir: str, capsys: pytest.CaptureFixture[str]) -> None:
        list_review_branches()
        # Should not crash; logger.info prints the message
        out = capsys.readouterr().out
        assert out == ''  # message goes to logger, not stdout

    def test_list_json(self, gitdir: str, capsys: pytest.CaptureFixture[str]) -> None:
        create_review_branch(gitdir, 'json-alpha', subject='Alpha JSON')
        create_review_branch(gitdir, 'json-bravo', subject='Bravo JSON')
        list_review_branches(as_json=True)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) == 2
        change_ids = {d['change-id'] for d in data}
        assert 'json-alpha' in change_ids
        assert 'json-bravo' in change_ids


# ---------------------------------------------------------------------------
# TestTargetBranchInInfo
# ---------------------------------------------------------------------------


class TestTargetBranchInInfo:
    def test_target_branch_in_info(self, gitdir: str) -> None:
        """Branch with target-branch in tracking data includes it in info."""
        branch_name = create_review_branch(
            gitdir,
            'target-info-test',
            subject='Target info test',
            sender_name='Test',
            series_extra={'target-branch': 'sound/for-next'},
        )
        info = get_review_info(gitdir, branch_name)
        assert info['target-branch'] == 'sound/for-next'

    def test_target_branch_fallback(self, gitdir: str) -> None:
        """No per-series target + single config value = fallback shown."""
        from unittest.mock import patch as mock_patch

        branch = create_review_branch(
            gitdir, 'target-fallback-test', subject='Fallback test'
        )
        with mock_patch(
            'b4.review.tracking.get_review_target_branch_default',
            return_value='regulator/for-next',
        ):
            info = get_review_info(gitdir, branch)
        assert info['target-branch'] == 'regulator/for-next'

    def test_target_branch_none(self, gitdir: str) -> None:
        """No per-series target + no config = None."""
        branch = create_review_branch(gitdir, 'target-none-test', subject='None test')
        info = get_review_info(gitdir, branch)
        assert info['target-branch'] is None
