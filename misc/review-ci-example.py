#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Example CI check script for b4 review tracking.
#
# This script demonstrates the external check tool JSON protocol.
# It reads an RFC 2822 email message from stdin (a single patch or
# cover letter) and prints a JSON array of check results to stdout.
#
# Configure it in your git config as either:
#
#   [b4]
#       review-perpatch-check-cmd = /path/to/review-ci-example.py
#       review-series-check-cmd = /path/to/review-ci-example.py
#
# Each result object has the following fields:
#
#   tool     (required)  Column header name in the results matrix
#   status   (required)  One of "pass", "warn", "fail"
#   summary  (optional)  One-line summary for the detail view
#   url      (optional)  Link for the maintainer to open in a browser
#   details  (optional)  Multi-line text for the scrollable detail view
#
# An empty array [] means nothing to report for this patch.
# A non-zero exit with no JSON output is treated as an execution error.
#
# This example produces random pass/warn/fail results for demonstration.
# Replace the logic below with your actual CI system queries.
#
# Environment variables set by b4:
#
#   B4_TRACKING_FILE  Path to a temporary JSON file containing the full
#                     tracking data for the series. Parse it to access
#                     branch tips, take history, patch metadata, etc.

import email
import json
import os
import random
import sys


def main() -> None:
    msg = email.message_from_binary_file(sys.stdin.buffer)
    subject = msg.get('subject', '(no subject)')  # noqa: F841
    msgid = msg.get('message-id', '').strip('<> ')

    # Example: read tracking data for commit-based CI lookups
    tracking_file = os.environ.get('B4_TRACKING_FILE', '')
    if tracking_file:
        with open(tracking_file) as fp:
            tracking = json.load(fp)
        branch_tips = tracking.get('series', {}).get('branch-tips', [])
    else:
        branch_tips = []  # noqa: F841

    # Seed the RNG with the message-id so results are stable across
    # repeated runs of the same message (simulates cached CI results).
    random.seed(msgid)

    results = []

    # Simulate a build check
    build_status = random.choice(['pass', 'pass', 'pass', 'warn', 'fail'])
    build_result = {
        'tool': 'example-build',
        'status': build_status,
        'summary': {
            'pass': 'Build succeeded',
            'warn': 'Build succeeded with warnings',
            'fail': 'Build failed',
        }[build_status],
        'url': f'https://ci.example.com/builds/{msgid}',
    }
    if build_status == 'warn':
        build_result['details'] = 'Warning: unused variable in drivers/foo.c:42'
    elif build_status == 'fail':
        build_result['details'] = (
            'Error: implicit declaration of function bar\n  drivers/foo.c:57:5'
        )
    results.append(build_result)

    # Simulate a test suite check
    test_status = random.choice(['pass', 'pass', 'pass', 'pass', 'warn', 'fail'])
    test_result = {
        'tool': 'example-test',
        'status': test_status,
        'summary': {
            'pass': '47 tests passed',
            'warn': '45 passed, 2 skipped',
            'fail': '44 passed, 3 failed',
        }[test_status],
        'url': f'https://ci.example.com/tests/{msgid}',
    }
    if test_status == 'fail':
        test_result['details'] = (
            'FAIL: test_driver_probe (drivers/foo_test.c)\n'
            'FAIL: test_driver_remove (drivers/foo_test.c)\n'
            'FAIL: test_ioctl_handler (drivers/foo_test.c)'
        )
    results.append(test_result)

    json.dump(results, sys.stdout, indent=2)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
