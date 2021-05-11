#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#

import sys
import b4
import argparse
try:
    import patatt
    can_patatt = True
except ModuleNotFoundError:
    can_patatt = False

from collections import namedtuple

logger = b4.logger


def attest_patches(cmdargs: argparse.Namespace) -> None:
    if not can_patatt:
        logger.critical('ERROR: b4 now uses patatt for patch attestation. See:')
        logger.critical('       https://git.kernel.org/pub/scm/utils/patatt/patatt.git/about/')
        sys.exit(1)

    # directly invoke cmd_sign in patatt
    config = patatt.get_config_from_git(r'patatt\..*', multivals=['keyringsrc'])
    fakeargs = namedtuple('Struct', ['hookmode', 'msgfile'])
    fakeargs.hookmode = True
    fakeargs.msgfile = cmdargs.patchfile
    patatt.cmd_sign(fakeargs, config)
