#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020-2021 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import sys
import pathlib
import re

import b4
import b4.mbox


logger = b4.logger


def main(cmdargs):
    if cmdargs.showkeys:
        msgid, msgs = b4.retrieve_messages(cmdargs)
        logger.info('---')
        try:
            import patatt
        except ModuleNotFoundError:
            logger.info('--show-keys requires the patatt library')
            sys.exit(1)

        keydata = set()
        for msg in msgs:
            xdk = msg.get('x-developer-key')
            xds = msg.get('x-developer-signature')
            if not xdk or not xds:
                continue
            # grab the selector they used
            kdata = b4.LoreMessage.get_parts_from_header(xdk)
            sdata = b4.LoreMessage.get_parts_from_header(xds)
            algo = kdata.get('a')
            identity = kdata.get('i')
            selector = sdata.get('s', 'default')
            if algo == 'openpgp':
                keyinfo = kdata.get('fpr')
            elif algo == 'ed25519':
                keyinfo = kdata.get('pk')
            else:
                logger.debug('Unknown key type: %s', algo)
                continue
            keydata.add((identity, algo, selector, keyinfo))

        if not keydata:
            logger.info('No keys found in the thread.')
            sys.exit(0)
        krpath = os.path.join(b4.get_data_dir(), 'keyring')
        pgp = False
        ecc = False
        for identity, algo, selector, keyinfo in keydata:
            keypath = patatt.make_pkey_path(algo, identity, selector)
            fullpath = os.path.join(krpath, keypath)
            if os.path.exists(fullpath):
                status = 'known'
            else:
                status = 'unknown'
                if algo == 'openpgp':
                    try:
                        uids = b4.get_gpg_uids(keyinfo)
                        if len(uids):
                            status = 'in default keyring'
                    except KeyError:
                        pass
            pathlib.Path(os.path.dirname(fullpath)).mkdir(parents=True, exist_ok=True)

            logger.info('%s: (%s)', identity, status)
            logger.info('    keytype: %s', algo)
            if algo == 'openpgp':
                pgp = True
                logger.info('      keyid: %s', keyinfo[-16:])
                logger.info('        fpr: %s', ':'.join(re.findall(r'.{4}', keyinfo)))
            else:
                ecc = True
                logger.info('     pubkey: %s', keyinfo)
            logger.info('     krpath: %s', keypath)
            logger.info('   fullpath: %s', fullpath)
        logger.info('---')
        if pgp:
            logger.info('For openpgp keys:')
            logger.info('    gpg --recv-key [keyid]')
            logger.info('    gpg -a --export [keyid] > [fullpath]')
        if ecc:
            logger.info('For ed25519 keys:')
            logger.info('    echo [pubkey] > [fullpath]')

        sys.exit(0)

    logger.info('This command is experimental. Try --show-keys [msgid].')
