#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020-2021 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import argparse
import os
import re
import sys
from typing import Any, Dict, List, NoReturn, Optional

import b4
import b4.tofu as tofu

logger = b4.logger


def _fail(*lines: str) -> NoReturn:
    for line in lines:
        logger.critical(line)
    sys.exit(1)


def _keyring_note(identity: str) -> Optional[str]:
    """Explain that the keyring wins, if it has a key for *identity*."""
    if tofu.keyring_keys(identity, b4.get_keyring_sources()):
        return 'Your keyring has a key for this address, so it is used instead.'
    return None


def _never_seen(entry: Dict[str, Any]) -> bool:
    """True for a key added by hand that no message used yet."""
    return bool(
        entry['origin'] == 'manual' and entry['last_seen'] == entry['first_seen']
    )


def _key_line(entry: Dict[str, Any]) -> str:
    if _never_seen(entry):
        when = f'added by hand {tofu.fmt_day(entry["first_seen"])}'
    else:
        when = f'last seen {tofu.fmt_day(entry["last_seen"])}'
    return (
        f'{entry["status"]:<9} {tofu.short_key(entry["pk"])}  '
        f'{entry["count"]:>3} series  {when}'
    )


def cmd_list(cmdargs: argparse.Namespace) -> None:
    idents = tofu.identities()
    if not idents:
        logger.info('No keys trusted on first use yet.')
        return
    for identity in idents:
        logger.info('%s', identity)
        for entry in tofu.key_history(identity):
            logger.info('  %s', _key_line(entry))
        note = _keyring_note(identity)
        if note:
            logger.info('  (%s)', note)


def cmd_show(cmdargs: argparse.Namespace) -> None:
    identity = cmdargs.identity.lower()
    history = tofu.key_history(identity)
    if not history:
        logger.info('Nothing known about %s.', identity)
        return
    recent = tofu.recent_series(identity, limit=max(cmdargs.recent, 0))
    linkmask = str(b4.get_main_config().get('linkmask', b4.LINKADDR + '/%s'))
    logger.info('%s', identity)
    note = _keyring_note(identity)
    if note:
        logger.info('  %s', note)
    for entry in history:
        logger.info('---')
        logger.info('  Key: %s', entry['pk'])
        logger.info('    Status: %s (%s)', entry['status'], entry['origin'])
        if _never_seen(entry):
            logger.info('    Added by hand: %s', tofu.fmt_day(entry['first_seen']))
        else:
            logger.info(
                '    First seen: %s, last seen: %s',
                tofu.fmt_day(entry['first_seen']),
                tofu.fmt_day(entry['last_seen']),
            )
        logger.info('    Counted series: %s', entry['count'])
        for series in recent.get(entry['pk'], list()):
            flag = '' if series['counted'] else '  (not counted)'
            logger.info(
                '      %s  %s%s',
                tofu.fmt_day(series['seen_at']),
                series['subject'] or '(no subject)',
                flag,
            )
            logger.info('                  %s', linkmask % series['series_key'])
    pending = [entry for entry in history if entry['status'] == 'pending']
    if pending:
        logger.info('---')
        logger.info('Check with the developer through a channel you trust, then:')
        for entry in pending:
            short = entry['pk'][:10]
            logger.info(
                '  b4 kr accept %s %s --add      (an extra key)', identity, short
            )
            logger.info('  b4 kr accept %s %s --replace  (a new key)', identity, short)
            logger.info('  b4 kr reject %s %s', identity, short)


def _resolve(identity: str, pk: str) -> str:
    try:
        return tofu.resolve_pk(identity, pk)
    except tofu.TofuError as ex:
        _fail(str(ex))


def cmd_accept(cmdargs: argparse.Namespace) -> None:
    identity = cmdargs.identity.lower()
    pk = _resolve(identity, cmdargs.pk)
    history = tofu.key_history(identity)
    others = [
        entry['pk']
        for entry in history
        if entry['status'] == 'trusted' and entry['pk'] != pk
    ]
    if others and cmdargs.mode is None:
        lines = [f'{identity} already has a trusted key:']
        lines += [f'  {other}' for other in others]
        lines.append('Use --add to trust both, or --replace to retire the old one.')
        _fail(*lines)
    if pk not in [entry['pk'] for entry in history]:
        logger.info('This key was never seen in a message, adding it by hand.')
    try:
        retired = tofu.accept_key(identity, pk, replace=cmdargs.mode == 'replace')
    except tofu.TofuError as ex:
        _fail(str(ex))
    logger.info('Trusted for %s: %s', identity, pk)
    for oldpk in retired:
        logger.info('Retired: %s', oldpk)
    note = _keyring_note(identity)
    if note:
        logger.info(note)


def cmd_reject(cmdargs: argparse.Namespace) -> None:
    identity = cmdargs.identity.lower()
    pk = _resolve(identity, cmdargs.pk)
    try:
        tofu.reject_key(identity, pk)
    except tofu.TofuError as ex:
        _fail(str(ex))
    logger.info('Rejected for %s: %s', identity, pk)
    if not any(entry['status'] == 'trusted' for entry in tofu.key_history(identity)):
        logger.info('No trusted key is left for this address.')
        logger.info('The next key it uses must be accepted by hand.')


def cmd_forget(cmdargs: argparse.Namespace) -> None:
    identity = cmdargs.identity.lower()
    history = tofu.key_history(identity)
    if not history:
        logger.info('Nothing known about %s.', identity)
        return
    logger.info('Known keys for %s:', identity)
    for entry in history:
        logger.info('  %s', _key_line(entry))
    logger.info('---')
    try:
        answer = input('Forget all keys and series seen for this address? (y/N) ')
    except KeyboardInterrupt:
        logger.info('')
        sys.exit(130)
    if answer.strip().lower() not in ('y', 'yes'):
        logger.info('Aborted, nothing forgotten.')
        return
    nkeys, nsight = tofu.forget_identity(identity)
    logger.info('Forgot %s keys and %s sightings for %s.', nkeys, nsight, identity)
    logger.info('The next valid series from this address pins a key again.')


def cmd_promote(cmdargs: argparse.Namespace) -> None:
    identity = cmdargs.identity.lower()
    if cmdargs.pk:
        pk = _resolve(identity, cmdargs.pk)
    else:
        trusted = [
            entry['pk']
            for entry in tofu.key_history(identity)
            if entry['status'] == 'trusted'
        ]
        if len(trusted) != 1:
            _fail(
                f'{identity} has {len(trusted)} trusted keys, name the key to promote.'
            )
        pk = trusted[0]
    try:
        path = tofu.promote_key(identity, pk, cmdargs.selector, force=cmdargs.force)
    except tofu.TofuError as ex:
        _fail(
            str(ex), 'Use --force to overwrite it, or --selector to pick another name.'
        )
    logger.info('Wrote %s', path)
    logger.info('Signatures from %s are now checked against your keyring.', identity)


def _tofu_state(identity: str, pk: str) -> str:
    for entry in tofu.key_history(identity):
        if entry['pk'] == pk:
            return f'{entry["status"]} on first use, {entry["count"]} series'
    return 'unknown'


def cmd_show_keys(cmdargs: argparse.Namespace) -> None:
    if cmdargs.showkeys:
        logger.warning('"b4 kr --show-keys" is deprecated, use "b4 kr show-keys"')
    _, msgs = b4.retrieve_messages(cmdargs)
    if not msgs:
        logger.info('No messages found in the thread.')
        sys.exit(0)
    logger.info('---')
    import patatt

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
    sources = b4.get_keyring_sources()
    promote: List[str] = list()
    pgp = False
    for identity, algo, selector, keyinfo in sorted(keydata):
        if not identity:
            logger.warning(
                'No identity found for key %s %s %s', algo, selector, keyinfo
            )
            continue
        if not keyinfo:
            logger.warning(
                'No keyinfo found for key %s %s %s', algo, selector, identity
            )
            continue
        keypath = patatt.make_pkey_path(algo, identity, selector)
        fullpath = os.path.join(krpath, keypath)
        if algo == 'ed25519':
            if keyinfo in tofu.keyring_keys(identity, sources):
                status = 'in keyring'
            else:
                status = _tofu_state(identity.lower(), keyinfo)
                cmd = f'b4 kr promote {identity} {keyinfo}'
                if selector != 'default':
                    cmd += f' -s {selector}'
                promote.append(cmd)
        elif os.path.exists(fullpath):
            status = 'in keyring'
        else:
            status = 'unknown'
            try:
                if b4.get_gpg_uids(keyinfo):
                    status = 'in default gpg keyring'
            except KeyError:
                pass
            pgp = True

        logger.info('%s: (%s)', identity, status)
        logger.info('    keytype: %s', algo)
        if algo == 'openpgp':
            logger.info('      keyid: %s', keyinfo[-16:])
            logger.info('        fpr: %s', ':'.join(re.findall(r'.{4}', keyinfo)))
        else:
            logger.info('     pubkey: %s', keyinfo)
        logger.info('   selector: %s', selector)
        logger.info('   fullpath: %s', fullpath)
    logger.info('---')
    if promote:
        logger.info('After checking with the developer, add ed25519 keys with:')
        for cmd in promote:
            logger.info('    %s', cmd)
    if pgp:
        logger.info('For openpgp keys, get the key from the developer, then:')
        logger.info('    gpg --import [keyfile]')
        logger.info('    gpg -a --export [keyid] > [fullpath]')
    sys.exit(0)


def main(cmdargs: argparse.Namespace) -> None:
    subcmd = getattr(cmdargs, 'kr_subcmd', None)
    if subcmd is None:
        logger.critical('Please specify a kr sub-command (e.g.: b4 kr list)')
        sys.exit(1)
    if subcmd == 'show-keys':
        cmd_show_keys(cmdargs)
    elif subcmd == 'list':
        cmd_list(cmdargs)
    elif subcmd == 'show':
        cmd_show(cmdargs)
    elif subcmd == 'accept':
        cmd_accept(cmdargs)
    elif subcmd == 'reject':
        cmd_reject(cmdargs)
    elif subcmd == 'forget':
        cmd_forget(cmdargs)
    elif subcmd == 'promote':
        cmd_promote(cmdargs)
