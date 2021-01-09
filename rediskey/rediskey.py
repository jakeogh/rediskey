#!/usr/bin/env python3

# pylint: disable=C0111  # docstrings are always outdated and wrong
# pylint: disable=W0511  # todo is encouraged
# pylint: disable=C0301  # line too long
# pylint: disable=R0902  # too many instance attributes
# pylint: disable=C0302  # too many lines in module
# pylint: disable=C0103  # single letter var names, func name too descriptive
# pylint: disable=R0911  # too many return statements
# pylint: disable=R0912  # too many branches
# pylint: disable=R0915  # too many statements
# pylint: disable=R0913  # too many arguments
# pylint: disable=R1702  # too many nested blocks
# pylint: disable=R0914  # too many local variables
# pylint: disable=R0903  # too few public methods
# pylint: disable=E1101  # no member for base
# pylint: disable=W0201  # attribute defined outside __init__
# pylint: disable=R0916  # Too many boolean expressions in if statement


#import os
import sys

import click
import redis
from click_plugins import with_plugins
from enumerate_input import enumerate_input
from pkg_resources import iter_entry_points
from retry_on_exception import retry_on_exception

from rediskey import RedisKey, RedisKeyTypeNotFoundError

#from collections import defaultdict
#from prettyprinter import cpprint, install_extras
#install_extras(['attrs'])
#from getdents import files
# import pdb; pdb.set_trace()
# from pudb import set_trace; set_trace(paused=False)




def eprint(*args, **kwargs):
    if 'file' in kwargs.keys():
        kwargs.pop('file')
    print(*args, file=sys.stderr, **kwargs)


try:
    from icecream import ic  # https://github.com/gruns/icecream
except ImportError:
    ic = eprint


def get_size_of_key(r, key):
    key_type = r.type(key)
    if key_type == b'zset':
        return r.zcard(key)
    if key_type == b'set':
        return r.scard(key)
    if key_type == b'list':
        return r.llen(key)
    if key_type == b'hash':
        return r.hlen(key)
    raise RedisKeyTypeNotFoundError(key_type)


def list_keys_and_sizes(r):
    keys = r.keys()
    for key in keys:
        key_type = r.type(key)
        length = get_size_of_key(r=r, key=key)
        result = key.decode('utf8'), key_type.decode('utf8'), length
        yield result


#@click.command()
@click.option('--verbose', is_flag=True)
@click.option('--debug', is_flag=True)
@click.option('--count', is_flag=True)
@click.option('--skip', type=int, default=False)
@click.option('--head', type=int, default=False)
@click.option('--tail', type=int, default=False)
@click.option("--printn", is_flag=True)
@click.option("--progress", is_flag=True)
@with_plugins(iter_entry_points('click_command_tree'))
@click.group()
@click.pass_context
def cli(ctx,
        verbose,
        debug,
        count,
        skip,
        head,
        tail,
        progress,
        printn,):

    null = not printn
    end = '\n'
    if null:
        end = '\x00'
    if sys.stdout.isatty():
        end = '\n'

    #progress = False
    if (verbose or debug):
        progress = False

    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['debug'] = debug
    ctx.obj['end'] = end
    ctx.obj['null'] = null
    ctx.obj['progress'] = progress
    ctx.obj['count'] = count
    ctx.obj['skip'] = skip
    ctx.obj['head'] = head
    ctx.obj['tail'] = tail

    #redis_instance = redis.StrictRedis(host='127.0.0.1')



@cli.command()
@click.pass_context
def list_keys(ctx):
    r = redis.Redis(host='127.0.0.1')

    iterator = list_keys_and_sizes(r=r)

    for index, value in enumerate_input(iterator=iterator,
                                        null=ctx.obj['null'],
                                        progress=ctx.obj['progress'],
                                        skip=ctx.obj['skip'],
                                        head=ctx.obj['head'],
                                        tail=ctx.obj['tail'],
                                        debug=ctx.obj['debug'],
                                        verbose=ctx.obj['verbose'],):

        if ctx.obj['verbose']:
            ic(index, value)

        print(value, end=ctx.obj['end'])


@cli.command()
@click.argument("key", type=str, nargs=1)
#@click.argument("values", type=str, nargs=-1)
@click.pass_context
def list_key(ctx, key):
    r = redis.Redis(host='127.0.0.1')

    iterator = RedisKey(key=key, hash_type="sha3_256")

    for index, value in enumerate_input(iterator=iterator,
                                        null=ctx.obj['null'],
                                        progress=ctx.obj['progress'],
                                        skip=ctx.obj['skip'],
                                        head=ctx.obj['head'],
                                        tail=ctx.obj['tail'],
                                        debug=ctx.obj['debug'],
                                        verbose=ctx.obj['verbose'],):

        if ctx.obj['verbose']:
            ic(index, value)

        if not ctx.obj['count']:
            print(value, end=ctx.obj['end'])

    if ctx.obj['count']:
        print(index + 1, end=ctx.obj['end'])
