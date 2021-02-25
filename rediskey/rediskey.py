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
from collections import defaultdict
from typing import DefaultDict

import click
import redis
from click_plugins import with_plugins
from enumerate_input import enumerate_input
from pkg_resources import iter_entry_points
from retry_on_exception import retry_on_exception

from rediskey import RedisKey
from rediskey import RedisKeyTypeNotFoundError

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


def get_length_of_key(r, key):
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


def get_key_memory_used(r, *, key):
    bytes_used = r.memory_usage(key)
    k_bytes_used = '{}kB'.format(round(bytes_used / 1024, 2))
    M_bytes_used = '{}MB'.format(round(bytes_used / 1024 / 1024, 2))
    return bytes_used, k_bytes_used, M_bytes_used


def keys_and_sizes(r):
    keys = r.keys()
    for key in keys:
        key_type = r.type(key)
        length = get_length_of_key(r=r, key=key)
        result = key.decode('utf8'), key_type.decode('utf8'), length, *get_key_memory_used(r, key=key)
        yield result


def namespaces_and_sizes(r):
    namespaces = set()
    namespace_count: DefaultDict[str, int] = defaultdict(int)
    namespace_size: DefaultDict[str, int] = defaultdict(int)
    namespace_values: DefaultDict[str, int] = defaultdict(int)
    namespace_types: DefaultDict[str, set] = defaultdict(set)
    broken_namespaces = set()
    for result in keys_and_sizes(r):
        key, key_type, length, key_memory_used = result[:]
        if '#' in key:
            namespace = key.split('#')[0]
            namespaces.add(namespace)
            namespace_count[namespace] += 1
            #try:
            namespace_size[namespace] += key_memory_used
            #except TypeError:
            #    pass
            namespace_values[namespace] += length
            namespace_types[namespace].add(key_type)
        else:
            broken_namespaces.add(key)

    ns_list = list(namespaces)
    ns_list.sort()
    for namespace in ns_list:
        type_list = [t for t in namespace_types[namespace]]
        print(namespace,
              namespace_count[namespace],
              namespace_values[namespace],
              str(int(namespace_size[namespace] / 1024 / 1024)) + 'MB',
              type_list)

    if broken_namespaces:
        print("\n\nlen(broken_namesapces):", len(broken_namespaces), file=sys.stderr)
        for ns in broken_namespaces:
            print(ns, file=sys.stderr)


@click.option('--verbose', is_flag=True)
@click.option('--debug', is_flag=True)
@click.option("--printn", is_flag=True)
@click.option("--progress", is_flag=True)
@with_plugins(iter_entry_points('click_command_tree'))
@click.group()
@click.pass_context
def cli(ctx,
        verbose,
        debug,
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

    if verbose:
        ic(ctx.obj)


@cli.command()
@click.pass_context
def list_keys(ctx):
    r = redis.Redis(host='127.0.0.1')

    iterator = keys_and_sizes(r=r)

    for index, value in enumerate_input(iterator=iterator,
                                        null=ctx.obj['null'],
                                        progress=ctx.obj['progress'],
                                        skip=False,
                                        head=False,
                                        tail=False,
                                        debug=ctx.obj['debug'],
                                        verbose=ctx.obj['verbose'],):

        if ctx.obj['verbose']:
            ic(index, value)

        print(value, end=ctx.obj['end'])


@cli.command()
@click.pass_context
def list_namespaces(ctx):
    r = redis.Redis(host='127.0.0.1')

    namespaces_and_sizes(r=r)

    #for index, value in enumerate_input(iterator=iterator,
    #                                    null=ctx.obj['null'],
    #                                    progress=ctx.obj['progress'],
    #                                    skip=False,
    #                                    head=False,
    #                                    tail=False,
    #                                    debug=ctx.obj['debug'],
    #                                    verbose=ctx.obj['verbose'],):

    #    if ctx.obj['verbose']:
    #        ic(index, value)

    #    print(value, end=ctx.obj['end'])


@cli.command()
@click.argument("key", type=str, nargs=1)
#@click.argument("values", type=str, nargs=-1)
@click.option('--count', is_flag=True)
@click.option('--skip', default=None)
@click.option('--head', default=None)
@click.option('--tail', default=None)
@click.option('--verbose', is_flag=True)
@click.option('--debug', is_flag=True)
@click.pass_context
def list_key(ctx, *,
             key,
             count,
             skip,
             head,
             tail,
             verbose,
             debug,):

    ctx.obj['count'] = count
    ctx.obj['skip'] = skip
    ctx.obj['head'] = head
    ctx.obj['tail'] = tail
    ctx.obj['verbose'] = verbose
    ctx.obj['debug'] = debug

    if ctx.obj['verbose']:
        ic(ctx.obj, skip, head, tail)

    iterator = RedisKey(key=key,
                        algorithm="sha3_256",
                        hash_values=False,
                        key_type=None,
                        verbose=ctx.obj['verbose'],
                        debug=ctx.obj['debug'],
                        hash_length=None,)
    index = 0
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


@cli.command()
@click.argument("keys", type=str, nargs=-1)
@click.option('--verbose', is_flag=True)
@click.option('--debug', is_flag=True)
@click.pass_context
def delete_key(ctx, *,
               keys,
               verbose,
               debug,):

    ctx.obj['verbose'] = verbose
    ctx.obj['debug'] = debug

    if ctx.obj['verbose']:
        ic(ctx.obj, keys)

    iterator = keys

    index = 0
    for index, key in enumerate_input(iterator=iterator,
                                      null=ctx.obj['null'],
                                      progress=ctx.obj['progress'],
                                      skip=None,
                                      head=None,
                                      tail=None,
                                      debug=ctx.obj['debug'],
                                      verbose=ctx.obj['verbose'],):

        if ctx.obj['verbose']:
            ic(index, key)

        redis_instance = RedisKey(key=key,
                                  algorithm="sha3_256",
                                  hash_values=False,
                                  key_type=None,
                                  verbose=ctx.obj['verbose'],
                                  debug=ctx.obj['debug'],
                                  hash_length=None,)

        result = redis_instance.delete()

        print(key, result, end=ctx.obj['end'])
