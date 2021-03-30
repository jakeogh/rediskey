"""Module for common redis access"""

# pylint: disable=C0111     # docstrings are always outdated and wrong
# pylint: disable=W0511     # todo
# pylint: disable=R0902     # too many instance attributes
# pylint: disable=C0302     # too many lines in module
# pylint: disable=C0103     # single letter var names
# pylint: disable=R0911     # too many return statements
# pylint: disable=R0912     # too many branches
# pylint: disable=R0915     # too many statements
# pylint: disable=R0913     # too many arguments
# pylint: disable=R1702     # too many nested blocks
# pylint: disable=R0914     # too many local variables
# pylint: disable=R0903     # too few public methods
# pylint: disable=E1101     # no uhashfs member for base
# pylint: disable=W0201     # attribute defined outside __init__

import binascii
import hashlib
import time

import redis
from icecream import ic
from redis.exceptions import ConnectionError
from redis.exceptions import ResponseError
from retry_on_exception import retry_on_exception
from uniquepipe import generate_truncated_string_hash


class RedisKeyTypeNotFoundError(ValueError):
    pass


class RedisKey():
    @retry_on_exception(exception=ConnectionError,)
    @retry_on_exception(exception=ResponseError,
                        in_e_args="MISCONF Redis is configured to save RDB snapshots, but it is currently not able to persist on disk.",)
    @retry_on_exception(exception=ResponseError,
                        in_e_args="OOM command not allowed when used memory > 'maxmemory'",)
    def __init__(self, *,
                 key: str,
                 key_type: str = None,
                 hash_values: bool = False,
                 algorithm: str = None,
                 hash_length: int = None,
                 verbose: bool,
                 debug: bool,
                 ):
        self.verbose = verbose
        self.debug = debug
        self.r = redis.StrictRedis(host='127.0.0.1')
        self.key = key
        self.type = self.r.type(self.key).decode('utf8')
        #ic(self.type)
        #ic(key_type)
        if self.type == 'none':
            if self.verbose:
                ic('uncreated new key:', key, key_type)
            if key_type is None:
                raise ValueError('key:', key, 'does not exist', 'key_type must be specified to create a new key')
            self.type = key_type
        else:
            if key_type is not None:
                if key_type != self.type:
                    raise ValueError(self.type, 'does not match', key_type)

        self.algorithm = algorithm
        self.hash_values = hash_values
        if self.hash_values:
            if not self.algorithm:
                raise ValueError('hash_values is True, an algorithm must be specified')
        #if self.algorithm:
        #    if not self.hash_values:
        #        raise ValueError('algorithm is {}, but hash_values is not set'.format(self.algorithm))

        self.add_disabled = False
        self.hash_length = hash_length
        if self.hash_length is None:
            if self.hash_values:
                self.add_disabled = True

        if not self.add_disabled:
            if not key.endswith('#'):
                raise ValueError('adding to a key is only possible if the key ends with #')
            if ':' not in key:
                raise ValueError('adding to a key is only possible if the key contains :')

        #if self.algorithm:
        #    self.digestlen = hashlib.new(self.algorithm).digest_size
        #    self.hexdigestlen = self.digestlen * 2
        #    self.emptydigest = getattr(hashlib, self.algorithm)(b'').digest()
        #    self.emptyhexdigest = self.emptydigest.hex()
        #    assert len(self.emptydigest) == self.digestlen
        #    assert len(self.emptyhexdigest) == self.hexdigestlen

    @retry_on_exception(exception=ConnectionError,)
    def __iter__(self):
        cursor = None
        if self.type in ['set', 'hash']:
            if self.type == 'set':
                func = 'sscan'
            elif self.type == 'hash':
                func = 'hscan'
            else:
                raise ValueError(self.type)
            function = getattr(self.r, func)
            cursor, values = function(self.key)
            if self.debug:
                ic(cursor, type(values), len(values))
            for v in values:
                yield v
            while cursor != 0:
                cursor, values = function(self.key, cursor)
                if self.debug:
                    ic(cursor, type(values), len(values))
                for v in values:
                    yield v
        elif self.type == 'list':
            for v in self.r.lrange(self.key, 0, -1):
                yield v
        elif self.type == 'zset':
            for v in self.r.zrange(self.key, 0, -1, desc=True):
                yield v
        else:
            raise RedisKeyTypeNotFoundError(self.type)

    @retry_on_exception(exception=ConnectionError,)
    def __contains__(self, value: str):
        if self.hash_values:
            value = generate_truncated_string_hash(string=value,
                                                   algorithm=self.algorithm,
                                                   length=self.hash_length,
                                                   verbose=self.verbose,
                                                   debug=self.debug,)
            #value = binascii.unhexlify(value)

        if self.type == 'zset':
            return bool(self.r.zscore(self.key, value))
        if self.type == 'set':
            return bool(self.r.sismember(self.key, value))
        if self.type == 'hash':
            return bool(self.r.hget(self.key, value))
        if self.type == 'list':
            for v in self.r.lrange(self.key, 0, -1):
                if value == v:
                    return True
            return False
        raise RedisKeyTypeNotFoundError(self.type)

    @retry_on_exception(exception=ConnectionError,)
    def __len__(self):
        if self.type == 'zset':
            return self.r.zcard(self.key)
        if self.type == 'set':
            return self.r.scard(self.key)
        if self.type == 'list':
            return self.r.llen(self.key)
        if self.type == 'hash':
            return self.r.hlen(self.key)
        raise RedisKeyTypeNotFoundError(self.type)

    @retry_on_exception(exception=ConnectionError,)
    @retry_on_exception(exception=ResponseError,
                        in_e_args="MISCONF Redis is configured to save RDB snapshots, but it is currently not able to persist on disk.",)
    @retry_on_exception(exception=ResponseError,
                        in_e_args="OOM command not allowed when used memory > 'maxmemory'",)
    def add(self, *value: str, index=None, verbose=False):
        #ic(value)
        if self.add_disabled:
            raise ValueError('hash_length was not specified and hash_values is True, so adding to the key is disabled')
        if self.hash_values:
            value = generate_truncated_string_hash(string=value,
                                                   algorithm=self.algorithm,
                                                   length=self.hash_length,
                                                   verbose=self.verbose,
                                                   debug=self.debug,)
            #value = binascii.unhexlify(value)
        if self.type == 'zset':
            if index:
                mapping = {value[0]: index}
            else:
                mapping = {value[0]: time.time()}

            if verbose:
                ic(self.key, mapping)
            result = self.r.zadd(self.key, mapping)
            return result
        if self.type == 'set':
            #ic(self.key, *value)
            result = self.r.sadd(self.key, *value)
            return result
        if self.type == 'list':
            #ic(self.key, *value)
            result = self.r.rpush(self.key, *value)
            return result
        #if self.type == 'hash':
        #    return result
        raise RedisKeyTypeNotFoundError(self.type)

    @retry_on_exception(exception=ConnectionError,)
    def first(self):
        #ic(value)
        if self.type == 'zset':
            result = self.r.zrange(self.key, 0, 0)
            return result
        if self.type == 'set':
            raise ValueError('key {} is of type `set`, therefore it has no first member')
        if self.type == 'list':
            #ic(self.key, *value)
            result = self.r.lindex(self.key, 0)
            return result
        #if self.type == 'hash':
        #    return result
        raise RedisKeyTypeNotFoundError(self.type)

    @retry_on_exception(exception=ConnectionError,)
    def last(self):
        #ic(value)
        if self.type == 'zset':
            result = self.r.zrange(self.key, -1, -1)
            return result
        if self.type == 'set':
            raise ValueError('key {} is of type `set`, therefore it has no last member')
        if self.type == 'list':
            #ic(self.key, *value)
            result = self.r.lindex(self.key, -1)
            return result
        #if self.type == 'hash':
        #    return result
        raise RedisKeyTypeNotFoundError(self.type)

    @retry_on_exception(exception=ConnectionError,)
    def exists(self):
        return self.r.exists(self.key)

    @retry_on_exception(exception=ConnectionError,)
    @retry_on_exception(exception=ResponseError,
                        in_e_args="MISCONF Redis is configured to save RDB snapshots, but it is currently not able to persist on disk.",)
    @retry_on_exception(exception=ResponseError,
                        in_e_args="OOM command not allowed when used memory > 'maxmemory'",)
    def delete(self):
        return self.r.delete(self.key)
