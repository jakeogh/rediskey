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
from uniquepipe import generate_truncated_string_hash


class RedisKeyTypeNotFoundError(ValueError):
    pass


class RedisKey():
    def __init__(self, *,
                 key,
                 key_type,
                 algorithm: str,
                 verbose: bool,
                 debug: bool,
                 hash_length: int,):
        self.verbose = verbose
        self.debug = debug
        self.r = redis.StrictRedis(host='127.0.0.1')
        self.key = key
        self.type = self.r.type(self.key).decode('utf8')
        ic(self.type)
        ic(key_type)
        if self.type == 'none':
            ic('new key:', key, key_type)
            if key_type is None:
                raise ValueError('key:', key, 'does not exist', 'key_type must be specified to create a new key')
            self.type = key_type
        else:
            if key_type is not None:
                if key_type != self.type:
                    raise ValueError(self.type, 'does not match', key_type)

        self.add_disabled = False
        self.hash_length = hash_length
        if self.hash_length is None:
            self.add_disabled = True

        if not self.add_disabled:
            if not key.endswith('#'):
                raise ValueError('adding to a key is only possible if the key ends with #')
            if not ':' in key:
                raise ValueError('adding to a key is only possible if the key contains :')

        self.algorithm = algorithm
        #if self.algorithm:
        #    self.digestlen = hashlib.new(self.algorithm).digest_size
        #    self.hexdigestlen = self.digestlen * 2
        #    self.emptydigest = getattr(hashlib, self.algorithm)(b'').digest()
        #    self.emptyhexdigest = self.emptydigest.hex()
        #    assert len(self.emptydigest) == self.digestlen
        #    assert len(self.emptyhexdigest) == self.hexdigestlen

    #def __iter__(self):
    #    return self

    def __iter__(self):
        cursor = None
        if self.type == 'zset':
            while cursor != 0:
                cursor, values = self.r.zscan(self.key)
                for v in values:
                    yield v
        elif self.type == 'set':
            cursor, values = self.r.sscan(self.key)
            if self.debug:
                ic(cursor, type(values), len(values))
            for v in values:
                yield v
            while cursor != 0:
                cursor, values = self.r.sscan(self.key, cursor)
                if self.debug:
                    ic(cursor, type(values), len(values))
                for v in values:
                    yield v
        elif self.type == 'hash':
            while cursor != 0:
                cursor, values = self.r.hscan(self.key)
                for v in values:
                    yield v
        elif self.type == 'list':
            for v in self.r.lrange(self.key, 0, -1):
                yield v
        else:
            raise RedisKeyTypeNotFoundError(self.type)

    def __contains__(self, value: str):
        value_hash = generate_truncated_string_hash(string=value,
                                                    algorithm=self.algorithm,
                                                    length=self.hash_length,
                                                    verbose=self.verbose,
                                                    debug=self.debug,)
        #if not isinstance(value, RedisKey):
        #    if not isinstance(value, bytes):
        #        value = binascii.unhexlify(value)
        #else:
        #    for v in value:  # todo use set op
        #        if isinstance(v, tuple):
        #            v = v[0]
        #        #import IPython
        #        #IPython.embed()
        #        if not self.__contains__(v):
        #            return False
        #    return True

        if self.type == 'zset':
            return bool(self.r.zscore(self.key, value_hash))
        if self.type == 'set':
            return bool(self.r.sismember(self.key, value_hash))
        if self.type == 'hash':
            return bool(self.r.hget(self.key, value_hash))
        if self.type == 'list':
            for v in self.r.lrange(self.key, 0, -1):
                if value_hash == v:
                    return True
            return False
        raise RedisKeyTypeNotFoundError(self.type)

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

    def __add__(self, value: str, *,
                index=None):
        if self.add_disabled:
            raise ValueError('hash_length was not specified, so adding to the key is disabled')
        value_hash = generate_truncated_string_hash(string=value,
                                                    algorithm=self.algorithm,
                                                    length=self.hash_length,
                                                    verbose=self.verbose,
                                                    debug=self.debug,)
        #if not isinstance(value, RedisKey):
        #    if not isinstance(value, bytes):
        #        value = binascii.unhexlify(value)
        #else:
        #    for v in value:  # todo use set op
        #        ic(v)
        #        #import IPython
        #        #IPython.embed()

        #        self.__add__(value=v[0], index=v[1])
        #    return self
        #if self.digestlen:
        #    if len(value) != self.digestlen:
        #        err = "value `{0}` is {1} bytes, not {2} bytes as required by {3}".format(value, len(value), self.digestlen, self.algorithm)
        #        raise TypeError(err)
        if self.type == 'zset':
            if index:
                self.r.zadd(self.key, {value_hash: index})
            else:
                self.r.zadd(self.key, {value_hash: time.time()})
            return self
        if self.type == 'set':
            self.r.sadd(self.key, value_hash)
            return self
        if self.type == 'list':
            self.r.rpush(self.key, value_hash)
            return self
        #if self.type == 'hash':
        #    return self
        raise RedisKeyTypeNotFoundError(self.type)
