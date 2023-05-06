# Copyright (c) 2023, Neil Booth
#
# All rights reserved.
#

import attr
import logging
import re
import time
from enum import IntEnum, IntFlag
from functools import partial
from ipaddress import ip_address, IPv4Address, IPv6Address
from struct import Struct, error as struct_error

from .errors import ConnectionClosedError, ProtocolError
from .hashes import double_sha256
from .packing import (
    pack_byte, pack_le_int32, pack_le_uint32, pack_le_int64, pack_le_uint64, pack_varint,
    pack_varbytes, pack_port, unpack_port,
    read_varbytes, read_varint, read_le_int32, read_le_uint32, read_le_uint64, read_le_int64,
)


# Standard and extended message hedaers
std_header_struct = Struct('<4s12sI4s')
ext_header_struct = Struct('<4s12sI4s12sQ')
ext_extra_struct = Struct('<12sQ')

# This is the maximum payload length a non-streaming command can accept.  Such
# payloads are buffered and processed as a unit by the handler.
ATOMIC_PAYLOAD_SIZE = 2_000_000
PROTOCOL_VERSION = 70015


class ServiceFlags(IntFlag):
    NODE_NONE = 0
    NODE_NETWORK = 1 << 0
    NODE_GETUTXO = 1 << 1
    NODE_BLOOM = 1 << 2


class InventoryKind(IntEnum):
    ERROR = 0
    TX = 1
    BLOCK = 2
    # The following occur only in getdata messages.  Invs always use TX or BLOCK.
    FILTERED_BLOCK = 3
    COMPACT_BLOCK = 4


class ServicePart(IntEnum):
    PROTOCOL = 0
    HOST = 1
    PORT = 2


async def read_exact(read, size):
    '''Asynchronously read exactly size bytes using read().
    Raises: ConnectionClosedError.'''
    # Optimize normal case
    part = await read(size)
    if len(part) == size:
        return part
    parts = []
    while part:
        parts.append(part)
        size -= len(part)
        if not size:
            return b''.join(parts)
        part = await read(size)
    raise ConnectionClosedError(f'connection closed with {size:,d} bytes left')


@attr.s(slots=True)
class MessageHeader:
    '''The header of a network protocol message.'''

    # Extended headers were introduced in the BSV 1.0.10 node software.

    COMMAND_LEN = 12
    STD_HEADER_SIZE = std_header_struct.size
    EXT_HEADER_SIZE = ext_header_struct.size

    magic = attr.ib()
    command_bytes = attr.ib()
    payload_len = attr.ib()
    checksum = attr.ib()
    is_extended = attr.ib()

    @classmethod
    async def from_stream(cls, read):
        raw_std = await read_exact(read, cls.STD_HEADER_SIZE)
        magic, command, payload_len, checksum = std_header_struct.unpack(raw_std)
        is_extended = False
        if command == cls.EXTMSG:
            raw_ext = await read_exact(read, cls.EXT_HEADER_SIZE - cls.STD_HEADER_SIZE)
            command, payload_len = ext_extra_struct.unpack(raw_ext)
            is_extended = True
        return cls(magic, command, payload_len, checksum, is_extended)

    def __str__(self):
        '''The message command as text (or a hex representation if not ASCII).'''
        command = self.command_bytes.rstrip(b'\0')
        return command.decode() if command.isascii() else '0x' + command.hex()

    @classmethod
    def std_bytes(cls, magic, command, payload):
        return std_header_struct.pack(
            magic, command, len(payload), double_sha256(payload)[:4]
        )

    @classmethod
    def ext_bytes(cls, magic, command, payload_len):
        return ext_header_struct.pack(
            magic, cls.EXTMSG, 0xffffffff, bytes(4), command, payload_len
        )



def _command(text):
    return text.encode().ljust(MessageHeader.COMMAND_LEN, b'\0')


# List these explicitly because pylint is dumb
MessageHeader.ADDR = _command('addr')
MessageHeader.BLOCK = _command('block')
MessageHeader.BLOCKTXN = _command('blocktxn')
MessageHeader.CMPCTBLOCK = _command('cmpctblock')
MessageHeader.CREATESTRM = _command('createstrm')
MessageHeader.EXTMSG = _command('extmsg')
MessageHeader.FEEFILTER = _command('feefilter')
MessageHeader.FILTERADD = _command('filteradd')
MessageHeader.FILTERCLEAR = _command('filterclear')
MessageHeader.FILTERLOAD = _command('filterload')
MessageHeader.GETADDR = _command('getaddr')
MessageHeader.GETBLOCKS = _command('getblocks')
MessageHeader.GETBLOCKTXN = _command('getblocktxn')
MessageHeader.GETDATA = _command('getdata')
MessageHeader.GETHEADERS = _command('getheaders')
MessageHeader.HEADERS = _command('headers')
MessageHeader.INV = _command('inv')
MessageHeader.MEMPOOL = _command('mempool')
MessageHeader.MERKELBLOCK = _command('merkleblock')
MessageHeader.NOTFOUND = _command('notfound')
MessageHeader.PING = _command('ping')
MessageHeader.PONG = _command('pong')
MessageHeader.PROTOCONF = _command('protoconf')
MessageHeader.REJECT = _command('reject')
MessageHeader.REPLY = _command('reply')
MessageHeader.SENDCMPCT = _command('sendcmpct')
MessageHeader.SENDHEADERS = _command('sendheaders')
MessageHeader.STREAMACK = _command('streamack')
MessageHeader.TX = _command('tx')
MessageHeader.VERACK = _command('verack')
MessageHeader.VERSION = _command('version')


# See http://stackoverflow.com/questions/2532053/validate-a-hostname-string
# Note underscores are valid in domain names, but strictly invalid in host
# names.  We ignore that distinction.
PROTOCOL_REGEX = re.compile('[A-Za-z][A-Za-z0-9+-.]+$')
LABEL_REGEX = re.compile('^[a-z0-9_]([a-z0-9-_]{0,61}[a-z0-9_])?$', re.IGNORECASE)
NUMERIC_REGEX = re.compile('[0-9]+$')


def is_valid_hostname(hostname):
    '''Return True if hostname is valid, otherwise False.'''
    if not isinstance(hostname, str):
        raise TypeError('hostname must be a string')
    # strip exactly one dot from the right, if present
    if hostname and hostname[-1] == ".":
        hostname = hostname[:-1]
    if not hostname or len(hostname) > 253:
        return False
    labels = hostname.split('.')
    # the TLD must be not all-numeric
    if re.match(NUMERIC_REGEX, labels[-1]):
        return False
    return all(LABEL_REGEX.match(label) for label in labels)


def classify_host(host):
    '''Host is an IPv4Address, IPv6Address or a string.

    If an IPv4Address or IPv6Address return it.  Otherwise convert the string to an
    IPv4Address or IPv6Address object if possible and return it.  Otherwise return the
    original string if it is a valid hostname.

    Raise ValueError if a string cannot be interpreted as an IP address and it is not
    a valid hostname.
    '''
    if isinstance(host, (IPv4Address, IPv6Address)):
        return host
    if is_valid_hostname(host):
        return host
    return ip_address(host)


def validate_port(port):
    '''Validate port and return it as an integer.

    A string, or its representation as an integer, is accepted.'''
    if not isinstance(port, (str, int)):
        raise TypeError(f'port must be an integer or string: {port}')
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    if isinstance(port, int) and 0 < port <= 65535:
        return port
    raise ValueError(f'invalid port: {port}')


def validate_protocol(protocol):
    '''Validate a protocol, a string, and return it.'''
    if not re.match(PROTOCOL_REGEX, protocol):
        raise ValueError(f'invalid protocol: {protocol}')
    return protocol.lower()


def _split_address(string):
    if string.startswith('['):
        end = string.find(']')
        if end != -1:
            if len(string) == end + 1:
                return string[1:end], ''
            if string[end + 1] == ':':
                return string[1:end], string[end+2:]
    colon = string.find(':')
    if colon == -1:
        return string, ''
    return string[:colon], string[colon + 1:]


class NetAddress:

    def __init__(self, host, port, check_port=True):
        '''Construct a NetAddress from a host and a port.

        Host is classified and port is an integer.'''
        self._host = classify_host(host)
        self._port = validate_port(port) if check_port else int(port)

    def __eq__(self, other):
        # pylint: disable=protected-access
        return (isinstance(other, NetAddress) and
                self._host == other._host and self._port == other._port)

    def __hash__(self):
        return hash((self._host, self._port))

    @classmethod
    def from_string(cls, string, *, check_port=True, default_func=None):
        '''Construct a NetAddress from a string and return a (host, port) pair.

        If either (or both) is missing and default_func is provided, it is called with
        ServicePart.HOST or ServicePart.PORT to get a default.
        '''
        if not isinstance(string, str):
            raise TypeError(f'address must be a string: {string}')
        host, port = _split_address(string)
        if default_func:
            host = host or default_func(ServicePart.HOST)
            port = port or default_func(ServicePart.PORT)
            if not host or not port:
                raise ValueError(f'invalid address string: {string}')
        return cls(host, port, check_port=check_port)

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    def __str__(self):
        if isinstance(self._host, IPv6Address):
            return f'[{self._host}]:{self._port}'
        return f'{self.host}:{self.port}'

    def __repr__(self):
        return f'NetAddress({self.host!r}, {self.port})'

    @classmethod
    def default_host_and_port(cls, host, port):
        def func(kind):
            return host if kind == ServicePart.HOST else port
        return func

    @classmethod
    def default_host(cls, host):
        return cls.default_host_and_port(host, None)

    @classmethod
    def default_port(cls, port):
        return cls.default_host_and_port(None, port)

    def pack_host(self):
        '''Return the host as a 16-byte IPv6 address.'''
        if isinstance(self._host, IPv4Address):
            # An IPv4-mapped IPv6 address
            return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + self._host.packed
        if isinstance(self._host, IPv6Address):
            return self._host.packed
        raise TypeError(f'address must be resolved: {self._host}')

    def pack(self):
        return self.pack_host() + pack_port(self._port)


class Service:
    '''A validated protocol, address pair.'''

    def __init__(self, protocol, address):
        '''Construct a service from a protocol string and a NetAddress object,'''
        self._protocol = validate_protocol(protocol)
        if not isinstance(address, NetAddress):
            address = NetAddress.from_string(address)
        self._address = address

    def __eq__(self, other):
        # pylint: disable=protected-access
        return (isinstance(other, Service) and
                self._protocol == other._protocol and self._address == other._address)

    def __hash__(self):
        return hash((self._protocol, self._address))

    @property
    def protocol(self):
        return self._protocol

    @property
    def address(self):
        return self._address

    @property
    def host(self):
        return self._address.host

    @property
    def port(self):
        return self._address.port

    @classmethod
    def from_string(cls, string, *, default_func=None):
        '''Construct a Service from a string.

        If default_func is provided and any ServicePart is missing, it is called with
        default_func(protocol, part) to obtain the missing part.
        '''
        if not isinstance(string, str):
            raise TypeError(f'service must be a string: {string}')

        parts = string.split('://', 1)
        if len(parts) == 2:
            protocol, address = parts
        else:
            item, = parts
            protocol = None
            if default_func:
                if default_func(item, ServicePart.HOST) and default_func(item, ServicePart.PORT):
                    protocol, address = item, ''
                else:
                    protocol, address = default_func(None, ServicePart.PROTOCOL), item
            if not protocol:
                raise ValueError(f'invalid service string: {string}')

        if default_func:
            default_func = partial(default_func, protocol.lower())
        address = NetAddress.from_string(address, default_func=default_func)
        return cls(protocol, address)

    def __str__(self):
        return f'{self._protocol}://{self._address}'

    def __repr__(self):
        return f"Service({self._protocol!r}, '{self._address}')"


class BitcoinService:
    '''Represents a bitcoin network service.

    Consists of an NetAddress (which must have an IPv4 or IPv6 resolved host) and a
    services mask.
    '''
    struct = Struct('<Q16s2s')

    def __init__(self, address, services):
        if not isinstance(address, NetAddress):
            address = NetAddress.from_string(address, check_port=False)
        self.address = address
        self.services = services

    def __eq__(self, other):
        return (isinstance(other, BitcoinService) and
                self.address == other.address and self.services == other.services)

    def __hash__(self):
        return hash((self.address, self.services))

    def pack(self):
        '''Return the service as an encoded internet address as used in the Bitcoin network
        protocol.  No timestamp is prefixed, as for the version message.
        '''
        return pack_le_uint64(self.services) + self.address.pack()

    def pack_with_timestamp(self, timestamp):
        '''Return the service as an encoded internet address as used in the Bitcoin network
        protocol, including a 4-byte timestamp prefix.
        '''
        return pack_le_uint32(timestamp) + self.pack()

    @classmethod
    def unpack(cls, raw):
        '''Given the final 26 bytes (no leading timestamp) of a protocol-encoded
        internet address return a BitcoinService object.'''
        services, address, raw_port = cls.struct.unpack(raw)
        address = ip_address(address)
        if address.ipv4_mapped:
            address = address.ipv4_mapped
        port, = unpack_port(raw_port)
        return cls(NetAddress(address, port, check_port=False), services)

    @classmethod
    def read(cls, read):
        '''Reads 26 bytes from a raw byte stream.'''
        return cls.unpack(read(cls.struct.size))

    @classmethod
    def read_with_timestamp(cls, read):
        '''Read a timestamp-prefixed net_addr (4 + 26 bytes); return a
        (BitcoinService, timestamp) pair.'''
        timestamp = read_le_uint32(read)
        return cls.read(read), timestamp

    @classmethod
    def read_addrs(cls, read):
        '''Return a lits of (service, timestamp) pairs from an addr message payload.'''
        count = read_varint(read)
        return [cls.read_with_timestamp(read) for _ in range(count)]

    def __str__(self):
        return f'{self.address} {ServiceFlags(self.services)!r}'

    def __repr__(self):
        return f'BitcoinService({self.address!r}, {ServiceFlags(self.services)!r})'


@attr.s(slots=True, repr=True)
class Protoconf:
    LEGACY_MAX_PAYLOAD = 1024 * 1024
    # Instance attributes
    max_payload = attr.ib()
    stream_policies = attr.ib()

    def max_inv_elements(self):
        return (self.max_payload - 9) // (4 + 32)

    def payload(self):
        field_count = 2
        return b''.join((
            pack_varint(field_count),
            pack_le_uint32(self.max_payload),
            pack_varbytes(b','.join(self.stream_policies)),
        ))

    @classmethod
    def read(cls, read, logger):
        field_count = read_varint(read)
        if field_count != 2:
            logger.warning('unexpected field count {field_count:,d} in protoconf message')

        max_payload = Protoconf.LEGACY_MAX_PAYLOAD
        if field_count > 0:
            max_payload = read_le_uint32(read)
            if max_payload < Protoconf.LEGACY_MAX_PAYLOAD:
                raise ProtocolError(f'invalid max payload {max_payload:,d} in protconf message')

        stream_policies = b'Default'
        if field_count > 1:
            stream_policies = read_varbytes(read)
        return Protoconf(max_payload, stream_policies.split(b','))


@attr.s(slots=True, repr=True)
class ServiceDetails:
    '''Stores the useful non-redundant information of a version message.'''
    # A BitcoinService object (the sender of a version message)
    service = attr.ib()
    # A string
    user_agent = attr.ib()
    version = attr.ib(default=PROTOCOL_VERSION)
    start_height = attr.ib(default=0)
    relay = attr.ib(default=False)
    # If None the current time is used in to_payload()
    timestamp = attr.ib(default=None)
    assoc_id = attr.ib(default=b'')
    protoconf = attr.ib(default=None)

    def version_payload(self, service, nonce):
        '''Service is a NetAddress or BitcoinService.'''
        if isinstance(service, NetAddress):
            service = BitcoinService(service, 0)
        assert isinstance(service, BitcoinService)
        assert isinstance(nonce, (bytes, bytearray)) and len(nonce) == 8

        timestamp = int(time.time()) if self.timestamp is None else self.timestamp
        return b''.join((
            pack_le_int32(self.version),
            pack_le_uint64(self.service.services),
            pack_le_int64(timestamp),
            service.pack(),
            self.service.pack(),
            nonce,
            pack_varbytes(self.user_agent.encode()),
            pack_le_int32(self.start_height),
            pack_byte(self.relay),
            # FIXME: uncomment this once we can handle the implications
            # pack_varbytes(self.assoc_id),
        ))

    @classmethod
    def read(cls, read, logger):
        '''Returns a (version_info, our_service, nonce) tuple.'''
        version = read_le_uint32(read)
        services = read_le_uint64(read)
        timestamp = read_le_int64(read)
        our_service = BitcoinService.read(read)
        their_service = BitcoinService.read(read)
        if their_service.services != services:
            logger.warning(f'{their_service.address}: service mismatch in version payload')
        nonce = read(8)
        user_agent = read_varbytes(read)
        start_height = read_le_int32(read)
        # Relay is optional, defaulting to True
        relay = read(1) != b'\0'
        # Association ID is optional.  We set it to None if not provided.
        try:
            assoc_id = read_varbytes(read)
        except struct_error:
            assoc_id = None

        try:
            user_agent = user_agent.decode()
        except UnicodeDecodeError:
            user_agent = '0x' + user_agent.hex()

        details = cls(their_service, user_agent, version, start_height, relay, timestamp, assoc_id)
        return details, our_service, nonce

    def read_protoconf(self, read, logger):
        if self.protoconf:
            raise ProtocolError('received second protoconf message')
        self.protoconf = Protoconf.read(read, logger)

    def __str__(self):
        return (
            f'{self.service} {self.user_agent!r} version={self.version} '
            f'start_height={self.start_height:,d} relay={self.relay} timestamp={self.timestamp} '
            f'assoc_id={self.assoc_id!r}'
        )


class Protocol:

    def __init__(self, network, is_outgoing, start_height, verbosity=0):
        # Verbosity: 0 (warnings), 1 (info), 2 (debug)
        self.network = network
        self.is_outgoing = is_outgoing

        # State
        self.our_service = ServiceDetails(
            service=BitcoinService('[::]:0', 0),
            user_agent='/test:1.0/',
            protoconf=Protoconf(ATOMIC_PAYLOAD_SIZE, [b'Default']),
            start_height=start_height,
        )
        self.their_service = None

        # Outgoing messages
        self.outgoing_messages = Queue()

        self.logger = logging.getLogger('Protocol')
        self.verbosity = verbosity

    # def log_service_details(self, serv, headline):
    #     self.logger.info(headline)
    #     self.logger.info(f'    user_agent={serv.user_agent} '
    #                      f'services={ServiceFlags(serv.service.services)!r}')
    #     self.logger.info(f'    protocol={serv.version} height={serv.start_height:,d}  '
    #                      f'relay={serv.relay} timestamp={serv.timestamp} assoc_id={serv.assoc_id}')

    #
    # Message streaming
    #

    async def send_message(self, command, payload):
        '''Send a command and its payload.  Since the message header requires a length and a
        checksum, we cannot stream messages; the entire payload must be known in
        advance.
        '''
        header = MessageHeader.std_bytes(self.network.magic, command, payload)
        await self.outgoing_messages.put((header, payload))

    async def send_streaming_message(self, command, payload_len, parts_func):
        header = MessageHeader.ext_bytes(self.network.magic, command, payload_len)
        await self.outgoing_messages.put((header, (payload_len, parts_func)))

    async def bytes_to_send(self):
        '''An asynchronous generator of bytes to send over the network.'''
        while True:
            header, payload = await self.outgoing_messages.get()
            yield header
            # Streaming payload?
            if isinstance(payload, tuple):
                payload_len, get_payload = payload
                while payload_len > 0:
                    payload = await get_payload()
                    payload_len -= len(payload)
                    yield payload
            else:
                yield payload
            # Release memory
            payload = None

    async def recv_message(self, read):
        '''An asynchronous generator of incoming message headers.

        The asynchronous function read is called to read bytes from a stream.
        The caller is responsible for reading the payload from the stream, and validating the
        checksum if necessary.
        '''
        while True:
            header = await MessageHeader.from_stream(read)
            if header.magic != self.network.magic:
                raise ProtocolError(f'bad magic: got 0x{header.magic.hex()} '
                                    f'expected 0x{self.network.magic.hex()}')

            if self.verbosity >= 2:
                self.logger.debug(f'{header} message with payload size {header.payload_len:,d}')

            yield header
