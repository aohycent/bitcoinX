# Copyright (c) 2023, Neil Booth
#
# All rights reserved.
#

import attr
import logging
import re
import time
from asyncio import Event, Queue
from enum import IntEnum, IntFlag
from functools import partial
from ipaddress import ip_address, IPv4Address, IPv6Address
from os import urandom
from struct import Struct, error as struct_error

from .errors import ConnectionClosedError, ProtocolError
from .hashes import double_sha256
from .packing import (
    pack_byte, pack_le_int32, pack_le_uint32, pack_le_int64, pack_le_uint64, pack_varint,
    pack_varbytes, pack_port, unpack_port,
    read_varbytes, read_varint, read_le_int32, read_le_uint32, read_le_uint64, read_le_int64,
)


__all__ = (
    'is_valid_hostname', 'classify_host', 'validate_port', 'validate_protocol',
    'NetAddress', 'Service', 'ServicePart', 'BitcoinService', 'Protoconf',
    'MessageHeader', 'Connection', 'Stream',
)

#
# Miscellaneous handy networking utility functions
#


class ServicePart(IntEnum):
    PROTOCOL = 0
    HOST = 1
    PORT = 2


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
    '''Validate a protocol, a string, and return it in lower case.'''
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
        return f"NetAddress('{self}')"

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


class Stream:

    def __init__(self, recv):
        self.recv = recv

    async def recv_exact(self, size):
        recv = self.recv
        parts = []
        while size > 0:
            part = await recv(size)
            if not part:
                raise ConnectionClosedError(f'connection closed with {size:,d} bytes left')
            parts.append(part)
            size -= len(part)
        return b''.join(parts)

    # async def chunks(self, chunk_size, total_size):
    #     '''Asynchronous generator of chunks.  Caller must send the number of bytes consumed.'''
    #     remaining = total_size
    #     residual = b''
    #     while remaining:
    #         size = min(remaining - len(residual), chunk_size)
    #         chunk = await self.recv_exact(size)
    #         if residual:
    #             chunk = b''.join((residual, chunk))
    #         bio = BytesIO(chunk)
    #         yield bio
    #         remaining -=
    #         consumed = bio.tell()
    #         remaining -= consumed
    #         residual = memoryview(chunk[consumed:])


#
# Constants and classes implementing the Bitcoin network protocol
#

# Standard and extended message hedaers
std_header_struct = Struct('<4s12sI4s')
std_pack = std_header_struct.pack
std_unpack = std_header_struct.unpack
ext_header_struct = Struct('<4s12sI4s12sQ')
ext_pack = ext_header_struct.pack
ext_extra_struct = Struct('<12sQ')
ext_extra_unpack = ext_extra_struct.unpack
empty_checksum = bytes(4)

# This is the maximum payload length a non-streaming command can accept.  Such
# payloads are buffered and processed as a unit by the handler.
ATOMIC_PAYLOAD_SIZE = 2_000_000
PROTOCOL_VERSION = 70015


class InventoryKind(IntEnum):
    ERROR = 0
    TX = 1
    BLOCK = 2
    # The following occur only in getdata messages.  Invs always use TX or BLOCK.
    FILTERED_BLOCK = 3
    COMPACT_BLOCK = 4


@attr.s(slots=True)
class MessageHeader:
    '''The header of a network protocol message.'''

    # Extended headers were introduced in the BSV 1.0.10 node software.

    COMMAND_LEN = 12
    STD_HEADER_SIZE = std_header_struct.size
    EXT_HEADER_SIZE = ext_header_struct.size

    magic = attr.ib()
    command = attr.ib()      # bytes
    payload_len = attr.ib()
    checksum = attr.ib()
    is_extended = attr.ib()

    @classmethod
    async def from_stream(cls, stream):
        raw_std = await stream.recv_exact(cls.STD_HEADER_SIZE)
        magic, command, payload_len, checksum = std_unpack(raw_std)
        is_extended = False
        if command == cls.EXTMSG:
            if checksum != empty_checksum or payload_len != 0xffffffff:
                raise ProtocolError('ill-formed extended message header')
            raw_ext = await stream.recv_exact(cls.EXT_HEADER_SIZE - cls.STD_HEADER_SIZE)
            command, payload_len = ext_extra_unpack(raw_ext)
            is_extended = True
        return cls(magic, command, payload_len, checksum, is_extended)

    def __str__(self):
        '''The message command as text (or a hex representation if not ASCII).'''
        command = self.command.rstrip(b'\0')
        return command.decode() if command.isascii() else '0x' + command.hex()

    @staticmethod
    def payload_checksum(payload):
        return double_sha256(payload)[:4]

    @classmethod
    def std_bytes(cls, magic, command, payload):
        return std_pack(magic, command, len(payload), cls.payload_checksum(payload))

    @classmethod
    def ext_bytes(cls, magic, command, payload_len):
        return ext_pack(magic, cls.EXTMSG, 0xffffffff, empty_checksum, command, payload_len)


def _command(text):
    return text.encode().ljust(MessageHeader.COMMAND_LEN, b'\0')


# List these explicitly because pylint is dumb
MessageHeader.ADDR = _command('addr')
MessageHeader.AUTHCH = _command('authch')
MessageHeader.AUTHRESP = _command('authresp')
MessageHeader.BLOCK = _command('block')
MessageHeader.BLOCKTXN = _command('blocktxn')
MessageHeader.CMPCTBLOCK = _command('cmpctblock')
MessageHeader.CREATESTRM = _command('createstrm')
MessageHeader.DATAREFTX = _command('datareftx')
MessageHeader.DSDETECTED = _command('dsdetected')
MessageHeader.EXTMSG = _command('extmsg')
MessageHeader.FEEFILTER = _command('feefilter')
MessageHeader.GETADDR = _command('getaddr')
MessageHeader.GETBLOCKS = _command('getblocks')
MessageHeader.GETBLOCKTXN = _command('getblocktxn')
MessageHeader.GETDATA = _command('getdata')
MessageHeader.GETHEADERS = _command('getheaders')
MessageHeader.GETHDRSEN = _command('gethdrsen')
MessageHeader.HDRSEN = _command('hdrsen')
MessageHeader.HEADERS = _command('headers')
MessageHeader.INV = _command('inv')
MessageHeader.MEMPOOL = _command('mempool')
MessageHeader.MERKLEBLOCK = _command('merkleblock')
MessageHeader.NOTFOUND = _command('notfound')
MessageHeader.PING = _command('ping')
MessageHeader.PONG = _command('pong')
MessageHeader.PROTOCONF = _command('protoconf')
MessageHeader.REJECT = _command('reject')
MessageHeader.REPLY = _command('reply')
MessageHeader.REVOKEMID = _command('revokemid')
MessageHeader.SENDCMPCT = _command('sendcmpct')
MessageHeader.SENDHEADERS = _command('sendheaders')
MessageHeader.SENDHDRSEN = _command('sendhdrsen')
MessageHeader.STREAMACK = _command('streamack')
MessageHeader.TX = _command('tx')
MessageHeader.VERACK = _command('verack')
MessageHeader.VERSION = _command('version')


class BitcoinService:
    '''Represents a bitcoin network service.

    Consists of an NetAddress (which must have an IPv4 or IPv6 resolved host) and a
    services mask.
    '''
    struct = Struct('<Q16s2s')

    class Flags(IntFlag):
        NODE_NONE = 0
        NODE_NETWORK = 1 << 0
        # All other flags are obsolete

    def __init__(self, address, services):
        if not isinstance(address, NetAddress):
            address = NetAddress.from_string(address)
        if not isinstance(address.host, (IPv4Address, IPv6Address)):
            raise ValueError('BitcoinService requires an IP address')
        self.address = address
        self.services = self.Flags(services)

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
        return f'{self.address} {self.services!r}'

    def __repr__(self):
        return f"BitcoinService('{self.address}', {self.services!r})"


@attr.s(repr=True)
class Protoconf:
    LEGACY_MAX_PAYLOAD = 1024 * 1024

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
    def read(cls, read, logger=None):
        logger = logger or logging

        field_count = read_varint(read)
        if field_count < 2:
            raise ProtocolError('bad field count {field_count} in protoconf message')
        if field_count != 2:
            logger.warning('unexpected field count {field_count:,d} in protoconf message')

        max_payload = read_le_uint32(read)
        if max_payload < Protoconf.LEGACY_MAX_PAYLOAD:
            raise ProtocolError(f'invalid max payload {max_payload:,d} in protconf message')

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


class Connection:

    def __init__(self, headers, send, stream, net_address, is_outgoing, handlers, *,
                 max_payload_size=ATOMIC_PAYLOAD_SIZE, verbosity=2):
        '''net_address is a resolved NetAddress object.'''
        # Verbosity: 0 (warnings), 1 (info), 2 (debug)
        self.headers = headers
        self.send = send
        self.stream = stream
        self.net_address = net_address
        self.is_outgoing = is_outgoing
        self.handlers = self.add_default_handlers(handlers)
        self.verbosity = verbosity

        # Quick access
        self.network = headers.network
        self.network_magic = self.network.magic

        # State
        self.our_service = ServiceDetails(
            service=BitcoinService('[::]:0', 0),
            user_agent='/Z:1.0/',
            protoconf=Protoconf(max_payload_size, [b'Default']),
            start_height=headers.height,
        )
        self.their_service = None
        self.version_sent = False
        self.version_received = Event()
        self.verack_received = Event()

        # Outgoing messages
        self.outgoing_messages = Queue()

        self.logger = logging.getLogger('Protocol')

    def log_service_details(self, serv, headline):
        self.logger.info(headline)
        self.logger.info(f'    user_agent={serv.user_agent} '
                         f'services={serv.service.services!r}')
        self.logger.info(f'    protocol={serv.version} height={serv.start_height:,d}  '
                         f'relay={serv.relay} timestamp={serv.timestamp} assoc_id={serv.assoc_id}')

    def add_default_handlers(self, handlers):
        handlers = handlers.copy()
        for command in 'version verack protoconf ping pong'.split():
            handler = getattr(self, f'on_{command}', None)
            if handler:
                handlers[getattr(MessageHeader, command.toupper())] = handler
        return handlers

    #
    # Message streaming
    #

    async def recv_messages_loop(self):
        '''An asynchronous generator of incoming message headers.

        Bytes are asynchonously read from a stream.  The caller is responsible for reading
        the payload from the stream, and validating the checksum if necessary.
        '''
        while True:
            header = await MessageHeader.from_stream(self.stream)
            if header.magic != self.network_magic:
                raise ProtocolError(f'bad magic: got 0x{header.magic.hex()} '
                                    f'expected 0x{self.network_magic.hex()}')

            if self.verbosity >= 2:
                self.logger.debug(f'in: {header} message payload {header.payload_len:,d} bytes')

            await self.handle_message(header)

    async def handle_message(self, header):
        if not self.verack_received.is_set():
            if header.command not in (MessageHeader.VERSION, MessageHeader.VERACK):
                raise ProtocolError(f'{header} command received before handshake finished')

        if header.is_extended:
            handler = self.handlers.get(header.command + b'X')
            if handler:
                await handler(self.stream, header.payload_len)
                return

        # FIXME: handle large payloads in a streaming fashion

        # Consume the payload
        payload = await self.stream.recv_exact(header.payload_len)
        handler = self.handlers.get(header.command)
        if not handler:
            self.logger.debug(f'ignoring unhandled {header} command')
            return

        if not header.is_extended and header.payload_checksum(payload) != header.checksum:
            raise ProtocolError(f'bad payload chceksum for {header} command')
        return await handler(payload)

    async def send_messages_loop(self):
        '''Handles sending the queue of messages.  This sends all messages except the initial
        version / verack handshake.
        '''
        await self.perform_handshake()

        while True:
            items = await self.outgoing_messages.get()
            for item in items:
                # Items are something byte-like to send, or a (payload_len, parts_func) pair.
                if isinstance(item, tuple):
                    payload_len, parts_func = item
                    while payload_len > 0:
                        payload = await parts_func()
                        payload_len -= len(payload)
                        await self.send(payload)
                else:
                    await self.send(item)

    async def perform_handshake(self):
        '''Perform the initial handshake.  Send version and verack messages, and wait until a
        verack is received back.'''
        await self.send_version()
        await self.send_verack()
        await self.verack_received.wait()

    async def send_version(self):
        '''Send a version message.'''
        # Incoming connections wait until the version message is received.
        if not self.is_outgoing:
            await self.version_received.wait()
        nonce = urandom(8)
        self.log_service_details(self.our_service, 'sending version message:')

        payload = self.our_service.version_payload(self.net_address, nonce)
        header = MessageHeader.std_bytes(self.network_magic, MessageHeader.VERSION, payload)
        await self.send(header)
        await self.send(payload)
        self.version_sent = True

    async def send_verack(self):
        await self.version_received.wait()
        header = MessageHeader.std_bytes(self.network_magic, MessageHeader.VERACK, b'')
        await self.send(header)

    async def on_version(self, payload):
        pass

    async def on_verack(self, payload):
        if not self.version_sent:
            raise ProtocolError('verack message received before version message sent')

        if self.verack_received.is_set():
            self.logger.error('duplicate verack message received')
        else:
            if payload:
                self.logger.error('verack message has payload')
            self.verack_received.set()

    async def send_message(self, command, payload):
        '''Send a command and its payload.  Since the message header requires a length and a
        checksum, we cannot stream messages; the entire payload must be known in
        advance.
        '''
        header = MessageHeader.std_bytes(self.network_magic, command, payload)
        await self.outgoing_messages.put((header, payload))

    async def send_stream(self, command, payload_len, parts_func):
        header = MessageHeader.ext_bytes(self.network_magic, command, payload_len)
        await self.outgoing_messages.put((header, (payload_len, parts_func)))
