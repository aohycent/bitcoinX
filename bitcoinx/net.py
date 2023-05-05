# Copyright (c) 2023, Neil Booth
#
# All rights reserved.
#

import attr
import re
import time
from enum import IntEnum, IntFlag
from functools import partial
from hashlib import sha256
from io import BytesIO
from ipaddress import ip_address, IPv4Address, IPv6Address
from struct import Struct, error as struct_error

from .packing import (
    pack_byte, pack_le_int32, pack_le_uint32, pack_le_int64, pack_le_uint64, pack_varint,
    pack_varbytes, pack_port, unpack_port,
    read_varbytes, read_varint, read_le_int32, read_le_uint32, read_le_uint64, read_le_int64,
)

from .errors import ConnectionClosedError, ForceDisconnectError, ProtocolError


header_struct = Struct('<4s12sI4s')
unpack_header = header_struct.unpack
pack_header = header_struct.pack
# This is the maximum payload length a non-streaming command can accept.  Such
# payloads are buffered and processed as a unit by the handler.
ATOMIC_PAYLOAD_SIZE = 2_000_000
PROTOCOL_VERSION = 70015


@attr.s(slots=True)
class NetMessage:

    HEADER_SIZE = header_struct.size
    COMMAND_LEN = 12

    magic = attr.ib()
    command_bytes = attr.ib()
    payload_len = attr.ib()
    checksum = attr.ib()

    @classmethod
    def from_bytes(cls, header):
        return cls(*unpack_header(header))

    def __str__(self):
        '''The message command as text (or a hex representation if not ASCII).'''
        command = self.command_bytes.rstrip(b'\0')
        return command.decode() if command.isascii() else '0x' + command.hex()


def _command(text):
    return text.encode().ljust(NetMessage.COMMAND_LEN, b'\0')


# List these explicitly because pylint is dumb
NetMessage.ADDR = _command('addr')
NetMessage.BLOCK = _command('block')
NetMessage.BLOCKTXN = _command('blocktxn')
NetMessage.CMPCTBLOCK = _command('cmpctblock')
NetMessage.CREATESTRM = _command('createstrm')
NetMessage.FEEFILTER = _command('feefilter')
NetMessage.FILTERADD = _command('filteradd')
NetMessage.FILTERCLEAR = _command('filterclear')
NetMessage.FILTERLOAD = _command('filterload')
NetMessage.GETADDR = _command('getaddr')
NetMessage.GETBLOCKS = _command('getblocks')
NetMessage.GETBLOCKTXN = _command('getblocktxn')
NetMessage.GETDATA = _command('getdata')
NetMessage.GETHEADERS = _command('getheaders')
NetMessage.HEADERS = _command('headers')
NetMessage.INV = _command('inv')
NetMessage.MEMPOOL = _command('mempool')
NetMessage.MERKELBLOCK = _command('merkleblock')
NetMessage.NOTFOUND = _command('notfound')
NetMessage.PING = _command('ping')
NetMessage.PONG = _command('pong')
NetMessage.PROTOCONF = _command('protoconf')
NetMessage.REJECT = _command('reject')
NetMessage.REPLY = _command('reply')
NetMessage.SENDCMPCT = _command('sendcmpct')
NetMessage.SENDHEADERS = _command('sendheaders')
NetMessage.STREAMACK = _command('streamack')
NetMessage.TX = _command('tx')
NetMessage.VERACK = _command('verack')
NetMessage.VERSION = _command('version')


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


class ServicePart(IntEnum):
    PROTOCOL = 0
    HOST = 1
    PORT = 2


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


class ServiceFlags(IntFlag):
    NODE_NONE = 0
    NODE_NETWORK = 1 << 0
    NODE_GETUTXO = 1 << 1
    NODE_BLOOM = 1 << 2


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


class PayloadReader:

    streaming_commands = {
        NetMessage.BLOCK, NetMessage.CMPCTBLOCK, NetMessage.BLOCKTXN,
        NetMessage.TX, NetMessage.INV, NetMessage.GETDATA
    }

    def __init__(self, session, message):
        self.sock = session.sock
        self.message = message
        self.remaining = message.payload_len
        self.hasher = sha256()
        self.logger = session.logger

    def validate_checksum(self):
        assert not self.remaining
        ours = sha256(self.hasher.digest()).digest()[:4]
        if ours != self.message.checksum:
            raise ProtocolError(f'checksum mismatch in {self.message}: '
                                f'ours=0x{ours.hex()} theirs=0x{self.message.checksum.hex()}')

    async def read(self, size):
        size = min(self.remaining, size)
        result = await read_exact(self.sock.recv, size)
        self.hasher.update(result)
        self.remaining -= size
        return result

    async def handle(self, handler):
        if not handler:
            self.logger.warning(f'received unknown message {self.message}')
            await self.consume_remainder()
        elif self.message.command_bytes in self.streaming_commands:
            await handler(self)
            if self.remaining:
                self.logger.warning(f'ignoring overlong {self.message} message')
                await self.consume_remainder()
            else:
                self.validate_checksum()
        elif self.remaining <= ATOMIC_PAYLOAD_SIZE:
            # Handle atomically
            payload = await self.read(self.remaining)
            self.validate_checksum()
            read = BytesIO(payload).read
            await handler(read)
            if read(1):
                self.logger.warning(f'ignoring overlong {self.message} message')
        else:
            await self.consume_remainder()
            raise ProtocolError(f'oversized {self.message} payload of '
                                f'{self.message.payload_len:,d} bytes')

    async def consume_remainder(self, timeout=1.0):
        try:
            async with timeout_after(timeout):
                while self.remaining:
                    await self.read(1_000_000)
        except TaskTimeout:
            raise ForceDisconnectError(f'timeout consuming payload of length '
                                       f'{self.message.payload_len:,d} '
                                       f'of {self.message} message') from None
        self.validate_checksum()

    async def recv_into(self, buffer, nbytes=0):
        # This works best if buffer is a memoryview
        if not nbytes:
            nbytes = len(buffer)
        total = min(nbytes, self.remaining)

        remaining = total
        while remaining > 0:
            done = await self.sock.recv_into(buffer, remaining)
            if not done:
                raise ConnectionClosedError(f'connection closed with {remaining:,d} bytes left')
            self.hasher.update(buffer[:done])
            buffer = buffer[done:]
            remaining -= done

        self.remaining -= total
        return total


async def read_exact(recv, size):
    # Optimize normal case
    part = await recv(size)
    if len(part) == size:
        return part
    parts = []
    while part:
        parts.append(part)
        size -= len(part)
        if not size:
            return b''.join(parts)
        part = await recv(size)
    raise ConnectionClosedError(f'connection closed with {size:,d} bytes left')


class BitcoinSession:

    def __init__(self, network, peer_address, verbosity):
        self.peer_address = NetAddress.from_string(peer_address)
        self.network = network
        self.verbosity = verbosity
        self.resolved_address = None
        self.is_outgoing = False
        # The chain tracked by our peer
        self.chain = None
        self.known_height = 0
        self.headers_synced = False
        self.logger = logging.getLogger(f'BS {peer_address}')

    async def connect(self):
        self.sock = await open_connection(str(self.peer_address.host), self.peer_address.port)
        self.is_outgoing = True
        ip_addr, port, *_ = self.sock.getpeername()
        self.resolved_address = NetAddress(ip_addr, port)
        self.logger.info(f'connected at {self.resolved_address}')

    async def on_headers(self, headers):
        '''Pass headers on to coordinator.  Returns a locator to request more headers.'''
        return await self.coordinator.send_request('headers', headers)

    async def run(self, start_height, initial_locator):
        await self.connect()
        protocol = self.network.protocol(self, start_height)
        await protocol.run(initial_locator)

    async def read_exact(self, size):
        return await read_exact(self.sock.recv, size)

    async def send_raw(self, message):
        await self.sock.sendall(message)


class InventoryKind(IntEnum):
    ERROR = 0
    TX = 1
    BLOCK = 2
    # The following occur only in getdata messages.  Invs always use TX or BLOCK.
    FILTERED_BLOCK = 3
    COMPACT_BLOCK = 4


def getdata_payload(hashes, kind):
    def parts(hashes, kind):
        yield pack_varint(len(hashes))
        kind_bytes = pack_le_uint32(kind)
        for item_hash in hashes:
            yield kind_bytes
            yield item_hash

    return b''.join(parts(hashes, kind))


def block_locator_parts(locator, hash_stop):
    yield pack_le_int32(PROTOCOL_VERSION)
    yield pack_varint(len(locator))
    for block_hash in locator:
        yield block_hash
    yield hash_stop or bytes(32)


def pack_block_locator(locator, hash_stop=None):
    return b''.join(block_locator_parts(locator, hash_stop))


class BitcoinProtocol:

    def __init__(self, session, start_height, *, magic):
        self.session = session
        self.magic = magic
        self.verbosity = session.verbosity
        self.network = session.network
        self.logger = session.logger

        # State
        self.handlers = {}
        self.our_service = ServiceDetails(
            service=BitcoinService('[::]:0', 0),
            user_agent='/seeder:1.0/',
            protoconf=Protoconf(ATOMIC_PAYLOAD_SIZE, [b'Default']),
            start_height=start_height,
        )
        self.their_service = None
        self.version_sent = False
        self.requested_blocks = {}

        # These three coordinate the initial handshake
        self.send_version_good = Event()
        self.version_received = Event()
        self.verack_received = Event()

        self.caught_up_event = Event()
        self.request_blocks_event = Event()

    def log_service_details(self, serv, headline):
        self.logger.info(headline)
        self.logger.info(f'    user_agent={serv.user_agent} '
                         f'services={ServiceFlags(serv.service.services)!r}')
        self.logger.info(f'    protocol={serv.version} height={serv.start_height:,d}  '
                         f'relay={serv.relay} timestamp={serv.timestamp} assoc_id={serv.assoc_id}')

    #
    # Control
    #

    def setup_handlers(self, handshake):
        '''Set up handlers.  If handshake is True then for the initial handshake, otherwise
        for once the handshake is complete.'''
        if handshake:
            self.handlers = {
                NetMessage.VERSION: self.on_version,
                NetMessage.PROTOCONF: self.on_protoconf,
                NetMessage.VERACK: self.on_verack,
            }
        else:
            self.handlers.update({
                NetMessage.ADDR: self.on_addr,
                NetMessage.BLOCK: self.on_block,
                NetMessage.FEEFILTER: self.on_feefilter,
                NetMessage.HEADERS: self.on_headers,
                # NetMessage.INV: self.on_inv,
                NetMessage.PING: self.on_ping,
                # NetMessage.PONG is handled locally in keep_alive()
                NetMessage.SENDHEADERS: self.on_sendheaders,
                NetMessage.SENDCMPCT: self.on_sendcmpct,
            })

    async def perform_handshake(self):
        '''Perform the initial handshake.'''
        await self.send_version()
        await self.send_verack()
        await self.verack_received.wait()

    async def post_handshake_messaging(self, initial_locator):
        await self.send_protoconf()
        await self.send_message(NetMessage.SENDHEADERS, b'')
        await self.get_headers(initial_locator)

    async def run(self, initial_locator):
        if self.session.is_outgoing:
            await self.send_version_good.set()

        # FIXME: clean this up
        async with TaskGroup(wait=any) as group:
            # Set up the handshake handlers and the message processing task so we can
            # handle responses
            self.setup_handlers(handshake=True)
            await group.spawn(self.process_messages)

            # Do the handshake before post-handshake messaging, setting up keep-alive etc.
            await self.perform_handshake()
            await self.post_handshake_messaging(initial_locator)

            await group.spawn(self.keep_alive)
            # await group.spawn(self.sync_blocks)

    async def keep_alive(self, interval=600):
        '''Send occational pings to keep the connection alive.'''
        async def on_pong(read):
            nonlocal ping_nonce

            pong_nonce = read(8)
            if ping_nonce is None:
                self.logger.warning('ignoring pong; no ping sent')
            else:
                if ping_nonce == pong_nonce:
                    ping_nonce = None
                    self.logger.debug('received good pong')
                else:
                    self.logger.warning('received bad pong')

        ping_nonce = None
        self.handlers[NetMessage.PONG] = on_pong
        while True:
            ping_nonce = urandom(8)
            self.logger.debug('sending ping')
            await self.send_message(NetMessage.PING, ping_nonce)
            await sleep(interval)
            if ping_nonce is not None:
                self.logger.warning('ping sent but pong not received')

    async def get_headers(self, locator):
        self.logger.debug(f'requesting headers; locator has {len(locator)} entries')
        await self.send_message(NetMessage.GETHEADERS, pack_block_locator(locator))

    # async def sync_blocks(self):
    #     await self.caught_up_event.wait()
    #     while True:
    #         self.request_blocks_event.clear()
    #         # FIXME: smarter way to throttle?
    #         count = 200 - len(self.requested_blocks)
    #         hashes = self.synchronizer.getblock_hashes(count)
    #         if hashes:
    #             self.logger.debug(f'requesting {len(hashes):,d} blocks')
    #             self.requested_blocks.update(hashes)
    #             payload = getdata_payload(hashes.keys(), kind=InventoryKind.BLOCK)
    #             await self.send_message(NetMessage.GETDATA, payload)
    #         await self.request_blocks_event.wait()

    #
    # Outgoing messages
    #

    def build_header(self, command, payload):
        checksum = double_sha256(payload)[:4]
        return b''.join((self.magic, command, pack_le_uint32(len(payload)), checksum))

    async def send_message(self, command, payload):
        '''Send a command and its payload.  Since the message header requires a length and a
        checksum, we cannot stream messages; the entire payload must be known in
        advance.
        '''
        await self.session.send_raw(self.build_header(command, payload))
        await self.session.send_raw(payload)

    async def send_version(self):
        await self.send_version_good.wait()
        nonce = urandom(8)
        self.log_service_details(self.our_service, 'sending version message:')
        payload = self.our_service.version_payload(self.session.resolved_address, nonce)
        await self.send_message(NetMessage.VERSION, payload)
        self.version_sent = True

    async def send_verack(self):
        await self.version_received.wait()
        self.logger.debug('sending verack message')
        await self.send_message(NetMessage.VERACK, b'')

    async def send_protoconf(self):
        await self.send_message(NetMessage.PROTOCONF, self.our_service.protoconf.payload())

    #
    # Incoming message processing
    #

    async def process_messages(self):
        '''Process incoming commands.

        Raises: ConnectionClosedError
        '''
        self.logger.debug('processing incoming messages...')
        while True:
            try:
                await self.process_one_message()
            except struct_error as e:
                self.logger.error(f'truncated message: {e}')
            except ProtocolError as e:
                self.logger.error(f'protocol error: {e}')

    async def process_one_message(self):
        '''Process a single incoming command.

        Raises: ProtocolError, ConnectionClosedError, UnknownCommandError
        '''
        message = NetMessage.from_bytes(await self.session.read_exact(NetMessage.HEADER_SIZE))

        if message.magic != self.magic:
            raise ProtocolError(f'bad magic: got 0x{message.magic.hex()} '
                                f'expected 0x{self.magic.hex()}')
        if self.verbosity:
            self.logger.debug(f'{message} message with payload size {message.payload_len:,d}')

        reader = PayloadReader(self.session, message)
        handler = self.handlers.get(message.command_bytes)
        await reader.handle(handler)

    #
    # Message receiving
    #

    async def on_version(self, read):
        is_duplicate = self.version_received.is_set()
        if is_duplicate:
            self.logger.error('duplicate version message received')

        service_details, _our_service, _nonce = ServiceDetails.read(read, self.logger)
        if not is_duplicate:
            self.their_service = service_details
            self.log_service_details(service_details, 'received version message:')
            await self.version_received.set()
            await self.send_version_good.set()

    async def on_verack(self, _read):
        if self.verack_received.is_set():
            self.logger.error('duplicate verack message received')
        elif self.version_sent:
            self.setup_handlers(handshake=False)
            await self.verack_received.set()
        else:
            self.logger.error('verack message received before version message sent')

    async def on_addr(self, read):
        '''Receive a lits of peer addresses.'''
        addrs = BitcoinService.read_addrs(read)
        self.logger.debug(f'read {len(addrs)} peers from ADDR message')

    async def on_ping(self, read):
        '''Handle an incoming ping by sending a pong with the same 8-byte nonce.'''
        nonce = read(8)
        if self.verbosity:
            self.logger.debug(f'received ping nonce {nonce.hex()}')
        await self.send_message(NetMessage.PONG, nonce)

    async def on_sendheaders(self, _read):
        '''The sendheaders message of of no interest to us; we don't announce new blocks.'''
        # No payload
        self.logger.debug('ignoring sendheaders message')

    async def on_sendcmpct(self, read):
        '''The sendcmpct message of of no interest to us; we don't announce new blocks.'''
        flag = read(1)
        version = read_le_uint64(read)
        if flag[0] not in {0, 1}:
            self.logger.warning(f'unexpected flag byte {flag[0]}')
        self.logger.debug(f'ignoring sendcmpct message (version is {version:,d})')

    async def on_feefilter(self, read):
        '''The feefilter message of of no interest to us; ignore it.'''
        feerate = read_le_int64(read)
        self.logger.debug(f'ignoring feefilter message; feerate was {feerate:,d}')

    async def on_protoconf(self, read):
        '''Handle the protoconf message.'''
        self.their_service.read_protoconf(read, self.logger)
        # FIXME: maybe create further streams to this peer

    async def on_headers(self, read):
        '''Handle getting a bunch of headers.'''
        count = read_varint(read)
        if count > 2000:
            self.logger.warning(f'{count:,d} headers in headers message')

        headers = []
        for _ in range(count):
            headers.append(read(80))
            # A stupid tx count which seems to always be zero...
            read_varint(read)

        locator = await self.session.on_headers(headers)
        if locator:
            await self.get_headers(locator)
        else:
            await self.caught_up_event.set()

    async def on_inv(self, read):
        '''Handle getting an inv packet.'''
        count = read_varint(read)
        if count > 50_000:
            self.logger.warning(f'{count:,d} items in inv message')
        inv = [(read_le_uint32(read), read(32)) for _ in range(count)]
        block_count = sum(kind == InventoryKind.BLOCK for kind, _hash in inv)
        self.logger.warning(f'received inv with {block_count:,d}/{len(inv):,d} blocks')

    async def on_block(self, stream):
        header = await stream.read(80)
        block_hash = double_sha256(header)
        block_id = self.requested_blocks.pop(block_hash, None)
        if block_id is None:
            self.logger.warning(f'received unrequested block {hash_to_hex_str(block_hash)}')
            await stream.consume_remainder()
        else:
            # await self.block_db.write_block(stream, header)
            await stream.consume_remainder()
            await self.request_blocks_event.set()


class Protocol:

    def __init__(self, network, is_outgoing, start_height):
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

        # Incoming messages
        self.unprocessed = []
        self.unprocessed_len = 0
        self.need_len = NetMessage.HEADER_SIZE

        self.version_sent = False
        self.requested_blocks = {}
        self.handlers = {}

        # These three coordinate the initial handshake
        self.send_version_good = Event()
        self.version_received = Event()
        self.verack_received = Event()

        self.caught_up_event = Event()
        self.request_blocks_event = Event()

    def log_service_details(self, serv, headline):
        self.logger.info(headline)
        self.logger.info(f'    user_agent={serv.user_agent} '
                         f'services={ServiceFlags(serv.service.services)!r}')
        self.logger.info(f'    protocol={serv.version} height={serv.start_height:,d}  '
                         f'relay={serv.relay} timestamp={serv.timestamp} assoc_id={serv.assoc_id}')

    #
    # Call this when data is received
    #

    def incoming_data(self, data):
        self.unprocessed.append(data)
        self.unprocessed_len += len(data)

    def incoming_message(self):
        if self.unprocesed_len < self.need_len:
            return None
        #


    def version_message


    #
    # Control
    #

    def setup_handlers(self, handshake):
        '''Set up handlers.  If handshake is True then for the initial handshake, otherwise
        for once the handshake is complete.'''
        if handshake:
            self.handlers = {
                NetMessage.VERSION: self.on_version,
                NetMessage.PROTOCONF: self.on_protoconf,
                NetMessage.VERACK: self.on_verack,
            }
        else:
            self.handlers.update({
                NetMessage.ADDR: self.on_addr,
                NetMessage.BLOCK: self.on_block,
                NetMessage.FEEFILTER: self.on_feefilter,
                NetMessage.HEADERS: self.on_headers,
                # NetMessage.INV: self.on_inv,
                NetMessage.PING: self.on_ping,
                # NetMessage.PONG is handled locally in keep_alive()
                NetMessage.SENDHEADERS: self.on_sendheaders,
                NetMessage.SENDCMPCT: self.on_sendcmpct,
            })

    async def perform_handshake(self):
        '''Perform the initial handshake.'''
        await self.send_version()
        await self.send_verack()
        await self.verack_received.wait()

    async def post_handshake_messaging(self, initial_locator):
        await self.send_protoconf()
        await self.send_message(NetMessage.SENDHEADERS, b'')
        await self.get_headers(initial_locator)

    async def run(self, initial_locator):
        if self.session.is_outgoing:
            await self.send_version_good.set()

        # FIXME: clean this up
        async with TaskGroup(wait=any) as group:
            # Set up the handshake handlers and the message processing task so we can
            # handle responses
            self.setup_handlers(handshake=True)
            await group.spawn(self.process_messages)

            # Do the handshake before post-handshake messaging, setting up keep-alive etc.
            await self.perform_handshake()
            await self.post_handshake_messaging(initial_locator)

            await group.spawn(self.keep_alive)
            # await group.spawn(self.sync_blocks)

    async def keep_alive(self, interval=600):
        '''Send occational pings to keep the connection alive.'''
        async def on_pong(read):
            nonlocal ping_nonce

            pong_nonce = read(8)
            if ping_nonce is None:
                self.logger.warning('ignoring pong; no ping sent')
            else:
                if ping_nonce == pong_nonce:
                    ping_nonce = None
                    self.logger.debug('received good pong')
                else:
                    self.logger.warning('received bad pong')

        ping_nonce = None
        self.handlers[NetMessage.PONG] = on_pong
        while True:
            ping_nonce = urandom(8)
            self.logger.debug('sending ping')
            await self.send_message(NetMessage.PING, ping_nonce)
            await sleep(interval)
            if ping_nonce is not None:
                self.logger.warning('ping sent but pong not received')

    async def get_headers(self, locator):
        self.logger.debug(f'requesting headers; locator has {len(locator)} entries')
        await self.send_message(NetMessage.GETHEADERS, pack_block_locator(locator))

    # async def sync_blocks(self):
    #     await self.caught_up_event.wait()
    #     while True:
    #         self.request_blocks_event.clear()
    #         # FIXME: smarter way to throttle?
    #         count = 200 - len(self.requested_blocks)
    #         hashes = self.synchronizer.getblock_hashes(count)
    #         if hashes:
    #             self.logger.debug(f'requesting {len(hashes):,d} blocks')
    #             self.requested_blocks.update(hashes)
    #             payload = getdata_payload(hashes.keys(), kind=InventoryKind.BLOCK)
    #             await self.send_message(NetMessage.GETDATA, payload)
    #         await self.request_blocks_event.wait()

    #
    # Outgoing messages
    #

    def build_header(self, command, payload):
        checksum = double_sha256(payload)[:4]
        return b''.join((self.magic, command, pack_le_uint32(len(payload)), checksum))

    async def send_message(self, command, payload):
        '''Send a command and its payload.  Since the message header requires a length and a
        checksum, we cannot stream messages; the entire payload must be known in
        advance.
        '''
        await self.session.send_raw(self.build_header(command, payload))
        await self.session.send_raw(payload)

    async def send_version(self):
        await self.send_version_good.wait()
        nonce = urandom(8)
        self.log_service_details(self.our_service, 'sending version message:')
        payload = self.our_service.version_payload(self.session.resolved_address, nonce)
        await self.send_message(NetMessage.VERSION, payload)
        self.version_sent = True

    async def send_verack(self):
        await self.version_received.wait()
        self.logger.debug('sending verack message')
        await self.send_message(NetMessage.VERACK, b'')

    async def send_protoconf(self):
        await self.send_message(NetMessage.PROTOCONF, self.our_service.protoconf.payload())

    #
    # Incoming message processing
    #

    async def process_messages(self):
        '''Process incoming commands.

        Raises: ConnectionClosedError
        '''
        self.logger.debug('processing incoming messages...')
        while True:
            try:
                await self.process_one_message()
            except struct_error as e:
                self.logger.error(f'truncated message: {e}')
            except ProtocolError as e:
                self.logger.error(f'protocol error: {e}')

    async def process_one_message(self):
        '''Process a single incoming command.

        Raises: ProtocolError, ConnectionClosedError, UnknownCommandError
        '''
        message = NetMessage.from_bytes(await self.session.read_exact(NetMessage.HEADER_SIZE))

        if message.magic != self.magic:
            raise ProtocolError(f'bad magic: got 0x{message.magic.hex()} '
                                f'expected 0x{self.magic.hex()}')
        if self.verbosity:
            self.logger.debug(f'{message} message with payload size {message.payload_len:,d}')

        reader = PayloadReader(self.session, message)
        handler = self.handlers.get(message.command_bytes)
        await reader.handle(handler)

    #
    # Message receiving
    #

    async def on_version(self, read):
        is_duplicate = self.version_received.is_set()
        if is_duplicate:
            self.logger.error('duplicate version message received')

        service_details, _our_service, _nonce = ServiceDetails.read(read, self.logger)
        if not is_duplicate:
            self.their_service = service_details
            self.log_service_details(service_details, 'received version message:')
            await self.version_received.set()
            await self.send_version_good.set()

    async def on_verack(self, _read):
        if self.verack_received.is_set():
            self.logger.error('duplicate verack message received')
        elif self.version_sent:
            self.setup_handlers(handshake=False)
            await self.verack_received.set()
        else:
            self.logger.error('verack message received before version message sent')

    async def on_addr(self, read):
        '''Receive a lits of peer addresses.'''
        addrs = BitcoinService.read_addrs(read)
        self.logger.debug(f'read {len(addrs)} peers from ADDR message')

    async def on_ping(self, read):
        '''Handle an incoming ping by sending a pong with the same 8-byte nonce.'''
        nonce = read(8)
        if self.verbosity:
            self.logger.debug(f'received ping nonce {nonce.hex()}')
        await self.send_message(NetMessage.PONG, nonce)

    async def on_sendheaders(self, _read):
        '''The sendheaders message of of no interest to us; we don't announce new blocks.'''
        # No payload
        self.logger.debug('ignoring sendheaders message')

    async def on_sendcmpct(self, read):
        '''The sendcmpct message of of no interest to us; we don't announce new blocks.'''
        flag = read(1)
        version = read_le_uint64(read)
        if flag[0] not in {0, 1}:
            self.logger.warning(f'unexpected flag byte {flag[0]}')
        self.logger.debug(f'ignoring sendcmpct message (version is {version:,d})')

    async def on_feefilter(self, read):
        '''The feefilter message of of no interest to us; ignore it.'''
        feerate = read_le_int64(read)
        self.logger.debug(f'ignoring feefilter message; feerate was {feerate:,d}')

    async def on_protoconf(self, read):
        '''Handle the protoconf message.'''
        self.their_service.read_protoconf(read, self.logger)
        # FIXME: maybe create further streams to this peer

    async def on_headers(self, read):
        '''Handle getting a bunch of headers.'''
        count = read_varint(read)
        if count > 2000:
            self.logger.warning(f'{count:,d} headers in headers message')

        headers = []
        for _ in range(count):
            headers.append(read(80))
            # A stupid tx count which seems to always be zero...
            read_varint(read)

        locator = await self.session.on_headers(headers)
        if locator:
            await self.get_headers(locator)
        else:
            await self.caught_up_event.set()

    async def on_inv(self, read):
        '''Handle getting an inv packet.'''
        count = read_varint(read)
        if count > 50_000:
            self.logger.warning(f'{count:,d} items in inv message')
        inv = [(read_le_uint32(read), read(32)) for _ in range(count)]
        block_count = sum(kind == InventoryKind.BLOCK for kind, _hash in inv)
        self.logger.warning(f'received inv with {block_count:,d}/{len(inv):,d} blocks')

    async def on_block(self, stream):
        header = await stream.read(80)
        block_hash = double_sha256(header)
        block_id = self.requested_blocks.pop(block_hash, None)
        if block_id is None:
            self.logger.warning(f'received unrequested block {hash_to_hex_str(block_hash)}')
            await stream.consume_remainder()
        else:
            # await self.block_db.write_block(stream, header)
            await stream.consume_remainder()
            await self.request_blocks_event.set()
