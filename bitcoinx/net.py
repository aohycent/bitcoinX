# Copyright (c) 2023, Neil Booth
#
# All rights reserved.
#

'''
Networking utilities that do not depend on (async) I/O.
'''

import attr
import logging
import time
from enum import IntEnum, IntFlag
from functools import partial
from io import BytesIO
from ipaddress import ip_address
from os import urandom
from struct import Struct, error as struct_error

from curio import Event, Queue, TaskGroup, open_connection, CancelledError, spawn

from .errors import ProtocolError, ForceDisconnectError
from .hashes import double_sha256, hash_to_hex_str
from .headers import Headers, header_prev_hash
from .packing import (
    pack_byte, pack_le_int32, pack_le_uint32, pack_le_int64, pack_le_uint64, pack_varint,
    pack_varbytes, unpack_port,
    read_varbytes, read_varint, read_le_int32, read_le_uint32, read_le_uint64, read_le_int64,
    read_list
)
from .misc import NetAddress


__all__ = (
    'BitcoinService', 'ServiceFlags', 'Protoconf', 'MessageHeader',
    'Node', 'Session',
)

ZERO_NONCE = bytes(8)


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
    command_bytes = attr.ib()
    payload_len = attr.ib()
    checksum = attr.ib()
    is_extended = attr.ib()

    @classmethod
    async def from_stream(cls, recv_exactly):
        raw_std = await recv_exactly(cls.STD_HEADER_SIZE)
        magic, command_bytes, payload_len, checksum = std_unpack(raw_std)
        is_extended = False
        if command_bytes == cls.EXTMSG:
            if checksum != empty_checksum or payload_len != 0xffffffff:
                raise ProtocolError('ill-formed extended message header')
            raw_ext = await recv_exactly(cls.EXT_HEADER_SIZE - cls.STD_HEADER_SIZE)
            command_bytes, payload_len = ext_extra_unpack(raw_ext)
            is_extended = True
        return cls(magic, command_bytes, payload_len, checksum, is_extended)

    def command(self):
        '''The command as text, e.g. addr '''
        command = self.command_bytes.rstrip(b'\0')
        return command.decode() if command.isascii() else '0x' + command.hex()

    def __str__(self):
        return self.command()

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


class ServiceFlags(IntFlag):
    NODE_NONE = 0
    NODE_NETWORK = 1 << 0
    # All other flags are obsolete


class ServicePacking:
    struct = Struct('<Q16s2s')

    @classmethod
    def pack(cls, address, services):
        '''Return the address and service flags as an encoded service.

        No timestamp is prefixed; this is used in for the version message.
        '''
        return pack_le_uint64(services) + address.pack()

    @classmethod
    def pack_with_timestamp(cls, address, services, timestamp):
        '''Return an encoded service with a 4-byte timestamp prefix.'''
        return pack_le_uint32(timestamp) + cls.pack(address, services)

    @classmethod
    def unpack(cls, raw):
        '''Given the final 26 bytes (no leading timestamp) of a protocol-encoded
        internet address return a (NetAddress, services) pair.'''
        services, address, raw_port = cls.struct.unpack(raw)
        address = ip_address(address)
        if address.ipv4_mapped:
            address = address.ipv4_mapped
        port, = unpack_port(raw_port)
        return (NetAddress(address, port, check_port=False), ServiceFlags(services))

    @classmethod
    def read(cls, read):
        '''Reads 26 bytes from a raw byte stream, returns a (NetAddress, services) pair.'''
        return cls.unpack(read(cls.struct.size))

    @classmethod
    def read_with_timestamp(cls, read):
        '''Read a timestamp-prefixed net_addr (4 + 26 bytes); return a
        (NetAddress, services, timestamp) tuple.'''
        timestamp = read_le_uint32(read)
        address, services = cls.read(read)
        return (address, services, timestamp)

    @classmethod
    def read_addrs(cls, read):
        '''Return a lits of (NetAddress, services, timestamp) triples from an addr
        message payload.'''
        count = read_varint(read)
        read_with_timestamp = cls.read_with_timestamp
        return [read_with_timestamp(read) for _ in range(count)]


def pack_block_locator(protocol_version, locator, hash_stop=None):
    parts = [pack_le_int32(protocol_version), pack_varint(len(locator))]
    parts.extend(locator)
    parts.append(hash_stop or bytes(32))
    return b''.join(parts)


def unpack_headers(payload):
    def read_one(read):
        raw_header = read(80)
        # A stupid tx count which seems to always be zero...
        read_varint(read)
        return raw_header

    read = BytesIO(payload).read
    return read_list(read, read_one)


class BitcoinService:
    '''Represents a bitcoin network service.

    Stores various details obtained from the version message.  Comparison and hashing is
    only done on the (resolved) network address.
    '''

    def __init__(self, *,
                 address=None,
                 services=ServiceFlags.NODE_NONE,
                 user_agent=None,
                 protocol_version=None,
                 start_height=0,
                 relay=True,
                 timestamp=None,
                 assoc_id=None):
        from bitcoinx import _version_str

        self.address = (NetAddress('::', 0, check_port=False) if address is None else
                        NetAddress.ensure_resolved(address))
        self.services = ServiceFlags(services)
        self.user_agent = user_agent or f'/bitcoinx/{_version_str}'
        self.protocol_version = protocol_version or 70015
        self.start_height = start_height
        self.relay = relay
        self.timestamp = timestamp
        self.assoc_id = assoc_id

    def __eq__(self, other):
        return self.address == other.address

    def __hash__(self):
        return hash(self.address)

    def to_version_payload(self, their_service, nonce):
        '''Create a version message payload.

        If self.timestamp is None, then the current time is used.
        their_service is a NetAddress or BitcoinService.
        '''
        if len(nonce) != 8:
            raise ValueError('nonce must be 8 bytes')

        if isinstance(their_service, NetAddress):
            their_service_packed = ServicePacking.pack(their_service, ServiceFlags.NODE_NONE)
        else:
            their_service_packed = their_service.pack()

        timestamp = int(time.time()) if self.timestamp is None else self.timestamp
        assoc_id = b'' if self.assoc_id is None else pack_varbytes(self.assoc_id)

        return b''.join((
            pack_le_int32(self.protocol_version),
            pack_le_uint64(self.services),
            pack_le_int64(timestamp),
            their_service_packed,
            self.pack(),   # In practice this is ignored by receiver
            nonce,
            pack_varbytes(self.user_agent.encode()),
            pack_le_int32(self.start_height),
            pack_byte(self.relay),
            assoc_id,
        ))

    def read_version_payload(self, payload):
        '''Read a version payload and update member variables (except address).  Return a tuple
        (our_address, our_services, nonce) from the payload.
        '''
        read = BytesIO(payload).read
        self.protocol_version = read_le_uint32(read)
        self.services = read_le_uint64(read)
        self.timestamp = read_le_int64(read)
        our_address, our_services = ServicePacking.read(read)
        ServicePacking.read(read)   # Ignore
        nonce = read(8)

        user_agent = read_varbytes(read)
        try:
            self.user_agent = user_agent.decode()
        except UnicodeDecodeError:
            self.user_agent = '0x' + user_agent.hex()

        self.start_height = read_le_int32(read)
        # Relay is optional, defaulting to True
        self.relay = read(1) != b'\0'
        # Association ID is optional.  We set it to None if not provided.
        try:
            self.assoc_id = read_varbytes(read)
        except struct_error:
            self.assoc_id = None

        return (our_address, our_services, nonce)

    def pack(self):
        '''Return the address and service flags as an encoded service.'''
        return ServicePacking.pack(self.address, self.services)

    def pack_with_timestamp(self, timestamp):
        '''Return an encoded service with a 4-byte timestamp prefix.'''
        return ServicePacking.pack_with_timestamp(self.address, self.services, timestamp)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return (
            f'BitcoinService({self.address}, services={self.services!r}, '
            f'user_agent={self.user_agent!r}, protocol_version={self.protocol_version}, '
            f'start_height={self.start_height:,d} relay={self.relay} '
            f'timestamp={self.timestamp}, assoc_id={self.assoc_id!r})'
        )


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
    def default(cls):
        return cls(5_000_000, [b'Default'])

    @classmethod
    def from_payload(cls, payload, logger=None):
        logger = logger or logging
        read = BytesIO(payload).read

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


class Node:
    '''Represents the state of a network, e.g., mainnet.'''

    def __init__(self, network, *, our_service=None):
        self.network = network
        self.our_service = our_service or BitcoinService()
        # Headers
        self.headers = Headers(network)

    async def listen(self, host, port, **kwargs):
        '''Listen for incoming connections.  kwargs are as for Session constructor.'''
        await tcp_server(host, port, self.handle_client, partial(self.handle_client, kwargs))

    async def handle_client(self, kwargs, client, address):
        service = BitcoinService(address=NetAddress(*address))
        session = Session(self, service, False, **kwargs)
        session.logger.info(f'connection from {service.address}')
        await session.maintain_connection(Connection(client))

    async def connect(self, service, **kwargs):
        '''Establish an outgoing connection to a service (a BitcoinService instance).
        The session spawns further connections as part of its association as necessary.
        '''
        connection = Connection(await open_connection(str(address.host), address.port))
        session = Session(self, service, connection, True, **kwargs)


class SessionLogger(logging.LoggerAdapter):

    '''Prepends a connection identifier to a logging message.'''
    def process(self, msg, kwargs):
        peer_id = self.extra.get('peer_id', 'unknown')
        return f'[{peer_id}] {msg}', kwargs


def random_nonce():
    '''A nonce suitable for a PING or VERSION messages.'''
    # bitcoind doesn't like zero nonces
    while True:
        nonce = urandom(8)
        if nonce != ZERO_NONCE:
            return nonce


class Session:
    '''Represents a single logical connection (an association) to a peer.  This can consist of
    multiple actual connections to the peer.  The peer determines on which connection a
    message is sent, and tracks state across the associated connections.

    If a client wishes to maintain several associations with the same address, it must be
    done with separate Session objects.
    '''

    def __init__(self, node, service, connection, is_outgoing, *,
                 protoconf=None,
                 perform_handshake=True,
                 send_protoconf=True,
                 sync_headers=True):
        self.node = node
        self.their_service = service
        self.connection = connection
        self.is_outgoing = is_outgoing
        self.our_protoconf = protoconf or Protoconf.default()
        self._perform_handshake = perform_handshake
        self._send_protoconf = send_protoconf
        self.sync_headers = sync_headers

        # State
        self.version_sent = False
        self.version_received = Event()
        self.verack_received = Event()
        self.headers_synced = Event()
        self.protoconf_sent = False
        self.their_protoconf = None
        self.nonce = random_nonce()

        # Logging
        logger = logging.getLogger('Session')
        context = {'peer_id': f'{service.address}'}
        self.logger = SessionLogger(logger, context)
        self.debug = logger.isEnabledFor(logging.DEBUG)

    async def close(self):
        await self.connection.close()
        self.connection = None

    async def maintain_connection(self):
        '''Maintains the main connection.'''
        connection = self.connection
        async with TaskGroup() as group:
            await group.spawn(self.recv_messages_loop, connection)
            await group.spawn(self.send_messages_loop, connection)
            if self._perform_handshake:
                await group.spawn(self.perform_handshake, connection)
            if self._send_protoconf:
                await group.spawn(self.send_protoconf)
            if self.sync_headers:
                await group.spawn(self.get_headers)

            async for task in group:
                task.result    # pylint:disable=W0104

    async def send_messages_loop(self, connection):
        '''Handle sending the queue of messages.  This sends all messages except the initial
        version / verack handshake.
        '''
        await self.verack_received.wait()

        send = connection.send
        while True:
            # FIXME: handle extended messages
            header, payload = await connection.outgoing_messages.get()
            if len(payload) + len(header) <= 536:
                await send(header + payload)
            else:
                await send(header)
                await send(payload)

    async def recv_messages_loop(self, connection):
        '''Read messages from a stream and pass them to handlers for processing.'''
        while True:
            header = 'incoming'
            try:
                header = await MessageHeader.from_stream(connection.recv_exactly)
                await self.handle_message(connection, header)
            except EOFError:
                self.logger.info('connection closed remotely')
                raise
            except ForceDisconnectError as e:
                self.logger.error(f'fatal protocol error, disconnecting: {e}')
                raise
            except ProtocolError as e:
                self.logger.error(f'protocol error: {e}')
            except Exception:
                self.logger.exception(f'error handling {header} message')

    async def _send_unqueued(self, connection, command, payload):
        '''Send a command without queueing.  For use with handshake negotiation.'''
        self.logger.debug(f'sending unqueued {command} message')
        header = MessageHeader.std_bytes(self.node.network.magic, command, payload)
        await connection.send(header + payload)

    def log_service_details(self, serv, headline):
        self.logger.info(headline)
        self.logger.info(f'    user_agent={serv.user_agent} services={serv.services!r}')
        self.logger.info(f'    protocol={serv.protocol_version} height={serv.start_height:,d}  '
                         f'relay={serv.relay} timestamp={serv.timestamp} assoc_id={serv.assoc_id}')

    async def perform_handshake(self, connection):
        '''Perform the initial handshake.  Send version and verack messages, and wait until a
        verack is received back.'''
        if not self.is_outgoing:
            # Incoming connections wait for version message first
            await self.version_received.wait()

        # Send version message with our current height
        our_service = self.node.our_service
        our_service.start_height = self.node.headers.height
        self.log_service_details(our_service, 'sending version message:')
        payload = our_service.to_version_payload(self.their_service.address, self.nonce)
        await self._send_unqueued(connection, MessageHeader.VERSION, payload)

        self.version_sent = True
        if self.is_outgoing:
            # Outoing connections wait now
            await self.version_received.wait()

        # Send verack
        await self._send_unqueued(connection, MessageHeader.VERACK, b'')

        # Handhsake is complete once verack is received
        await self.verack_received.wait()

    def connection_for_command(self, _command):
        return self.connection

    async def send_message(self, command, payload):
        '''Send a command and its payload.'''
        connection = self.connection_for_command(command)
        header = MessageHeader.std_bytes(self.node.network.magic, command, payload)
        await connection.outgoing_messages.put((header, payload))

    async def handle_message(self, connection, header):
        if self.debug:
            self.logger.debug(f'<- {header} payload {header.payload_len:,d} bytes')

        magic = self.node.network.magic
        if header.magic != magic:
            raise ForceDisconnectError(f'bad magic: got 0x{header.magic.hex()} '
                                       f'expected 0x{magic.hex()}')

        if not self.verack_received.is_set():
            if header.command_bytes not in (MessageHeader.VERSION, MessageHeader.VERACK):
                raise ProtocolError(f'{header} command received before handshake finished')

        command = header.command()

        if header.is_extended:
            # FIXME
            pass

        # FIXME: handle large payloads in a streaming fashion

        # Consume the payload
        payload = await connection.recv_exactly(header.payload_len)
        handler = getattr(self, f'on_{command}', None)
        if not handler:
            if self.debug:
                self.logger.debug(f'ignoring unhandled {command} command')
            return

        if not header.is_extended and header.payload_checksum(payload) != header.checksum:
            # Maybe force disconnect if we get too many bad checksums in a short time
            error = ProtocolError if self.verack_received.is_set() else ForceDisconnectError
            raise error(f'bad checksum for {header} command')

        await handler(payload)

    # Call to request various things from the peer

    async def get_addr(self):
        '''Call to request network nodes from the peer.'''

    async def get_data(self, items):
        '''Request various items from the peer.'''

    async def get_block(self, block_hash):
        '''Call to request the block with the given hash.'''

    async def get_headers(self, chain=None):
        '''Send a request to get headers with the chain's block locator.  If chain is None,
        the logest chain is used.

        Calling this with no argument forms a loop with on_headers() whose eventual effect
        is to synchronize the peer's headers.
        '''
        self.headers_synced.clear()
        locator = (chain or self.node.headers.longest_chain()).block_locator()
        payload = pack_block_locator(self.node.our_service.protocol_version, locator)
        if self.debug:
            self.logger.debug(f'requesting headers; locator has {len(locator)} entries')
        await self.send_message(MessageHeader.GETHEADERS, payload)

    # Callbacks when certain messages are received.

    async def on_addr(self, services):
        '''Called when an addr message is received.'''

    async def on_block(self, raw):
        '''Called when a block is received.'''

    async def on_headers(self, payload):
        '''Handle getting a bunch of headers.'''
        raw_headers = unpack_headers(payload)
        if len(raw_headers) > 2000:
            self.logger.warning(f'{len(raw_headers):,d} headers in headers message')

        # Synchronized?
        headers = self.node.headers
        if not raw_headers:
            if self.debug:
                self.logger.debug(f'headers synchronized to height {headers.height}')
            await self.headers_synced.set()
            return

        prev_hash = header_prev_hash(raw_headers[0])
        chain, height = headers.lookup(prev_hash)
        if chain is None:
            self.logger.error(f'on_headers: {hash_to_hex_str(prev_hash)} not present')
            return
        if self.debug:
            self.logger.debug(f'connecting {len(raw_headers):,d} block headers '
                              f'starting at height {height + 1:,d}')

        for raw_header in raw_headers:
            if prev_hash != header_prev_hash(raw_header):
                raise ProtocolError('headers do not form a chain')
            chain, prev_hash = headers.connect(raw_header)

        await self.get_headers(chain)

    async def on_inv(self, items):
        '''Called when an inv message is received advertising availability of various objects.'''

    async def on_tx(self, raw):
        '''Called when a tx is received.'''

    async def on_version(self, payload):
        '''Called when a version message is received.   their_service has been updated as
        they report it (except the address is unchanged).'''
        if self.version_received.is_set():
            raise ProtocolError('duplicate version message')
        await self.version_received.set()
        _, _, nonce = self.their_service.read_version_payload(payload)
        if nonce == self.nonce:
            raise ForceDisconnectError('connected to ourself')
        self.log_service_details(self.their_service, 'received version message:')

    async def on_verack(self, payload):
        if not self.version_sent:
            raise ProtocolError('verack message received before version message sent')
        if self.verack_received.is_set():
            self.logger.error('duplicate verack message')
        if payload:
            self.logger.error('verack message has payload')
        await self.verack_received.set()

    async def on_protoconf(self, payload):
        '''Called when a protoconf message is received.'''
        if self.their_protoconf:
            raise ProtocolError('duplicate protoconf message received')
        self.their_protoconf = Protoconf.from_payload(payload, self.logger)

    async def send_protoconf(self):
        if self.protoconf_sent:
            self.logger.warning('protoconf message already sent')
            return
        self.protoconf_sent = True
        await self.send_message(MessageHeader.PROTOCONF,
                                self.our_protoconf.payload())


class Connection:

    def __init__(self, sock):
        self.sock = sock
        self.outgoing_messages = Queue()

    async def close(self):
        await self.sock.close()

    async def send(self, data):
        await self.sock.sendall(data)

    async def recv_exactly(self, nbytes):
        recv = self.sock.recv
        parts = []
        while nbytes > 0:
            try:
                part = await recv(nbytes)
            except CancelledError as e:
                e.bytes_read = b''.join(parts)
                raise
            if not part:
                e = EOFError('unexpected end of data')
                e.bytes_read = b''.join(parts)
                raise e
            parts.append(part)
            nbytes -= len(part)
        return b''.join(parts)
