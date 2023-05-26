import os
import random
import time
from curio import Queue, sleep, spawn, TaskGroup
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address

import pytest

from bitcoinx import (
    Bitcoin, BitcoinTestnet, double_sha256, Headers, pack_varint, _version_str, NetAddress
)
from bitcoinx.net import *
from bitcoinx.net import ServicePacking
from bitcoinx.errors import ProtocolError, ForceDisconnectError

from .test_work import mainnet_first_2100


mainnet_headers = mainnet_first_2100()


pack_tests = (
    ('[1a00:23c6:cf86:6201:3cc8:85d1:c41f:9bf6]:8333', ServiceFlags.NODE_NONE,
     bytes(8) + b'\x1a\x00#\xc6\xcf\x86b\x01<\xc8\x85\xd1\xc4\x1f\x9b\xf6 \x8d'),
    ('1.2.3.4:56', ServiceFlags.NODE_NETWORK,
     b'\1' + bytes(17) + b'\xff\xff\1\2\3\4\0\x38'),
)

pack_ts_tests = (
    ('[1a00:23c6:cf86:6201:3cc8:85d1:c41f:9bf6]:8333', ServiceFlags.NODE_NETWORK,
     123456789,'15cd5b0701000000000000001a0023c6cf8662013cc885d1c41f9bf6208d'),
    ('100.101.102.103:104', ServiceFlags.NODE_NONE, 987654321,
     'b168de3a000000000000000000000000000000000000ffff646566670068'),
)

X_address = NetAddress.from_string('1.2.3.4:5678')
X_protoconf = Protoconf(2_000_000, [b'Default', b'BlockPriority'])
X_service = BitcoinService(
    services=ServiceFlags.NODE_NETWORK,
    address = X_address,
    protocol_version=80_000,
    user_agent='/foobar:1.0/',
    relay=False,
    timestamp=500_000,
    assoc_id=b'Default',
    start_height=5,
)
X_node = Node(Bitcoin, our_service=X_service)
Y_node = Node(Bitcoin)
Y_node.headers = mainnet_headers
testnet_node = Node(BitcoinTestnet)


class TestServicePacking:

    @pytest.mark.parametrize('address,services,result', pack_tests)
    def test_pack(self, address, services, result):
        assert ServicePacking.pack(NetAddress.from_string(address), services) == result

    @pytest.mark.parametrize('address,services,ts,result', pack_ts_tests)
    def test_pack_with_timestamp(self, address, services, ts, result):
        addr = NetAddress.from_string(address)
        assert ServicePacking.pack_with_timestamp(addr, services, ts) == bytes.fromhex(result)

    @pytest.mark.parametrize('address,services,result', pack_tests)
    def test_unpack(self, address, services, result):
        assert ServicePacking.unpack(result) == (NetAddress.from_string(address), services)

    @pytest.mark.parametrize('address,services,result', pack_tests)
    def test_read(self, address, services, result):
        assert ServicePacking.read(BytesIO(result).read) == (
            NetAddress.from_string(address), services)

    @pytest.mark.parametrize('address,services,ts,result', pack_ts_tests)
    def test_read_with_timestamp(self, address, services, ts, result):
        read = BytesIO(bytes.fromhex(result)).read
        addr, srvcs, timestamp = ServicePacking.read_with_timestamp(read)
        assert ts == timestamp
        assert services == srvcs
        assert addr == NetAddress.from_string(address)

    def test_read_addrs(self):
        raw = bytearray()
        raw += pack_varint(len(pack_ts_tests))
        for address, flags, ts, packed in pack_ts_tests:
            raw += bytes.fromhex(packed)
        result = ServicePacking.read_addrs(BytesIO(raw).read)
        assert len(result) == len(pack_ts_tests)
        for n, (addr, srvcs, ts) in enumerate(result):
            address, services, timestamp, packed = pack_ts_tests[n]
            assert addr == NetAddress.from_string(address)
            assert srvcs == services
            assert ts == timestamp


class TestBitcoinService:

    def test_eq(self):
        assert BitcoinService(address=NetAddress('1.2.3.4', 35),
                              services=ServiceFlags.NODE_NETWORK) == \
            BitcoinService(address='1.2.3.4:35', services=ServiceFlags.NODE_NETWORK)
        assert BitcoinService(address='1.2.3.4:35', services=ServiceFlags.NODE_NETWORK) != \
            BitcoinService(address='1.2.3.4:36', services=ServiceFlags.NODE_NETWORK)
        assert X_service == BitcoinService(address=X_address)

    def test_hashable(self):
        assert 1 == len({BitcoinService(address='1.2.3.5:35', services=ServiceFlags.NODE_NONE),
                         BitcoinService(address='1.2.3.5:35', services=ServiceFlags.NODE_NETWORK)})

    def test_str_repr(self):
        service = BitcoinService(address='1.2.3.4:5', services=1)
        assert repr(service) == str(service)

    def test_service_set(self):
        service = X_service
        assert service.address == X_address
        assert service.services == ServiceFlags.NODE_NETWORK
        assert service.protocol_version == 80_000
        assert service.user_agent == '/foobar:1.0/'
        assert service.relay is False
        assert service.timestamp == 500_000
        assert service.assoc_id == b'Default'
        assert service.start_height == 5

    def test_service_default(self):
        service = BitcoinService()
        assert service.address == NetAddress('::', 0, check_port=False)
        assert service.services == ServiceFlags.NODE_NONE
        assert service.protocol_version == 70_015
        assert service.user_agent == f'/bitcoinx/{_version_str}'
        assert service.relay is True
        assert service.timestamp is None
        assert service.assoc_id is None
        assert service.start_height == 0

    def test_service_node_service(self):
        service = Node(Bitcoin).our_service
        assert service.address == NetAddress('::', 0, check_port=False)
        assert service.services == ServiceFlags.NODE_NONE
        assert service.protocol_version == 70_015
        assert service.user_agent == f'/bitcoinx/{_version_str}'
        assert service.relay is True
        assert service.timestamp is None
        assert service.assoc_id is None
        assert service.start_height == 0


protoconf_tests = [
    (2_000_000, [b'foo', b'bar'], '0280841e0007666f6f2c626172'),
]

class TestProtoconf:

    @pytest.mark.parametrize('max_payload', (Protoconf.LEGACY_MAX_PAYLOAD, 10_000_000))
    def test_max_inv_elements(self, max_payload):
        assert Protoconf(max_payload, b'').max_inv_elements() == (max_payload - 9) // (4 + 32)

    @pytest.mark.parametrize('max_payload, policies, result', protoconf_tests)
    def test_payload(self, max_payload, policies, result):
        assert Protoconf(max_payload, policies).payload() == bytes.fromhex(result)

    @pytest.mark.parametrize('max_payload, policies, result', protoconf_tests)
    def test_from_payload(self, max_payload, policies, result):
        pc = Protoconf.from_payload(bytes.fromhex(result))
        assert pc.max_payload == max_payload
        assert pc.stream_policies == policies

    @pytest.mark.parametrize('N', (0, 1))
    def test_bad_field_count(self, N):
        raw = bytearray(Protoconf(2_000_000, [b'Default']).payload())
        raw[0] = N
        with pytest.raises(ProtocolError):
            Protoconf.from_payload(raw)

    def test_bad_max_payload(self):
        raw = Protoconf(Protoconf.LEGACY_MAX_PAYLOAD - 1, [b'Default']).payload()
        with pytest.raises(ProtocolError):
            Protoconf.from_payload(raw)

    def test_logging(self, caplog):
        raw = bytearray(Protoconf(2_000_000, [b'Default']).payload())
        raw[0] = 3
        with caplog.at_level('WARNING'):
            Protoconf.from_payload(raw)
        assert 'unexpected field count' in caplog.text


class Dribble:
    '''Utility class for testing.'''

    def __init__(self, raw):
        self.raw = raw
        self.cursor = 0

    async def recv_exactly(self, size):
        result = self.raw[self.cursor: self.cursor + size]
        self.cursor += size
        return result

    @staticmethod
    def lengths(total):
        lengths = []
        cursor = 0
        while cursor < total:
            length = min(random.randrange(1, total // 2), total - cursor)
            lengths.append(length)
            cursor += length
        return lengths

    @staticmethod
    def parts(raw):
        parts = []
        start = 0
        for length in Dribble.lengths(len(raw)):
            parts.append(raw[start: start+length])
            start += length
        return parts


std_header_tests = [
    (b'1234', b'0123456789ab', b'', b'12340123456789ab\0\0\0\0]\xf6\xe0\xe2'),
    (Bitcoin.magic, MessageHeader.ADDR, b'foobar',
     b'\xe3\xe1\xf3\xe8addr\0\0\0\0\0\0\0\0\6\0\0\0?,|\xca'),
]

ext_header_tests = [
    (b'1234', b'command\0\0\0\0\0', 5,
     b'1234extmsg\0\0\0\0\0\0\xff\xff\xff\xff\0\0\0\0'
     b'command\0\0\0\0\0\5\0\0\0\0\0\0\0'),
    (Bitcoin.magic, MessageHeader.BLOCK, 8_000_000_000,
     b'\xe3\xe1\xf3\xe8extmsg\0\0\0\0\0\0\xff\xff\xff\xff\0\0\0\0'
     b'block\0\0\0\0\0\0\0\0P\xd6\xdc\1\0\0\0'),
]


class TestMessageHeader:

    def basics(self):
        assert MessageHeader.STD_HEADER_SIZE == 28
        assert MessageHEader.EXT_HEADER_SIZE == 48

    @pytest.mark.parametrize("magic, command, payload, answer", std_header_tests)
    def test_std_bytes(self, magic, command, payload, answer):
        assert MessageHeader.std_bytes(magic, command, payload) == answer

    @pytest.mark.parametrize("magic, command, payload_len, answer", ext_header_tests)
    def test_ext_bytes(self, magic, command, payload_len, answer):
        assert MessageHeader.ext_bytes(magic, command, payload_len) == answer

    @pytest.mark.parametrize("magic, command, payload, answer", std_header_tests)
    def test_from_stream_std(self, kernel, magic, command, payload, answer):
        async def main():
            dribble = Dribble(answer)
            header = await MessageHeader.from_stream(dribble.recv_exactly)
            assert header.magic == magic
            assert header.command_bytes == command
            assert header.payload_len == len(payload)
            assert header.checksum == double_sha256(payload)[:4]
            assert header.is_extended is False

        kernel.run(main())

    @pytest.mark.parametrize("magic, command, payload_len, answer", ext_header_tests)
    def test_from_stream_ext(self, kernel, magic, command, payload_len, answer):
        async def main():
            dribble = Dribble(answer)
            header = await MessageHeader.from_stream(dribble.recv_exactly)
            assert header.magic == magic
            assert header.command_bytes == command
            assert header.payload_len == payload_len
            assert header.checksum == bytes(4)
            assert header.is_extended is True

        kernel.run(main())

    @pytest.mark.parametrize("raw", (
        b'1234extmsg\0\0\0\0\0\0\xfe\xff\xff\xff\0\0\0\0command\0\0\0\0\0\5\0\0\0\0\0\0\0',
        b'4567extmsg\0\0\0\0\0\0\xff\xff\xff\xff\0\0\1\0command\0\0\0\0\0\5\0\0\0\0\0\0\0',
    ))
    def test_from_stream_ext_bad(self, kernel, raw):
        async def main():
            dribble = Dribble(raw)
            with pytest.raises(ProtocolError):
                await MessageHeader.from_stream(dribble.recv_exactly)

        kernel.run(main())

    @pytest.mark.parametrize("command", ('addr', 'ping', 'sendheaders'))
    def test_str(self, command):
        command_bytes = getattr(MessageHeader, command.upper())
        header = MessageHeader(b'', command_bytes, 0, b'', False)
        assert str(header) == command

    def test_commands(self):
        for key, value in MessageHeader.__dict__.items():
            if isinstance(value, bytes):
                assert key.lower().encode() == value.rstrip(b'\0')


net_addresses = ['1.2.3.4', '4.3.2.1', '001:0db8:85a3:0000:0000:8a2e:0370:7334',
                 '2001:db8:85a3:8d3:1319:8a2e:370:7348']

def random_net_address():
    port = random.randrange(1024, 50000)
    address = random.choice(net_addresses)
    return NetAddress(address, port)


def random_service():
    address = random_net_address()
    return BitcoinService(address=address)


class FakePeer(Session):
    '''A fake peer handy for simulating connections.  Also fakes the Connection class with the
    send and recv_exactly methods.
    '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.remote_peer = None
        # Incoming message queue
        self.queue = Queue()
        self.residual = b''
        self.outgoing_messages = Queue()

    def connect_to(self, peer):
        self.remote_peer = peer
        peer.remote_peer = self

    async def recv_exactly(self, size):
        parts = []
        part = self.residual
        while True:
            size -= len(part)
            parts.append(part)
            if size <= 0:
                if size < 0:
                    self.residual = part[size:]
                    parts[-1] = part[:size]
                else:
                    self.residual = b''
                return b''.join(parts)
            part = await self.queue.get()
            if part is None:
                raise EOFError(b'', size)

    async def send(self, raw):
        put = self.remote_peer.queue.put
        for part in Dribble.parts(raw):
            await put(part)

    async def close_connection(self):
        await self.remote_peer.queue.put(None)

    @classmethod
    def random(cls, node, **kwargs):
        return cls(node, random_service(), **kwargs)


def setup_connection(out_peer=None, in_peer=None):
    out_peer = out_peer or FakePeer.random(X_node, is_outgoing=True, protoconf=X_protoconf)
    in_peer = in_peer or FakePeer.random(X_node, is_outgoing=False)
    out_peer.connect_to(in_peer)
    return (out_peer, in_peer)


async def run_connection(sessions, post_handshake=None):

    for session in sessions:
        task = await spawn(session.maintain_connection, session)
        session.connections.append((session, task))

    await sleep(0.02)

    if post_handshake:
        await post_handshake()
        await sleep(0.02)

    for session in sessions:
        await session.close()


class TestConnection:

    def test_handshake(self, kernel):
        async def main():
            in_peer = FakePeer.random(X_node, is_outgoing=False)
            out_peer = FakePeer.random(Y_node, is_outgoing=True)
            peers = setup_connection(out_peer, in_peer)
            await run_connection(peers)

            # Check all relevant details were correctly recorded in each node
            for check, other in ((in_peer, out_peer), (out_peer, in_peer)):
                assert check.version_received.is_set()
                assert check.verack_received.is_set()
                assert check.their_service is not None

                other_service = other.node.our_service
                assert check.their_service.address == check.their_service.address
                assert check.their_service.services == other_service.services
                assert check.their_service.protocol_version == other_service.protocol_version
                other_user_agent = other_service.user_agent or f'/bitcoinx:{_version_str}/'
                assert check.their_service.user_agent == other_user_agent
                assert check.their_service.start_height == other_service.start_height
                if other_service.timestamp is None:
                    assert abs(check.their_service.timestamp - time.time()) < 1
                else:
                    assert check.their_service.timestamp == other_service.timestamp
                assert check.their_service.relay == other_service.relay
                assert check.their_service.assoc_id == other_service.assoc_id
                assert check.their_protoconf == other.our_protoconf

        kernel.run(main())

    def test_self_connect(self, kernel):
        async def main():
            peer = FakePeer.random(X_node, is_outgoing=True)
            peer.connect_to(peer)
            with pytest.raises(ForceDisconnectError) as e:
                await run_connection([peer])
            assert 'connected to ourself' in str(e.value)

        kernel.run(main())

    def test_bad_magic(self, kernel):
        async def main():
            out_peer=FakePeer.random(testnet_node, is_outgoing=True)
            peers = setup_connection(out_peer)
            with pytest.raises(ForceDisconnectError) as e:
                await run_connection(peers)
                assert 'bad magic' in str(e.value)

        kernel.run(main())

    def test_bad_checksum(self, kernel):
        async def main():
            async def hijack_message(connection, header):
                header.checksum = bytes(4)
                await old_handler(connection, header)

            peers = setup_connection()
            out_peer, in_peer = peers
            old_handler = out_peer.handle_message
            out_peer.handle_message = hijack_message

            with pytest.raises(ForceDisconnectError) as e:
                await run_connection(peers)
            assert 'bad checksum for version command' in str(e.value)

        kernel.run(main())

    def test_unknown_command(self, kernel, caplog):
        async def main():
            async def send_unknown_message():
                await peers[0].send_message(b'foobar', b'')

            with caplog.at_level('DEBUG'):
                peers = setup_connection()
                await run_connection(peers, post_handshake=send_unknown_message)

            assert 'ignoring unhandled foobar command' in caplog.text

        kernel.run(main())


    def test_duplicate_version(self, kernel, caplog):
        async def main():
            async def send_version_message():
                payload = peers[0].node.our_service.to_version_payload(
                    peers[0].their_service.address, bytes(8))
                await peers[0].send_message(MessageHeader.VERSION, payload)

            peers = setup_connection()
            with caplog.at_level('ERROR'):
                await run_connection(peers, post_handshake=send_version_message)

            assert 'duplicate version message' in caplog.text

        kernel.run(main())

    def test_duplicate_verack(self, kernel, caplog):
        async def main():
            async def send_verack_message():
                await peers[0].send_message(MessageHeader.VERACK, b' ')

            peers = setup_connection()
            with caplog.at_level('ERROR'):
                await run_connection(peers, post_handshake=send_verack_message)

            assert 'duplicate verack message' in caplog.text
            assert 'verack message has payload' in caplog.text

        kernel.run(main())


    @pytest.mark.parametrize("peer_index", (0, 1))
    def test_verack_before_version(self, kernel, caplog, peer_index):
        async def main():
            peers = setup_connection()
            peer = peers[peer_index]
            await peer._send_unqueued(peer, MessageHeader.VERACK, b'')

            with caplog.at_level('ERROR'):
                await run_connection(peers)

            assert 'verack message received before version message sent' in caplog.text

        kernel.run(main())

    @pytest.mark.parametrize("peer_index", (0, 1))
    def test_protoconf_before_verack(self, kernel, caplog, peer_index):
        async def main():
            async def bad_on_version(*args):
                await on_version(*args)
                await peer._send_unqueued(peer, MessageHeader.PROTOCONF, b'')

            peers = setup_connection()
            peer = peers[peer_index]
            on_version = peer.on_version
            peer.on_version = bad_on_version

            with caplog.at_level('ERROR'):
                await run_connection(peers)

            assert 'protoconf command received before handshake finished' in caplog.text

        kernel.run(main())

    @pytest.mark.parametrize("peer_index", (0, 1))
    def test_premature_connection_closed(self, kernel, caplog, peer_index):
        async def main():
            peers = setup_connection()
            peer = peers[peer_index]

            with caplog.at_level('INFO'):
                with pytest.raises(EOFError) as e:
                    await run_connection(peers, post_handshake=peer.close_connection)

            assert 'connection closed remotely' in caplog.text

        kernel.run(main())
