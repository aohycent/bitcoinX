import asyncio
import os
import random
import time
from asyncio import Queue, create_task, sleep
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address

import pytest

from bitcoinx import Bitcoin, BitcoinTestnet, double_sha256, Headers, pack_varint
from bitcoinx.net import *
from bitcoinx.errors import ConnectionClosedError, ProtocolError, ForceDisconnectError

from .test_work import mainnet_first_2100


mainnet_headers = mainnet_first_2100()


##
## Tests for miscellaneous utlity functions
##


@pytest.mark.parametrize("hostname,answer", (
    ('', False),
    ('a', True),
    ('_', True),
    # Hyphens
    ('-b', False),
    ('a.-b', False),
    ('a-b', True),
    ('b-', False),
    ('b-.c', False),
    # Dots
    ('a.', True),
    ('a..', False),
    ('foo1.Foo', True),
    ('foo1..Foo', False),
    ('12Foo.Bar.Bax_', True),
    ('12Foo.Bar.Baz_12', True),
    # Numeric TLD
    ('foo1.123', False),
    ('foo1.d123', True),
    ('foo1.123d', True),
    # IP Addresses
    ('1.2.3.4', False),
    ('12::23', False),
    # 63 octets in part
    ('a.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.bar', True),
    # Over 63 octets in part
    ('a.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_1.bar', False),
    # Length
    (('a' * 62 + '.') * 4 + 'a', True),    # 253
    (('a' * 62 + '.') * 4 + 'ab', False),   # 254
))
def test_is_valid_hostname(hostname,answer):
    assert is_valid_hostname(hostname) == answer


@pytest.mark.parametrize("hostname", (2, b'1.2.3.4'))
def test_is_valid_hostname_bad(hostname):
    with pytest.raises(TypeError):
        is_valid_hostname(hostname)


@pytest.mark.parametrize("host,answer", (
    ('1.2.3.4', IPv4Address('1.2.3.4')),
    ('12:32::', IPv6Address('12:32::')),
    (IPv4Address('8.8.8.8'), IPv4Address('8.8.8.8')),
    (IPv6Address('::1'), IPv6Address('::1')),
    ('foo.bar.baz.', 'foo.bar.baz.'),
))
def test_classify_host(host, answer):
    assert classify_host(host) == answer


@pytest.mark.parametrize("host", (2, b'1.2.3.4'))
def test_classify_host_bad_type(host):
    with pytest.raises(TypeError):
        classify_host(host)


@pytest.mark.parametrize("host", ('', 'a..', 'b-', 'a' * 64))
def test_classify_host_bad(host):
    with pytest.raises(ValueError):
        classify_host(host)

@pytest.mark.parametrize("port,answer", (
    ('2', 2),
    (65535, 65535),
    (0, ValueError),
    (-1, ValueError),
    (65536, ValueError),
    (b'', TypeError),
    (2.0, TypeError),
    ('2a', ValueError),
))
def test_validate_port(port, answer):
    if isinstance(answer, type) and issubclass(answer, Exception):
        with pytest.raises(answer):
            validate_port(port)
    else:
        assert validate_port(port) == answer


@pytest.mark.parametrize("protocol,answer", (
    ('TCP', 'tcp'),
    ('http', 'http'),
    ('Ftp.-xbar+', 'ftp.-xbar+'),
    (b'', TypeError),
    (2, TypeError),
    ('', ValueError),
    ('a@b', ValueError),
    ('a:b', ValueError),
    ('[23]', ValueError),
))
def test_validate_protocol(protocol, answer):
    if isinstance(answer, type) and issubclass(answer, Exception):
        with pytest.raises(answer):
            validate_protocol(protocol)
    else:
        assert validate_protocol(protocol) == answer


class TestNetAddress:

    @pytest.mark.parametrize("host,port,answer,host_type",(
        ('foo.bar', '23', 'foo.bar:23', str),
        ('foo.bar', 23, 'foo.bar:23', str),
        ('foo.bar', 23.0, TypeError, None),
        ('::1', 15, '[::1]:15', IPv6Address),
        ('5.6.7.8', '23', '5.6.7.8:23', IPv4Address),
        ('5.6.7.8.9', '23', ValueError, None),
        ('[::1]', '23', ValueError, None),
        ('[::1]', 0, ValueError, None),
        ('[::1]', 65536, ValueError, None),
    ))
    def test_constructor(self, host,port,answer,host_type):
        if isinstance(answer, type) and issubclass(answer, Exception):
            with pytest.raises(answer):
                NetAddress(host, port)
        else:
            address = NetAddress(host, port)
            assert str(address) == answer
            assert isinstance(address.host, host_type)

    def test_eq(self):
        assert NetAddress('1.2.3.4', 23) == NetAddress('1.2.3.4', 23)
        assert NetAddress('1.2.3.4', 23) == NetAddress('1.2.3.4', '23')
        assert NetAddress('1.2.3.4', 23) != NetAddress('1.2.3.4', 24)
        assert NetAddress('1.2.3.4', 24) != NetAddress('1.2.3.5', 24)
        assert NetAddress('foo.bar', 24) != NetAddress('foo.baz', 24)

    def test_hashable(self):
        assert len({NetAddress('1.2.3.4', 23), NetAddress('1.2.3.4', '23')}) == 1

    @pytest.mark.parametrize("host,port,answer",(
        ('foo.bar', '23', "NetAddress('foo.bar:23')"),
        ('foo.bar', 23, "NetAddress('foo.bar:23')"),
        ('::1', 15, "NetAddress('[::1]:15')"),
        ('5.6.7.8', '23', "NetAddress('5.6.7.8:23')"),
    ))
    def test_repr(self, host, port, answer):
        assert repr(NetAddress(host, port)) == answer

    @pytest.mark.parametrize("string,default_func,answer",(
        ('foo.bar:23', None, NetAddress('foo.bar', 23)),
        (':23', NetAddress.default_host('localhost'), NetAddress('localhost', 23)),
        (':23', None, ValueError),
        (':23', NetAddress.default_port(23), ValueError),
        ('foo.bar', NetAddress.default_port(500), NetAddress('foo.bar', 500)),
        ('foo.bar:', NetAddress.default_port(500), NetAddress('foo.bar', 500)),
        ('foo.bar', NetAddress.default_port(500), NetAddress('foo.bar', 500)),
        (':', NetAddress.default_host_and_port('localhost', 80), NetAddress('localhost', 80)),
        ('::1:', None, ValueError),
        ('::1', None, ValueError),
        ('[::1:22', None, ValueError),
        ('[::1]:22', NetAddress.default_port(500), NetAddress('::1', 22)),
        ('[::1]:', NetAddress.default_port(500), NetAddress('::1', 500)),
        ('[::1]', NetAddress.default_port(500), NetAddress('::1', 500)),
        ('1.2.3.4:22', None, NetAddress('1.2.3.4', 22)),
        ('1.2.3.4:', NetAddress.default_port(500), NetAddress('1.2.3.4', 500)),
        ('1.2.3.4', NetAddress.default_port(500), NetAddress('1.2.3.4', 500)),
        ('localhost', NetAddress.default_port(500), NetAddress('localhost', 500)),
        ('1.2.3.4', NetAddress.default_host('localhost'), ValueError),
        (2, None, TypeError),
        (b'', None, TypeError),
    ))
    def test_from_string(self, string, default_func, answer):
        if isinstance(answer, type) and issubclass(answer, Exception):
            with pytest.raises(answer):
                NetAddress.from_string(string,default_func=default_func)
        else:
            assert NetAddress.from_string(string,default_func=default_func) == answer


    @pytest.mark.parametrize("address,answer",(
        (NetAddress('foo.bar', 23), 'foo.bar:23'),
        (NetAddress('abcd::dbca', 40), '[abcd::dbca]:40'),
        (NetAddress('1.2.3.5', 50000), '1.2.3.5:50000'),
    ))
    def test_str(self, address, answer):
        assert str(address) == answer


    @pytest.mark.parametrize("attr", ('host', 'port'))
    def test_immutable(self, attr):
        address = NetAddress('foo.bar', 23)
        with pytest.raises(AttributeError):
            setattr(address, attr, 'foo')
        setattr(address, 'foo', '')


class TestService:

    @pytest.mark.parametrize("protocol,address,answer", (
        ('tcp', 'domain.tld:8000', Service('tcp', NetAddress('domain.tld', 8000))),
        ('SSL', NetAddress('domain.tld', '23'), Service('ssl', NetAddress('domain.tld', 23))),
        ('SSL', '[::1]:80', Service('SSL', NetAddress('::1', 80))),
        ('ws', '1.2.3.4:80', Service('ws', NetAddress('1.2.3.4', 80))),
        (4, '1.2.3.4:80', TypeError),
        ('wss', '1.2.3.4:', ValueError),
    ))
    def test_constructor(self, protocol, address, answer):
        if isinstance(answer, type) and issubclass(answer, Exception):
            with pytest.raises(answer):
                Service(protocol, address)
        else:
            assert Service(protocol, address) == answer

    def test_eq(self):
        assert Service('http', '1.2.3.4:23') == Service(
            'HTTP', NetAddress(IPv4Address('1.2.3.4'), 23))
        assert Service('https', '1.2.3.4:23') != Service('http', '1.2.3.4:23')
        assert Service('https', '1.2.3.4:23') != Service('https', '1.2.3.4:22')

    def test_hashable(self):
        assert 1 == len({Service('http', '1.2.3.4:23'),
                         Service('HTTP', NetAddress(IPv4Address('1.2.3.4'), 23))})

    @pytest.mark.parametrize("protocol,address,answer", (
        ('TCP', 'foo.bar:23', 'tcp://foo.bar:23'),
        ('httpS', NetAddress('::1', 80), 'https://[::1]:80'),
        ('ws', NetAddress('1.2.3.4', '50000'), 'ws://1.2.3.4:50000'),
    ))
    def test_str(self, protocol, address, answer):
        assert str(Service(protocol, address)) == answer

    @pytest.mark.parametrize("protocol, address, answer", (
        ('TCP', 'foo.bar:23', "Service('tcp', 'foo.bar:23')"),
        ('httpS', NetAddress('::1', 80), "Service('https', '[::1]:80')"),
        ('ws', NetAddress('1.2.3.4', '50000'), "Service('ws', '1.2.3.4:50000')"),
    ))
    def test_repr(self, protocol, address, answer):
        assert repr(Service(protocol, address)) == answer

    def test_attributes(self):
        service = Service('HttpS', '[::1]:80')
        assert service.protocol == 'https'
        assert service.address == NetAddress('::1', 80)
        assert service.host == IPv6Address('::1')
        assert service.port == 80

    def default_func(protocol, kind):
        if kind == ServicePart.PROTOCOL:
            return 'SSL'
        if kind == ServicePart.HOST:
            return {'ssl': 'ssl_host.tld', 'tcp': 'tcp_host.tld'}.get(protocol)
        return {'ssl': 443, 'tcp': '80', 'ws': 50001}.get(protocol)

    @pytest.mark.parametrize("service,default_func,answer", (
        ('HTTP://foo.BAR:80', None, Service('http', NetAddress('foo.BAR', 80))),
        ('ssl://[::1]:80', None, Service('ssl', '[::1]:80')),
        ('ssl://5.6.7.8:50001', None, Service('ssl', NetAddress('5.6.7.8', 50001))),
        ('ssl://foo.bar', None, ValueError),
        ('ssl://:80', None, ValueError),
        ('foo.bar:80', None, ValueError),
        ('foo.bar', None, ValueError),
        (2, None, TypeError),
        # With default funcs
        ('localhost:80', default_func, Service('ssl', 'localhost:80')),
        ('localhost', default_func, Service('ssl', 'localhost:443')),
        ('WS://domain.tld', default_func, Service('ws', 'domain.tld:50001')),
        # TCP has a default host and port
        ('tcp://localhost', default_func, Service('tcp', 'localhost:80')),
        ('tcp://:', default_func, Service('tcp', 'tcp_host.tld:80')),
        ('tcp://', default_func, Service('tcp', 'tcp_host.tld:80')),
        # As TCP has a default host and port it is interpreted as a protocol not a host
        ('tcp', default_func, Service('tcp', 'tcp_host.tld:80')),
        # WS has no default host
        ('ws://', default_func, ValueError),
        ('ws://:45', default_func, ValueError),
        ('ws://localhost', default_func, Service('ws', 'localhost:50001')),
        # WS alone is interpreted as a host name as WS protocol has no default host
        ('ws', default_func, Service('ssl', 'ws:443')),
        # Default everything
        ('', default_func, Service('ssl', 'ssl_host.tld:443')),
    ))
    def test_from_string(self, service, default_func, answer):
        if isinstance(answer, type) and issubclass(answer, Exception):
            with pytest.raises(answer):
                Service.from_string(service, default_func=default_func)
        else:
            assert Service.from_string(service, default_func=default_func) == answer

    @pytest.mark.parametrize("attr", ('host', 'port', 'address', 'protocol'))
    def test_immutable(self, attr):
        service = Service.from_string('https://foo.bar:8000')
        with pytest.raises(AttributeError):
            setattr(service, attr, '')
        setattr(service, 'foo', '')


pack_tests = (
    ('[1a00:23c6:cf86:6201:3cc8:85d1:c41f:9bf6]:8333', BitcoinService.Service.NODE_NONE,
     bytes(8) + b'\x1a\x00#\xc6\xcf\x86b\x01<\xc8\x85\xd1\xc4\x1f\x9b\xf6 \x8d'),
    ('1.2.3.4:56', BitcoinService.Service.NODE_NETWORK,
     b'\1' + bytes(17) + b'\xff\xff\1\2\3\4\0\x38'),
)

pack_ts_tests = (
    ('[1a00:23c6:cf86:6201:3cc8:85d1:c41f:9bf6]:8333', BitcoinService.Service.NODE_NETWORK,
     123456789,'15cd5b0701000000000000001a0023c6cf8662013cc885d1c41f9bf6208d'),
    ('100.101.102.103:104', BitcoinService.Service.NODE_NONE, 987654321,
     'b168de3a000000000000000000000000000000000000ffff646566670068'),
)


class TestBitcoinService:

    def test_constructor_bad(self):
        with pytest.raises(ValueError):
            BitcoinService('foo.bar:2', BitcoinService.Service.NODE_NONE)

    def test_eq(self):
        assert BitcoinService(NetAddress('1.2.3.4', 35), BitcoinService.Service.NODE_NETWORK) == \
            BitcoinService('1.2.3.4:35', BitcoinService.Service.NODE_NETWORK)
        assert BitcoinService('1.2.3.4:35', BitcoinService.Service.NODE_NETWORK) != \
            BitcoinService('1.2.3.4:36', BitcoinService.Service.NODE_NETWORK)
        assert BitcoinService(NetAddress('1.2.3.4', 35), BitcoinService.Service.NODE_NETWORK) != \
            BitcoinService(NetAddress('1.2.3.5', 35), BitcoinService.Service.NODE_NETWORK)
        assert BitcoinService('1.2.3.4:35', BitcoinService.Service.NODE_NETWORK) != \
            BitcoinService('1.2.3.5:35', BitcoinService.Service.NODE_NONE)

    def test_hashable(self):
        assert 1 == len({BitcoinService('1.2.3.5:35', BitcoinService.Service.NODE_NONE),
                         BitcoinService('1.2.3.5:35', BitcoinService.Service.NODE_NONE)})

    @pytest.mark.parametrize('address,services,result', pack_tests)
    def test_pack(self, address, services, result):
        assert BitcoinService(address, services).pack() == result

    @pytest.mark.parametrize('address,services,ts,result', pack_ts_tests)
    def test_pack_with_timestamp(self, address, services, ts, result):
        assert BitcoinService(address, services).pack_with_timestamp(ts) == bytes.fromhex(result)

    @pytest.mark.parametrize('address,services,result', pack_tests)
    def test_unpack(self, address, services, result):
        assert BitcoinService.unpack(result) == BitcoinService(address, services)

    @pytest.mark.parametrize('address,services,result', pack_tests)
    def test_read(self, address, services, result):
        assert BitcoinService.read(BytesIO(result).read) == BitcoinService(address, services)

    @pytest.mark.parametrize('address,services,ts,result', pack_ts_tests)
    def test_read_with_timestamp(self, address, services, ts, result):
        read = BytesIO(bytes.fromhex(result)).read
        service, timestamp = BitcoinService.read_with_timestamp(read)
        assert ts == timestamp
        assert service == BitcoinService(address, services)

    def test_read_addrs(self):
        raw = bytearray()
        raw += pack_varint(len(pack_ts_tests))
        for address, flags, ts, packed in pack_ts_tests:
            raw += bytes.fromhex(packed)
        result = BitcoinService.read_addrs(BytesIO(raw).read)
        assert len(result) == len(pack_ts_tests)
        for n, (service, ts) in enumerate(result):
            address, flags, timestamp, packed = pack_ts_tests[n]
            assert ts == timestamp
            assert service == BitcoinService(address, flags)

    def test_str_repr(self):
        service = BitcoinService('1.2.3.4:5', 1)
        assert str(service) == '1.2.3.4:5 <Service.NODE_NETWORK: 1>'
        assert repr(service) == "BitcoinService('1.2.3.4:5', <Service.NODE_NETWORK: 1>)"


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
    def test_read(self, max_payload, policies, result):
        pc = Protoconf.read(BytesIO(bytes.fromhex(result)).read)
        assert pc.max_payload == max_payload
        assert pc.stream_policies == policies

    @pytest.mark.parametrize('N', (0, 1))
    def test_bad_field_count(self, N):
        raw = bytearray(Protoconf(2_000_000, [b'Default']).payload())
        raw[0] = N
        with pytest.raises(ProtocolError):
            Protoconf.read(BytesIO(raw).read)

    def test_bad_max_payload(self):
        raw = Protoconf(Protoconf.LEGACY_MAX_PAYLOAD - 1, [b'Default']).payload()
        with pytest.raises(ProtocolError):
            Protoconf.read(BytesIO(raw).read)

    def test_logging(self, caplog):
        raw = bytearray(Protoconf(2_000_000, [b'Default']).payload())
        raw[0] = 3
        with caplog.at_level('WARNING'):
            Protoconf.read(BytesIO(raw).read)
        assert 'unexpected field count' in caplog.text


class Dribble:
    '''Utility class for testing.'''

    def __init__(self, raw):
        self.raw = raw
        self.cursor = 0

    def stream(self):
        return Connection('', self.recv, None)

    async def recv(self, size):
        old_cursor = self.cursor
        count = min(random.randrange(0, size) + 1, len(self.raw) - self.cursor)
        self.cursor += count
        return self.raw[old_cursor: old_cursor + count]

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


class TestConnection:

    @pytest.mark.parametrize("N", (5, 32, 100))
    @pytest.mark.asyncio
    async def test_recv_exact(self, N):
        dribble = Dribble(memoryview(os.urandom(N)))
        stream = dribble.stream()
        assert dribble.raw == await stream.recv_exact(N)

        dribble.cursor = 0
        with pytest.raises(ConnectionClosedError):
            await stream.recv_exact(N + 1)

        dribble.cursor = 0
        parts = [await stream.recv_exact(length) for length in Dribble.lengths(N)]
        assert b''.join(parts) == dribble.raw


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
    @pytest.mark.asyncio
    async def test_from_stream_std(self, magic, command, payload, answer):
        dribble = Dribble(answer)
        header = await MessageHeader.from_stream(dribble.stream())
        assert header.magic == magic
        assert header.command_bytes == command
        assert header.payload_len == len(payload)
        assert header.checksum == double_sha256(payload)[:4]
        assert header.is_extended is False

    @pytest.mark.parametrize("magic, command, payload_len, answer", ext_header_tests)
    @pytest.mark.asyncio
    async def test_from_stream_ext(self, magic, command, payload_len, answer):
        dribble = Dribble(answer)
        header = await MessageHeader.from_stream(dribble.stream())
        assert header.magic == magic
        assert header.command_bytes == command
        assert header.payload_len == payload_len
        assert header.checksum == bytes(4)
        assert header.is_extended is True

    @pytest.mark.parametrize("raw", (
        b'1234extmsg\0\0\0\0\0\0\xfe\xff\xff\xff\0\0\0\0command\0\0\0\0\0\5\0\0\0\0\0\0\0',
        b'4567extmsg\0\0\0\0\0\0\xff\xff\xff\xff\0\0\1\0command\0\0\0\0\0\5\0\0\0\0\0\0\0',
    ))
    @pytest.mark.asyncio
    async def test_from_stream_ext_bad(self, raw):
        dribble = Dribble(raw)
        with pytest.raises(ProtocolError):
            await MessageHeader.from_stream(dribble.stream())

    @pytest.mark.parametrize("command", ('addr', 'ping', 'sendheaders'))
    def test_str(self, command):
        command_bytes = getattr(MessageHeader, command.upper())
        header = MessageHeader(b'', command_bytes, 0, b'', False)
        assert str(header) == command

    def test_commands(self):
        for key, value in MessageHeader.__dict__.items():
            if isinstance(value, bytes):
                assert key.lower().encode() == value.rstrip(b'\0')


class FakeNode(Peer):

    def __init__(self, is_outgoing, their_address, headers, **kwargs):
        super().__init__(headers, is_outgoing, **kwargs)
        self.remote_peer = None
        # Incoming message queue
        self.queue = Queue()
        self.residual = b''

        self.connection = Connection(their_address, self.recv, self.send)
        self.protocol = Protocol(self, self.connection)

    def connect_to(self, peer):
        self.remote_peer = peer

    async def recv(self, size):
        result = self.residual
        if not result:
            result = await self.queue.get()
        if len(result) <= size:
            self.residual = b''
            return result
        self.residual = result[size:]
        return result[:size]

    async def send(self, raw):
        put = self.remote_peer.queue.put
        for part in Dribble.parts(raw):
            await put(part)


class TestProtocol:

    # Tests: receive verack before version, both incoming and outgoing
    # Tests: receive anything else before version or verack, both incoming and outgoing

    @pytest.mark.asyncio
    async def test_handshake(self):
        headers = Headers(Bitcoin)
        addr_a = NetAddress('4.3.2.1', 8334)
        addr_b = NetAddress('1.2.3.4', 8333)

        protoconf_b = Protoconf(2_000_000, [b'Default', b'BlockPriority'])
        service_b = ServiceDetails.from_parts(
            services=BitcoinService.Service.NODE_NETWORK,
            protocol_version=80_000,
            user_agent='/foobar:1.0/',
            relay=False,
            timestamp=500_000,
            assoc_id=b'Default',
            protoconf=protoconf_b,
        )

        node_a = FakeNode(True, addr_b, mainnet_headers)
        node_b = FakeNode(False, addr_a, headers, our_service=service_b)

        # Check details set correctly
        assert node_a.our_service.service.services == BitcoinService.Service.NODE_NONE
        assert node_a.our_service.user_agent == '/bitcoinx:0.01/'
        assert node_a.our_service.protocol_version == 70_015
        assert node_a.our_service.start_height == 2099
        assert node_a.our_service.relay is True
        assert node_a.our_service.timestamp is None
        assert node_a.our_service.assoc_id == b''
        assert node_a.our_service.protoconf == Protoconf.default()

        assert node_b.our_service.service.services == BitcoinService.Service.NODE_NETWORK
        assert node_b.our_service.user_agent == '/foobar:1.0/'
        assert node_b.our_service.protocol_version == 80_000
        assert node_b.our_service.start_height == 0
        assert node_b.our_service.relay is False
        assert node_b.our_service.timestamp == 500_000
        assert node_b.our_service.assoc_id == b'Default'
        assert node_b.our_service.protoconf == protoconf_b

        node_a.connect_to(node_b)
        node_b.connect_to(node_a)
        nodes = (node_a, node_b)

        try:
            rmloops = [create_task(node.protocol.recv_messages_loop()) for node in nodes]
            handshakes = [create_task(node.protocol._perform_handshake()) for node in nodes]

            for task in handshakes:
                await task

            # Let protoconf be processed
            await sleep(0.005)

            assert not node_a.connection.disconnected
            assert not node_b.connection.disconnected

            assert node_a.their_service.service.address == addr_b
            assert node_b.their_service.service.address == addr_a

            # Check all relevant details were correctly recorded in each node
            for check, other in ((node_a, node_b), (node_b, node_a)):
                assert check.version_received.is_set()
                assert check.verack_received.is_set()
                assert check.their_service is not None

                assert check.their_service.service.services == other.our_service.service.services
                assert check.their_service.protocol_version == other.our_service.protocol_version
                assert check.their_service.user_agent == other.our_service.user_agent
                assert check.their_service.start_height == other.our_service.start_height
                if other.our_service.timestamp is None:
                    assert abs(check.their_service.timestamp - time.time()) < 1
                else:
                    assert check.their_service.timestamp == other.our_service.timestamp
                assert check.their_service.relay == other.our_service.relay
                assert check.their_service.assoc_id == other.our_service.assoc_id
                assert check.their_service.protoconf == other.our_service.protoconf

        finally:
            for task in handshakes + rmloops:
                if not task.done():
                    task.cancel()
            await sleep(0.01)

    @pytest.mark.asyncio
    async def test_self_connect(self):
        headers = Headers(Bitcoin)
        node = FakeNode(True, NetAddress.from_string('1.2.3.4:556'), headers)
        node.connect_to(node)

        rmloop = create_task(node.protocol.recv_messages_loop())
        handshake = create_task(node.protocol._perform_handshake())
        try:
            await sleep(0.01)
            assert rmloop.done()

            with pytest.raises(ForceDisconnectError) as e:
                rmloop.result()
            assert 'connected to ourself' in str(e.value)
            assert node.connection.disconnected
        finally:
            for task in (rmloop, handshake):
                if not task.done():
                    task.cancel()
            await sleep(0.01)

    @pytest.mark.asyncio
    async def test_bad_magic(self):
        node_a = FakeNode(True, NetAddress.from_string('1.2.3.4:5555'), Headers(Bitcoin))
        node_b = FakeNode(False, NetAddress.from_string('1.2.3.4:7777'), Headers(BitcoinTestnet))

        node_a.connect_to(node_b)
        nodes = (node_a, node_b)

        try:
            rmloop = create_task(node_b.protocol.recv_messages_loop())
            handshake = create_task(node_a.protocol._perform_handshake())

            await sleep(0.01)
            assert rmloop.done()

            with pytest.raises(ForceDisconnectError) as e:
                rmloop.result()
            assert 'bad magic' in str(e.value)
            assert node_b.connection.disconnected

        finally:
            for task in (rmloop, handshake):
                if not task.done():
                    task.cancel()
            await sleep(0.01)
