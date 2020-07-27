# coding=utf8
import six
from struct import pack, unpack
import base64
from io import BytesIO
import contextlib
import logging
import socket
import threading
from six.moves import queue, range

from thriftpy2.thrift import TClient, TException
from thriftpy2.transport.buffered import TBufferedTransport
from thriftpy2.transport.framed import TFramedTransport
from thriftpy2.transport import TSocket, TTransportBase, TTransportException
from thriftpy2.transport.base import readall
from thriftpy2.protocol.binary import TBinaryProtocol
from thriftpy2.protocol.compact import TCompactProtocol

import puresasl
from puresasl.client import SASLClient
from happybase import ConnectionPool, NoConnectionsAvailable
from happybase.util import ensure_bytes
from happybase import Connection
from Hbase_thrift import Hbase

import kerberos
from kerberos import KrbError

import time
from datetime import datetime

logger = logging.getLogger(__name__)


class CustomGSSAPIMechanism(puresasl.mechanisms.GSSAPIMechanism):
    '''
    The origin `GSSAPIMechanism` in puresasl don't work normally in python3 
    '''
    def wrap(self, outgoing):
        if self.qop != puresasl.QOP.AUTH:
            outgoing = base64.b64encode(outgoing)
            if self.qop == puresasl.QOP.AUTH_CONF:
                protect = 1
            else:
                protect = 0
            kerberos.authGSSClientWrap(
                self.context, outgoing.decode('utf8'), None, protect)
            return base64.b64decode(kerberos.authGSSClientResponse(self.context))
        else:
            return outgoing

class TSaslClientTransport(TTransportBase):
    """
    SASL transport
    """

    START = 1
    OK = 2
    BAD = 3
    ERROR = 4
    COMPLETE = 5

    def __init__(self, transport, host, service, mechanism=six.u('GSSAPI'),
                 **sasl_kwargs):
        """
        transport: an underlying transport to use, typically just a TSocket
        host: the name of the server, from a SASL perspective
        service: the name of the server's service, from a SASL perspective
        mechanism: the name of the preferred mechanism to use
        All other kwargs will be passed to the puresasl.client.SASLClient
        constructor.
        """

        self.transport = transport

        if six.PY3:
            self._patch_pure_sasl()
        self.sasl = SASLClient(host, service, mechanism, **sasl_kwargs)

        self.__wbuf = BytesIO()
        self.__rbuf = BytesIO()

    def _patch_pure_sasl(self):
        ''' we need to patch pure_sasl to support python 3 '''
        puresasl.mechanisms.mechanisms['GSSAPI'] = CustomGSSAPIMechanism

    def is_open(self):
        return self.transport.is_open() and bool(self.sasl)

    def open(self):
        if not self.transport.is_open():
            self.transport.open()

        self.send_sasl_msg(self.START, self.sasl.mechanism.encode('utf8'))
        self.send_sasl_msg(self.OK, self.sasl.process())

        while True:
            status, challenge = self.recv_sasl_msg()
            if status == self.OK:
                self.send_sasl_msg(self.OK, self.sasl.process(challenge))
            elif status == self.COMPLETE:
                if not self.sasl.complete:
                    raise TTransportException(
                        TTransportException.NOT_OPEN,
                        "The server erroneously indicated "
                        "that SASL negotiation was complete")
                else:
                    break
            else:
                raise TTransportException(
                    TTransportException.NOT_OPEN,
                    "Bad SASL negotiation status: %d (%s)"
                    % (status, challenge))

    def send_sasl_msg(self, status, body):
        '''
        body:bytes
        '''
        header = pack(">BI", status, len(body))
        self.transport.write(header + body)
        self.transport.flush()

    def recv_sasl_msg(self):
        header = readall(self.transport.read, 5)
        status, length = unpack(">BI", header)
        if length > 0:
            payload = readall(self.transport.read, length)
        else:
            payload = ""
        return status, payload

    def write(self, data):
        self.__wbuf.write(data)

    def flush(self):
        data = self.__wbuf.getvalue()
        encoded = self.sasl.wrap(data)
        if six.PY2:
            self.transport.write(''.join([
                    pack("!i", len(encoded)), 
                    encoded
                ])
            )
        else:
            self.transport.write(b''.join((pack("!i", len(encoded)), encoded)))
        self.transport.flush()
        self.__wbuf = BytesIO()

    def read(self, sz):
        ret = self.__rbuf.read(sz)
        if len(ret) != 0 or sz == 0:
            return ret

        self._read_frame()
        return self.__rbuf.read(sz)

    def _read_frame(self):
        header = readall(self.transport.read, 4)
        length, = unpack('!i', header)
        encoded = readall(self.transport.read, length)
        self.__rbuf = BytesIO(self.sasl.unwrap(encoded))

    def close(self):
        self.sasl.dispose()
        self.transport.close()

STRING_OR_BINARY = (six.binary_type, six.text_type)

COMPAT_MODES = ('0.90', '0.92', '0.94', '0.96')

THRIFT_TRANSPORTS = dict(
    buffered=TBufferedTransport,
    framed=TFramedTransport,
)
THRIFT_PROTOCOLS = dict(
    binary=TBinaryProtocol,
    compact=TCompactProtocol,
)

DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 9090
DEFAULT_TRANSPORT = 'buffered'
DEFAULT_COMPAT = '0.96'
DEFAULT_PROTOCOL = 'binary'


class KerberosConnection(Connection):
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=None,
                 autoconnect=True, table_prefix=None,
                 table_prefix_separator=b'_', compat=DEFAULT_COMPAT,
                 transport=DEFAULT_TRANSPORT, protocol=DEFAULT_PROTOCOL,
                 use_kerberos=False, sasl_service_name='hbase'):

        if transport not in THRIFT_TRANSPORTS:
            raise ValueError("'transport' must be one of %s"
                             % ", ".join(THRIFT_TRANSPORTS.keys()))

        if table_prefix is not None:
            if not isinstance(table_prefix, STRING_OR_BINARY):
                raise TypeError("'table_prefix' must be a string")
            table_prefix = ensure_bytes(table_prefix)

        if not isinstance(table_prefix_separator, STRING_OR_BINARY):
            raise TypeError("'table_prefix_separator' must be a string")
        table_prefix_separator = ensure_bytes(table_prefix_separator)

        if compat not in COMPAT_MODES:
            raise ValueError("'compat' must be one of %s"
                             % ", ".join(COMPAT_MODES))

        if protocol not in THRIFT_PROTOCOLS:
            raise ValueError("'protocol' must be one of %s"
                             % ", ".join(THRIFT_PROTOCOLS))

        # Allow host and port to be None, which may be easier for
        # applications wrapping a Connection instance.
        self.host = host or DEFAULT_HOST
        self.port = port or DEFAULT_PORT
        self.timeout = timeout
        self.table_prefix = table_prefix
        self.table_prefix_separator = table_prefix_separator
        self.compat = compat
        self.use_kerberos = use_kerberos
        self.sasl_service_name = sasl_service_name

        self._transport_class = THRIFT_TRANSPORTS[transport]
        self._protocol_class = THRIFT_PROTOCOLS[protocol]
        self._refresh_thrift_client()

        if autoconnect:
            self.open()

        self._initialized = True

    def _refresh_thrift_client(self):
        """Refresh the Thrift socket, transport, and client."""
        # socket = TSocket(self.host, self.port)
        socket = TSocket(host=self.host, port=self.port, socket_timeout=self.timeout)
        # if self.timeout is not None:
            # socket.set_timeout(self.timeout)

        self.transport = self._transport_class(socket)
        if self.use_kerberos:
            self.transport = TSaslClientTransport(self.transport, self.host, self.sasl_service_name)
        protocol = self._protocol_class(self.transport, decode_response=False)
        self.client = TClient(Hbase, protocol)


class KerberosConnectionPool(ConnectionPool):
    def __init__(self, size, **kwargs):
        if not isinstance(size, int):
            raise TypeError("Pool 'size' arg must be an integer")

        if not size > 0:
            raise ValueError("Pool 'size' arg must be greater than zero")

        logger.debug(
            "Initializing connection pool with %d connections", size)

        self._lock = threading.Lock()
        self._queue = queue.LifoQueue(maxsize=size)
        self._thread_connections = threading.local()

        connection_kwargs = kwargs
        connection_kwargs['autoconnect'] = False

        for i in range(size):
            connection = KerberosConnection(**connection_kwargs)
            self._queue.put(connection)

        # The first connection is made immediately so that trivial
        # mistakes like unresolvable host names are raised immediately.
        # Subsequent connections are connected lazily.
        with self.connection():
            pass

        # keep alive in a separate thread by running conn.tables()
        try:
            self.thread = threading.Thread(target=self.keep_alive)
            self.thread.daemon = True
            self.thread.start()
        except (KeyboardInterrupt, SystemExit) as e:
            pass

    def keep_alive(self, interval=1):
        while True:
            with self.connection() as conn:
                try:
                    conn.tables()
                except TTransportException as e:
                    # TTransportException: TTransportException(type=4, message='TSocket read 0 bytes')
                    conn._refresh_thrift_client()
                    conn.close()
            time.sleep(interval)
