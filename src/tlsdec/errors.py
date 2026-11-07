class TlsdecError(Exception):
    """Base for every tlsdec exception"""


class KdfError(TlsdecError):
    """Exception raised by kdf module"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class PcapError(TlsdecError):
    """Exception raised by pcap module"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class TcpError(TlsdecError):
    """Exception raised by tcp module"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class RecordError(TlsdecError):
    """Exception raised by record module"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class KeylogError(TlsdecError):
    """Exception raised by keylog module"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class DecryptError(TlsdecError):
    """Exception raised by decrypt module"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class HandshakeError(TlsdecError):
    """Exception raised by handshake module"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class HandshakeIncompleteError(HandshakeError):
    """Exception raised by handshake module when handshake is incomplete and needs more bytes"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
