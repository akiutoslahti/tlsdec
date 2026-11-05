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
