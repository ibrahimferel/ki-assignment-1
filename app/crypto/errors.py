class CryptoError(Exception):
    """Placeholder, errors raised by cryptographic functions."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message

    