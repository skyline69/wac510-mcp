"""Errors raised by the WAC510 client."""


class WAC510Error(Exception):
    """Base error for the package."""


class ConfigurationError(WAC510Error):
    """The local server configuration is invalid."""


class DeviceConnectionError(WAC510Error):
    """The access point could not be reached."""


class AuthenticationError(WAC510Error):
    """The access point rejected authentication."""


class ProtocolError(WAC510Error):
    """The access point returned an invalid or unsuccessful response."""


class UnsafeOperationError(WAC510Error):
    """An operation failed its local safety checks."""

