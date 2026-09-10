"""Multi-device topology: the network, not one box."""
from .fabric import Device, Fabric, Hop, PathAnswer
from .interfaces import Interface, extract

__all__ = ["Fabric", "Device", "Hop", "PathAnswer", "Interface", "extract"]
