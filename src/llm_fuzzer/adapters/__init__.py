"""
Adapters module - адаптеры для различных движков сканирования.

Используются реальные движки Garak и PyRIT.
"""

from .base import BaseAdapter
from .real_garak_adapter import RealGarakAdapter
from .real_pyrit_adapter import RealPyRITAdapter

__all__ = [
    "BaseAdapter",
    "RealGarakAdapter",
    "RealPyRITAdapter",
]
