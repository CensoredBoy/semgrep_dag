"""
PyRIT Custom Targets.

Кастомные targets для работы с различными endpoint-ами.
"""

from .insecure_target import InsecureOpenAIChatTarget, get_target

__all__ = [
    "InsecureOpenAIChatTarget",
    "get_target",
]
