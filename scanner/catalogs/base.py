"""
Generic CRUD catalog for ORM entities.

All 5 component catalogs + Attack catalog inherit from this.
"""

from __future__ import annotations

import json
from typing import Any, Generic, Optional, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.data.models import Base

T = TypeVar("T", bound=Base)


class BaseCatalog(Generic[T]):
    """
    Generic CRUD catalog for ORM entities.

    Subclasses set `model_class` and can override `_apply_filters`.
    """

    model_class: type[T]  # set by subclass

    def __init__(self, session: Session) -> None:
        self.session = session

    # ----- CREATE -----

    def add(self, entity: T) -> T:
        self.session.add(entity)
        self.session.commit()
        self.session.refresh(entity)
        return entity

    # ----- READ -----

    def get(self, entity_id: str) -> Optional[T]:
        return self.session.get(self.model_class, entity_id)

    def get_by_name(self, name: str) -> Optional[T]:
        stmt = select(self.model_class).where(self.model_class.name == name)  # type: ignore[attr-defined]
        return self.session.execute(stmt).scalar_one_or_none()

    def list_all(
        self,
        active_only: bool = True,
        limit: int = 1000,
        offset: int = 0,
        **filters: Any,
    ) -> list[T]:
        stmt = select(self.model_class)
        if active_only and hasattr(self.model_class, "is_active"):
            stmt = stmt.where(self.model_class.is_active == True)  # noqa: E712
        stmt = self._apply_filters(stmt, **filters)
        stmt = stmt.limit(limit).offset(offset)
        return list(self.session.execute(stmt).scalars().all())

    def count(self, active_only: bool = True) -> int:
        stmt = select(self.model_class)
        if active_only and hasattr(self.model_class, "is_active"):
            stmt = stmt.where(self.model_class.is_active == True)  # noqa: E712
        return len(list(self.session.execute(stmt).scalars().all()))

    # ----- UPDATE -----

    def update(self, entity_id: str, **fields: Any) -> Optional[T]:
        entity = self.get(entity_id)
        if entity is None:
            return None
        for key, value in fields.items():
            if hasattr(entity, key):
                setattr(entity, key, value)
        self.session.commit()
        self.session.refresh(entity)
        return entity

    # ----- DELETE -----

    def delete(self, entity_id: str) -> bool:
        entity = self.get(entity_id)
        if entity is None:
            return False
        self.session.delete(entity)
        self.session.commit()
        return True

    def deactivate(self, entity_id: str) -> bool:
        return self.update(entity_id, is_active=False) is not None

    # ----- HOOKS -----

    def _apply_filters(self, stmt: Any, **filters: Any) -> Any:
        """Override in subclass to add custom filters."""
        return stmt
