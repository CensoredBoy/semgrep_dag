"""
SQLAlchemy ORM models for LLM Fuzzing Scanner.

5 каталогов компонентов:
  - Prompt (атакующие промпты / патроны)
  - AttackerInstruction (system prompt для атакующей LLM)
  - DetectorSubstring (подстроки для substring scorer)
  - JudgeInstruction (инструкции для LLM judge)
  - Tool (OpenAI function calling definitions)

Attack -- бандл, объединяющий компоненты:
  - Attack -> Prompt (M:N)
  - Attack -> DetectorSubstring (M:N)
  - Attack -> Tool (M:N)
  - Attack -> AttackerInstruction (M:1, optional)
  - Attack -> JudgeInstruction (M:1, optional)

Результаты:
  - ScanSession -> AttackRun -> AttackResult
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Join tables (many-to-many)
# ---------------------------------------------------------------------------

attack_prompt = Table(
    "attack_prompt",
    Base.metadata,
    Column("attack_id", String, ForeignKey("attack.id", ondelete="CASCADE"), primary_key=True),
    Column("prompt_id", String, ForeignKey("prompt.id", ondelete="CASCADE"), primary_key=True),
    Column("sort_order", Integer, nullable=False, default=0),
)

attack_detector_substring = Table(
    "attack_detector_substring",
    Base.metadata,
    Column("attack_id", String, ForeignKey("attack.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "detector_substring_id",
        String,
        ForeignKey("detector_substring.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

attack_tool = Table(
    "attack_tool",
    Base.metadata,
    Column("attack_id", String, ForeignKey("attack.id", ondelete="CASCADE"), primary_key=True),
    Column("tool_id", String, ForeignKey("tool.id", ondelete="CASCADE"), primary_key=True),
)


# ---------------------------------------------------------------------------
# 1. КАТАЛОГИ КОМПОНЕНТОВ
# ---------------------------------------------------------------------------


class Prompt(Base):
    """Атакующий промпт (патрон)."""

    __tablename__ = "prompt"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False, default="custom")
    language: Mapped[str] = mapped_column(String, nullable=False, default="en")
    tags: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON array
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    # relationships
    attacks: Mapped[list[Attack]] = relationship(secondary=attack_prompt, back_populates="prompts")
    attack_results: Mapped[list[AttackResult]] = relationship(back_populates="prompt")

    __table_args__ = (
        Index("idx_prompt_source", "source"),
        Index("idx_prompt_language", "language"),
        Index("idx_prompt_active", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<Prompt id={self.id!r} source={self.source!r} active={self.is_active}>"


class AttackerInstruction(Base):
    """Системный промпт для атакующей LLM (adversarial_chat)."""

    __tablename__ = "attacker_instruction"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    system_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    # relationships
    attacks: Mapped[list[Attack]] = relationship(back_populates="attacker_instruction")

    def __repr__(self) -> str:
        return f"<AttackerInstruction name={self.name!r}>"


class DetectorSubstring(Base):
    """Подстрока для substring-детектора."""

    __tablename__ = "detector_substring"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    substring: Mapped[str] = mapped_column(Text, nullable=False)
    is_negation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source: Mapped[str] = mapped_column(String, nullable=False, default="custom")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    # relationships
    attacks: Mapped[list[Attack]] = relationship(secondary=attack_detector_substring, back_populates="detector_substrings")

    __table_args__ = (
        Index("idx_detector_substring_active", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<DetectorSubstring substring={self.substring!r} negation={self.is_negation}>"


class JudgeInstruction(Base):
    """Инструкция для LLM-судьи (SelfAskTrueFalseScorer)."""

    __tablename__ = "judge_instruction"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    system_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    true_description: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    # relationships
    attacks: Mapped[list[Attack]] = relationship(back_populates="judge_instruction")

    def __repr__(self) -> str:
        return f"<JudgeInstruction name={self.name!r}>"


class Tool(Base):
    """OpenAI function calling tool definition."""

    __tablename__ = "tool"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    parameters_schema: Mapped[str] = mapped_column(Text, nullable=False, default="{}")  # JSON Schema
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    # relationships
    attacks: Mapped[list[Attack]] = relationship(secondary=attack_tool, back_populates="tools")

    def __repr__(self) -> str:
        return f"<Tool name={self.name!r}>"


# ---------------------------------------------------------------------------
# 2. ATTACK (бандл)
# ---------------------------------------------------------------------------


class Attack(Base):
    """
    Атака -- собранный пакет из компонентов.

    Объединяет промпты, подстроки детекции, тулы,
    и ссылается на attacker/judge инструкции.
    Содержит настройки выполнения (orchestrator, scorer, converters).
    """

    __tablename__ = "attack"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    name: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    category: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    orchestrator_type: Mapped[str] = mapped_column(String, nullable=False)
    scorer_type: Mapped[str] = mapped_column(String, nullable=False)
    max_turns: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    converter_chain: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON array
    is_negation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # FK to instructions (optional)
    attacker_instruction_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("attacker_instruction.id", ondelete="SET NULL"), nullable=True
    )
    judge_instruction_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("judge_instruction.id", ondelete="SET NULL"), nullable=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    # relationships -- M:1
    attacker_instruction: Mapped[Optional[AttackerInstruction]] = relationship(back_populates="attacks")
    judge_instruction: Mapped[Optional[JudgeInstruction]] = relationship(back_populates="attacks")

    # relationships -- M:N
    prompts: Mapped[list[Prompt]] = relationship(secondary=attack_prompt, back_populates="attacks")
    detector_substrings: Mapped[list[DetectorSubstring]] = relationship(
        secondary=attack_detector_substring, back_populates="attacks"
    )
    tools: Mapped[list[Tool]] = relationship(secondary=attack_tool, back_populates="attacks")

    # relationships -- 1:M (results)
    attack_runs: Mapped[list[AttackRun]] = relationship(back_populates="attack")

    __table_args__ = (
        CheckConstraint(
            "category IN ('jailbreak', 'prompt_injection', 'system_prompt_leakage', 'tool_abuse')",
            name="ck_attack_category",
        ),
        CheckConstraint(
            "orchestrator_type IN ('prompt_sending', 'red_teaming')",
            name="ck_attack_orchestrator_type",
        ),
        CheckConstraint(
            "scorer_type IN ('substring', 'llm_judge')",
            name="ck_attack_scorer_type",
        ),
        Index("idx_attack_category", "category"),
        Index("idx_attack_active", "is_active"),
    )

    def __repr__(self) -> str:
        return f"<Attack name={self.name!r} category={self.category!r}>"


# ---------------------------------------------------------------------------
# 3. РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ
# ---------------------------------------------------------------------------


class ScanSession(Base):
    """Сессия сканирования -- один запуск сканера."""

    __tablename__ = "scan_session"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    target_url: Mapped[str] = mapped_column(String, nullable=False)
    target_model: Mapped[str] = mapped_column(String, nullable=False)
    attacker_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    attacker_model: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    judge_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    judge_model: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    mode: Mapped[str] = mapped_column(String, nullable=False)
    config_snapshot: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # relationships
    attack_runs: Mapped[list[AttackRun]] = relationship(back_populates="scan_session", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("mode IN ('simple', 'advanced')", name="ck_scan_session_mode"),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_scan_session_status",
        ),
    )

    def __repr__(self) -> str:
        return f"<ScanSession id={self.id!r} target={self.target_model!r} status={self.status!r}>"


class AttackRun(Base):
    """Запуск одной атаки внутри сессии."""

    __tablename__ = "attack_run"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    scan_session_id: Mapped[str] = mapped_column(
        String, ForeignKey("scan_session.id", ondelete="CASCADE"), nullable=False
    )
    attack_id: Mapped[str] = mapped_column(
        String, ForeignKey("attack.id", ondelete="RESTRICT"), nullable=False
    )
    total_prompts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    successful_hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # relationships
    scan_session: Mapped[ScanSession] = relationship(back_populates="attack_runs")
    attack: Mapped[Attack] = relationship(back_populates="attack_runs")
    results: Mapped[list[AttackResult]] = relationship(back_populates="attack_run", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_attack_run_status",
        ),
        Index("idx_attack_run_session", "scan_session_id"),
        Index("idx_attack_run_attack", "attack_id"),
    )

    def __repr__(self) -> str:
        return f"<AttackRun id={self.id!r} attack={self.attack_id!r} rate={self.success_rate}>"


class AttackResult(Base):
    """Результат одного промпта в рамках AttackRun."""

    __tablename__ = "attack_result"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_new_id)
    attack_run_id: Mapped[str] = mapped_column(
        String, ForeignKey("attack_run.id", ondelete="CASCADE"), nullable=False
    )
    prompt_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("prompt.id", ondelete="SET NULL"), nullable=True
    )
    turn_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    original_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    converted_prompt: Mapped[str] = mapped_column(Text, nullable=False, default="")
    response: Mapped[str] = mapped_column(Text, nullable=False, default="")
    response_tool_calls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array of tool_calls from model response
    detector_verdict: Mapped[str] = mapped_column(String, nullable=False, default="miss")
    detector_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    judge_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_hit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    conversation_history: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    # relationships
    attack_run: Mapped[AttackRun] = relationship(back_populates="results")
    prompt: Mapped[Optional[Prompt]] = relationship(back_populates="attack_results")

    __table_args__ = (
        CheckConstraint(
            "detector_verdict IN ('hit', 'miss', 'error')",
            name="ck_attack_result_verdict",
        ),
        Index("idx_attack_result_run", "attack_run_id"),
        Index("idx_attack_result_prompt", "prompt_id"),
        Index("idx_attack_result_hit", "is_hit"),
    )

    def __repr__(self) -> str:
        return f"<AttackResult id={self.id!r} hit={self.is_hit} score={self.detector_score}>"
