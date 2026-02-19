"""
Factory for creating PyRIT scorers from attack pipeline configuration.

Supports:
- SubStringScorer for substring detection
- TrueFalseInverterScorer for negation-mode substring detection
- SelfAskTrueFalseScorer for LLM judge evaluation
"""

from __future__ import annotations

from typing import Optional

from pyrit.prompt_target import OpenAIChatTarget
from pyrit.score import (
    SubStringScorer,
    SelfAskTrueFalseScorer,
    TrueFalseInverterScorer,
    TrueFalseCompositeScorer,
    TrueFalseScoreAggregator,
)
from pyrit.score.true_false.true_false_scorer import TrueFalseScorer
from pyrit.score.true_false.self_ask_true_false_scorer import TrueFalseQuestion


def create_substring_scorer(
    substrings: list[str],
    is_negation: bool = False,
) -> TrueFalseScorer:
    """
    Create a PyRIT scorer for substring detection.

    If multiple substrings: creates a TrueFalseCompositeScorer (OR logic).
    If is_negation: wraps with TrueFalseInverterScorer.

    Args:
        substrings: List of substrings to detect.
        is_negation: If True, inverts the result (absence = hit).

    Returns:
        Configured PyRIT TrueFalseScorer.
    """
    if not substrings:
        raise ValueError("At least one substring is required")

    if len(substrings) == 1:
        scorer: TrueFalseScorer = SubStringScorer(substring=substrings[0])
    else:
        # Multiple substrings -- compose with OR logic (any match = hit)
        individual_scorers = [SubStringScorer(substring=s) for s in substrings]
        scorer = TrueFalseCompositeScorer(
            scorers=individual_scorers,
            aggregator=TrueFalseScoreAggregator.OR,
        )

    if is_negation:
        scorer = TrueFalseInverterScorer(scorer=scorer)

    return scorer


def create_llm_judge_scorer(
    judge_target: OpenAIChatTarget,
    true_description: str,
) -> SelfAskTrueFalseScorer:
    """
    Create a PyRIT LLM judge scorer.

    Uses SelfAskTrueFalseScorer with the judge LLM to evaluate
    whether the attack objective was achieved.

    Args:
        judge_target: PyRIT target for the judge LLM.
        true_description: Description of what constitutes a successful attack.

    Returns:
        Configured SelfAskTrueFalseScorer.
    """
    return SelfAskTrueFalseScorer(
        chat_target=judge_target,
        true_false_question=TrueFalseQuestion(
            true_description=true_description,
        ),
    )
