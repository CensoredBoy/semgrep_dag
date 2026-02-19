"""
Фабрика PyRIT scorers.

- create_substring_scorer()   -- SubStringScorer / CompositeScorer(OR) / InverterScorer
- create_llm_judge_scorer()   -- SelfAskTrueFalseScorer (LLM judge)
"""

from __future__ import annotations

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
    if not substrings:
        raise ValueError("At least one substring is required")

    if len(substrings) == 1:
        scorer: TrueFalseScorer = SubStringScorer(substring=substrings[0])
    else:
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
    return SelfAskTrueFalseScorer(
        chat_target=judge_target,
        true_false_question=TrueFalseQuestion(
            true_description=true_description,
        ),
    )
