# tmp/ — автономные тесты PyRIT-интеграции

Код в этой папке работает **без** БД, каталогов, SQLAlchemy — только PyRIT.

## Файлы

| Файл | Что делает |
|------|-----------|
| `tool_target.py` | `ToolEnabledTarget` — кастомный target, инжектит `tools` в каждый API запрос |
| `target_factory.py` | Фабрика targets: `create_target()`, `create_tool_target()`, SSL=off |
| `scorer_factory.py` | Фабрика scorers: `SubStringScorer`, `SelfAskTrueFalseScorer` |
| `runner.py` | `AttackRunner` + DTO (pipeline, results) — всё в одном файле |
| `test_prompt_sending.py` | Тест single-turn: промпты + substring detection |
| `test_tool_abuse.py` | Тест tool abuse: tools в API + substring в tool_calls |
| `test_red_teaming.py` | Тест multi-turn: attacker + target + LLM judge |

## Запуск

```bash
cd tmp/

# Активировать venv проекта
source ../.venv/bin/activate

# Тест 1: single-turn + substring scorer
python test_prompt_sending.py \
    --url http://localhost:8080/v1 \
    --model my-model

# Тест 2: tool abuse (tools в API запросе)
python test_tool_abuse.py \
    --url http://localhost:8080/v1 \
    --model my-model

# Тест 3: multi-turn red teaming + LLM judge
python test_red_teaming.py \
    --url http://localhost:8080/v1 \
    --model my-model \
    --attacker-url http://localhost:8080/v1 \
    --attacker-model my-model \
    --judge-url http://localhost:8080/v1 \
    --judge-model my-model \
    --max-turns 3
```
