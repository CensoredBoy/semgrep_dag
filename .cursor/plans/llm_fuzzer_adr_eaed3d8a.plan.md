---
name: LLM Fuzzer ADR
overview: Создание архитектурного документа (ADR/RFC) для LLM Fuzzer с описанием архитектуры, диаграммами, проверками, конфигурациями и форматами отчётов.
todos:
  - id: create-adr
    content: Создать файл docs/ADR.md с полным ADR документом
    status: completed
---

# Architecture Decision Record: LLM Fuzzer

## Структура документа

Документ будет создан в файле `docs/ADR.md` и будет содержать следующие разделы:

---

### 1. Введение и мотивация

**Проблема:** Необходимость унифицированного инструмента для тестирования безопасности LLM, объединяющего возможности различных фреймворков.

**Решение:** LLM Fuzzer - интерфейс-обёртка над Garak (NVIDIA) и PyRIT (Microsoft).

**Преимущества:**

- Единый интерфейс для двух мощных фреймворков
- Унифицированные отчёты с полной информацией
- Декларативные YAML конфигурации
- CLI для автоматизации в CI/CD
- Расширяемость через плагины

---

### 2. Архитектурная диаграмма

```mermaid
graph TB
    subgraph CLI [CLI Layer]
        UserCLI[llm-fuzzer CLI]
    end
    
    subgraph Core [Core Layer]
        TargetConfig[TargetConfig]
        CheckConfig[CheckConfig]
        CheckResult[CheckResult]
        ScanSummary[ScanSummary]
    end
    
    subgraph Adapters [Adapter Layer]
        BaseAdapter[BaseAdapter]
        GarakAdapter[RealGarakAdapter]
        PyRITAdapter[RealPyRITAdapter]
    end
    
    subgraph Engines [External Engines]
        Garak[Garak NVIDIA]
        PyRIT[PyRIT Microsoft]
    end
    
    subgraph Reports [Report Layer]
        JSONReport[JSONReportGenerator]
        MarkdownReport[MarkdownReportGenerator]
    end
    
    subgraph Target [LLM Target]
        LLMEndpoint[LLM API Endpoint]
    end
    
    UserCLI --> TargetConfig
    UserCLI --> CheckConfig
    TargetConfig --> BaseAdapter
    CheckConfig --> BaseAdapter
    
    BaseAdapter --> GarakAdapter
    BaseAdapter --> PyRITAdapter
    
    GarakAdapter --> Garak
    PyRITAdapter --> PyRIT
    
    Garak --> LLMEndpoint
    PyRIT --> LLMEndpoint
    
    GarakAdapter --> CheckResult
    PyRITAdapter --> CheckResult
    
    CheckResult --> ScanSummary
    ScanSummary --> JSONReport
    ScanSummary --> MarkdownReport
```

---

### 3. Блок-схема процесса сканирования

```mermaid
flowchart TD
    Start([Начало]) --> LoadConfig[Загрузка конфигов]
    LoadConfig --> LoadTarget[Загрузка TargetConfig]
    LoadConfig --> LoadChecks[Загрузка CheckConfig]
    
    LoadTarget --> ValidateTarget{Валидация}
    LoadChecks --> ValidateChecks{Валидация}
    
    ValidateTarget -->|OK| InitAdapters[Инициализация адаптеров]
    ValidateChecks -->|OK| InitAdapters
    
    InitAdapters --> InitGarak[Init GarakAdapter]
    InitAdapters --> InitPyRIT[Init PyRITAdapter]
    
    InitGarak --> CheckLoop[Цикл по проверкам]
    InitPyRIT --> CheckLoop
    
    CheckLoop --> SelectEngine{Выбор движка}
    
    SelectEngine -->|garak| RunGarak[Запуск Garak]
    SelectEngine -->|pyrit| RunPyRIT[Запуск PyRIT]
    SelectEngine -->|auto| AutoSelect[Авто-выбор]
    
    RunGarak --> LoadProbes[Загрузка probes]
    LoadProbes --> LoadDetectors[Загрузка detectors]
    LoadDetectors --> ExecuteHarness[Запуск Harness]
    ExecuteHarness --> ParseResults[Парсинг результатов]
    
    RunPyRIT --> LoadCheck[Загрузка PyRIT Check]
    LoadCheck --> CreateTarget[Создание Target]
    CreateTarget --> SendPrompts[Отправка промптов]
    SendPrompts --> ScoreResponses[Оценка через Scorer]
    ScoreResponses --> ParseResults
    
    AutoSelect --> RunGarak
    AutoSelect --> RunPyRIT
    
    ParseResults --> CreateFinding[Создание Finding]
    CreateFinding --> CreateResult[Создание CheckResult]
    CreateResult --> NextCheck{Ещё проверки?}
    
    NextCheck -->|Да| CheckLoop
    NextCheck -->|Нет| GenerateReports[Генерация отчётов]
    
    GenerateReports --> CreateSummary[Создание ScanSummary]
    CreateSummary --> JSONGen[JSON отчёт]
    CreateSummary --> MDGen[Markdown отчёт]
    
    JSONGen --> SaveReports[Сохранение]
    MDGen --> SaveReports
    
    SaveReports --> EndNode([Конец])
```

---

### 4. Структура данных

**Ключевые модели из [`src/llm_fuzzer/core/`](src/llm_fuzzer/core/):**

| Модель | Файл | Назначение |

|--------|------|------------|

| `TargetConfig` | `target.py` | Конфигурация целевого LLM endpoint |

| `CheckConfig` | `check.py` | Конфигурация проверки безопасности |

| `CheckResult` | `check.py` | Результат выполнения проверки |

| `Finding` | `check.py` | Отдельная найденная уязвимость |

| `ScanSummary` | `report.py` | Сводка результатов сканирования |

---

### 5. Категории проверок

Таблица категорий из `CheckCategory`:

| Категория | Описание | Движок |

|-----------|----------|--------|

| `jailbreak` | Обход ограничений (DAN, roleplay) | Garak |

| `injection` | Prompt injection атаки | Garak |

| `leakage` | Утечка system prompt | PyRIT |

| `tool_abuse` | Злоупотребление tool calls | PyRIT |

| `toxicity` | Генерация токсичного контента | Garak |

| `hallucination` | Галлюцинации модели | Garak |

| `bias` | Предвзятость модели | Garak |

---

### 6. Конфигурации

Примеры YAML конфигов из [`configs/`](configs/):

**Target конфигурация:**

```yaml
name: my-target
endpoint: https://api.example.com/v1
api_key: ${API_KEY}
model: gpt-4
type: openai
options:
  disable_ssl_verify: false
  timeout: 60
```

**Check конфигурация:**

```yaml
checks:
  - id: jailbreak-dan
    name: DAN Jailbreak
    category: jailbreak
    engine: garak
    severity: high
    garak_probes:
      - dan.Dan_11_0
    garak_detectors:
      - mitigation.MitigationBypass
    max_prompts: 10
    generations: 1
```

---

### 7. Структура отчётов

**JSON отчёт:**

```json
{
  "meta": { "version": "1.0", "generator": "llm-fuzzer" },
  "target": { "name", "endpoint", "model" },
  "summary": {
    "total_checks", "passed", "failed",
    "findings_by_severity": { "critical", "high", "medium", "low" }
  },
  "results": [
    {
      "check_id", "status", "severity",
      "total_prompts", "successful_attacks", "success_rate",
      "findings": [
        { "prompt", "response", "evidence", "confidence" }
      ]
    }
  ]
}
```

---

### 8. Расширяемость

**Добавление PyRIT проверки:**

```python
@register_check("my-custom-check")
class MyCustomCheck(BasePyRITCheck):
    name = "My Custom Check"
    category = CheckCategory.CUSTOM
    
    async def run(self, target, config):
        # Логика проверки
        return [PyRITCheckResult(...)]
```

---

## Файл для создания

Создать файл `docs/ADR.md` с полным содержимым документа, включающим:

- Все диаграммы в формате Mermaid
- Таблицы с категориями проверок
- Примеры конфигураций
- Структуры данных
- Инструкции по расширению