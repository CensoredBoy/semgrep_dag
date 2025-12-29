# Исследование уязвимостей больших языковых моделей (LLM)

Этот репозиторий содержит комплексное исследование уязвимостей LLM, включающее описание основных типов уязвимостей, примеры из реальных инцидентов, методологию воспроизводимого сканирования и практические примеры использования инструментов.

## Содержание

- [Описание](#описание)
- [Структура проекта](#структура-проекта)
- [Установка](#установка)
- [Использование](#использование)
- [Инструменты](#инструменты)
- [Примеры](#примеры)
- [Документация](#документация)

## Описание

Исследование охватывает три основных типа уязвимостей LLM:

1. **Раскрытие системного промпта** - утечка внутренних инструкций модели
2. **Jailbreak** - обход встроенных ограничений модели
3. **Prompt Injection** - внедрение вредоносных инструкций в промпты

Для каждой уязвимости предоставлены:
- Подробное описание механизмов эксплуатации
- Примеры из реальных инцидентов
- Методы защиты

## Структура проекта

```
.
├── LLM_Vulnerabilities_Research.md  # Основной документ исследования
├── README.md                        # Этот файл
├── requirements.txt                 # Зависимости Python
├── examples/                        # Примеры использования инструментов
│   ├── garak_example.py            # Примеры использования Garak
│   ├── llamator_example.py         # Примеры использования Llamator
│   ├── pyrit_example.py            # Примеры использования PyRIT
│   └── custom_scanner.py           # Кастомный сканер уязвимостей
└── test_scenarios/                  # Тестовые сценарии
    ├── system_prompt_leakage.json  # Сценарии для тестирования раскрытия промпта
    ├── jailbreak.json              # Сценарии для тестирования jailbreak
    └── prompt_injection.json       # Сценарии для тестирования prompt injection
```

## Установка

### Предварительные требования

- Python 3.9 или выше
- pip (менеджер пакетов Python)

### Установка зависимостей

1. Клонируйте репозиторий или скачайте файлы:
```bash
cd /path/to/llm
```

2. Создайте виртуальное окружение (рекомендуется):
```bash
python3 -m venv venv
source venv/bin/activate  # Для Linux/Mac
# или
venv\Scripts\activate  # Для Windows
```

3. Установите зависимости:
```bash
pip install -r requirements.txt
```

### Установка инструментов

#### Garak

```bash
pip install garak
```

Или из исходников:
```bash
git clone https://github.com/leondz/garak.git
cd garak
pip install -e .
```

#### Llamator

```bash
git clone https://github.com/ai-security-lab/llamator.git
cd llamator
pip install -e .
```

Или через pip (если доступно):
```bash
pip install llamator
```

#### PyRIT

```bash
git clone https://github.com/Azure/PyRIT.git
cd PyRIT
pip install -e .
```

Или через pip (если доступно):
```bash
pip install pyrit
```

### Настройка API ключей

Для работы с моделями через API необходимо настроить ключи доступа:

```bash
# OpenAI
export OPENAI_API_KEY="your-openai-api-key"

# Azure OpenAI (для PyRIT)
export AZURE_OPENAI_API_KEY="your-azure-api-key"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com/"
```

Или создайте файл `.env`:
```
OPENAI_API_KEY=your-openai-api-key
AZURE_OPENAI_API_KEY=your-azure-api-key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
```

## Использование

### Просмотр основного исследования

Откройте файл `LLM_Vulnerabilities_Research.md` для ознакомления с полным исследованием.

### Запуск примеров

#### Примеры использования Garak

```bash
python examples/garak_example.py
```

Для реального сканирования:
```bash
garak --model_name gpt-3.5-turbo --probes promptinject --detectors base
```

#### Примеры использования Llamator

```bash
python examples/llamator_example.py
```

Для реального сканирования:
```bash
llamator --target http://your-llm-endpoint --attack-type prompt-injection
```

#### Примеры использования PyRIT

```bash
python examples/pyrit_example.py
```

Для реального сканирования:
```bash
pyrit attack --target-model gpt-3.5-turbo --attack-type prompt-injection
```

#### Кастомный сканер

```bash
python examples/custom_scanner.py --model gpt-3.5-turbo --scenarios test_scenarios/ --output scan_report.json
```

### Использование тестовых сценариев

Тестовые сценарии находятся в директории `test_scenarios/` и могут быть использованы с кастомным сканером или адаптированы для других инструментов.

Пример:
```bash
python examples/custom_scanner.py \
    --model gpt-3.5-turbo \
    --scenarios test_scenarios/ \
    --output my_scan_report.json \
    --api-key $OPENAI_API_KEY
```

## Инструменты

### Garak

**Описание**: Фреймворк для тестирования безопасности LLM от NVIDIA

**Основные возможности**:
- Более 50 типов тестов (probes)
- Поддержка множества моделей
- Автоматическое обнаружение уязвимостей
- Детальные отчеты

**Документация**: https://garak.ai/

**GitHub**: https://github.com/leondz/garak

### Llamator

**Описание**: Python-фреймворк для автоматизации Red Teaming атак на LLM-приложения

**Основные возможности**:
- Автоматизация атак на русском и английском языках
- Поддержка многоступенчатых атак
- Интеграция с LangChain, OpenAI API, Anthropic API
- Автоматическая генерация отчетов

**Документация**: https://llamator.ru/

**GitHub**: https://github.com/ai-security-lab/llamator

### PyRIT

**Описание**: Инструмент от Microsoft для проведения Red Teaming атак на LLM

**Основные возможности**:
- Одно- и многоступенчатые атаки
- Использование атакующих моделей для генерации промптов
- Оценка устойчивости моделей
- Интеграция с Azure OpenAI

**GitHub**: https://github.com/Azure/PyRIT

## Примеры

### Пример 1: Базовое сканирование с Garak

```bash
garak --model_name gpt-3.5-turbo --probes all --report garak_report.json
```

### Пример 2: Тестирование на Prompt Injection

```bash
garak --model_name gpt-3.5-turbo --probes promptinject --detectors base
```

### Пример 3: Многоступенчатая атака с Llamator

```bash
llamator --target http://your-llm-endpoint --attack-type multi-turn --steps 5
```

### Пример 4: Jailbreak тестирование с PyRIT

```bash
pyrit attack --target-model gpt-3.5-turbo --attack-type jailbreak
```

### Пример 5: Кастомное сканирование

```bash
python examples/custom_scanner.py \
    --model gpt-3.5-turbo \
    --scenarios test_scenarios/ \
    --output custom_report.json
```

## Документация

### Основной документ исследования

Полное исследование находится в файле `LLM_Vulnerabilities_Research.md` и включает:

1. Подробное описание каждого типа уязвимости
2. Примеры из реальных инцидентов
3. Описание инструментов для сканирования
4. Методологию воспроизводимого тестирования
5. Практические примеры использования
6. Рекомендации по защите

### Примеры кода

Все примеры находятся в директории `examples/`:

- `garak_example.py` - демонстрация использования Garak
- `llamator_example.py` - демонстрация использования Llamator
- `pyrit_example.py` - демонстрация использования PyRIT
- `custom_scanner.py` - кастомный сканер с методологией воспроизводимого тестирования

### Тестовые сценарии

Тестовые сценарии в формате JSON находятся в директории `test_scenarios/`:

- `system_prompt_leakage.json` - сценарии для тестирования раскрытия системного промпта
- `jailbreak.json` - сценарии для тестирования jailbreak
- `prompt_injection.json` - сценарии для тестирования prompt injection

## Безопасность и этика

**ВАЖНО**: Все примеры и инструменты в этом репозитории предназначены исключительно для:

- Исследовательских целей
- Тестирования собственных систем с разрешения
- Образовательных целей

**НЕ используйте эти инструменты для**:
- Атак на системы без разрешения
- Нарушения законов
- Вредоносной деятельности

Всегда получайте явное разрешение перед тестированием любых систем.

## Вклад

Если вы хотите внести вклад в исследование:

1. Форкните репозиторий
2. Создайте ветку для ваших изменений
3. Внесите изменения
4. Создайте Pull Request

## Лицензия

Этот проект предназначен для образовательных и исследовательских целей.

## Контакты и ссылки

- **OWASP Top 10 for LLM**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **Garak**: https://garak.ai/
- **Llamator**: https://llamator.ru/
- **PyRIT**: https://github.com/Azure/PyRIT

## Благодарности

- NVIDIA за разработку Garak
- AI Security Lab ИТМО за разработку Llamator
- Microsoft за разработку PyRIT
- Сообщество исследователей безопасности LLM

---

*Последнее обновление: 2024*
