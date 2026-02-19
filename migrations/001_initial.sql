-- ============================================================================
-- LLM Fuzzing Scanner -- Initial Migration
-- ============================================================================
-- 5 каталогов компонентов + Attack (бандл) + 3 join-таблицы + результаты
-- ============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ============================================================================
-- 1. КАТАЛОГИ КОМПОНЕНТОВ
-- ============================================================================

-- Промпты (патроны) -- атакующие тексты
CREATE TABLE IF NOT EXISTS prompt (
    id          TEXT PRIMARY KEY,
    content     TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'custom',   -- garak_dan | custom | paper_X
    language    TEXT    NOT NULL DEFAULT 'en',        -- en | ru | multi
    tags        TEXT    NOT NULL DEFAULT '[]',        -- JSON array of strings
    is_active   INTEGER NOT NULL DEFAULT 1,          -- 0/1, soft delete
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_prompt_source    ON prompt(source);
CREATE INDEX IF NOT EXISTS idx_prompt_language  ON prompt(language);
CREATE INDEX IF NOT EXISTS idx_prompt_active    ON prompt(is_active);

-- Инструкции для атакующей LLM (system prompt для adversarial_chat)
CREATE TABLE IF NOT EXISTS attacker_instruction (
    id              TEXT PRIMARY KEY,
    name            TEXT    NOT NULL UNIQUE,
    system_prompt   TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Подстроки для детекции (substring scorer)
CREATE TABLE IF NOT EXISTS detector_substring (
    id          TEXT PRIMARY KEY,
    substring   TEXT    NOT NULL,
    is_negation INTEGER NOT NULL DEFAULT 0,      -- 1 = absence means hit
    source      TEXT    NOT NULL DEFAULT 'custom',
    description TEXT    NOT NULL DEFAULT '',
    is_active   INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_detector_substring_active ON detector_substring(is_active);

-- Инструкции для LLM-судьи (SelfAskTrueFalseScorer)
CREATE TABLE IF NOT EXISTS judge_instruction (
    id                TEXT PRIMARY KEY,
    name              TEXT    NOT NULL UNIQUE,
    system_prompt     TEXT    NOT NULL,
    true_description  TEXT    NOT NULL,           -- критерий "истинности"
    description       TEXT    NOT NULL DEFAULT '',
    is_active         INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Тулы (OpenAI function calling definitions)
CREATE TABLE IF NOT EXISTS tool (
    id                  TEXT PRIMARY KEY,
    name                TEXT    NOT NULL UNIQUE,      -- get_weather
    description         TEXT    NOT NULL DEFAULT '',   -- human-readable
    parameters_schema   TEXT    NOT NULL DEFAULT '{}', -- JSON Schema
    is_active           INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- 2. ATTACK (бандл)
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack (
    id                      TEXT PRIMARY KEY,
    name                    TEXT    NOT NULL UNIQUE,
    category                TEXT    NOT NULL,          -- jailbreak | prompt_injection | system_prompt_leakage | tool_abuse
    description             TEXT    NOT NULL DEFAULT '',
    orchestrator_type       TEXT    NOT NULL,          -- prompt_sending | red_teaming
    scorer_type             TEXT    NOT NULL,          -- substring | llm_judge
    max_turns               INTEGER NOT NULL DEFAULT 1,
    converter_chain         TEXT    NOT NULL DEFAULT '[]', -- JSON array of converter names
    is_negation             INTEGER NOT NULL DEFAULT 0,   -- for substring scorer
    attacker_instruction_id TEXT    REFERENCES attacker_instruction(id) ON DELETE SET NULL,
    judge_instruction_id    TEXT    REFERENCES judge_instruction(id) ON DELETE SET NULL,
    is_active               INTEGER NOT NULL DEFAULT 1,
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    CHECK (category IN ('jailbreak', 'prompt_injection', 'system_prompt_leakage', 'tool_abuse')),
    CHECK (orchestrator_type IN ('prompt_sending', 'red_teaming')),
    CHECK (scorer_type IN ('substring', 'llm_judge'))
);

CREATE INDEX IF NOT EXISTS idx_attack_category ON attack(category);
CREATE INDEX IF NOT EXISTS idx_attack_active   ON attack(is_active);

-- ============================================================================
-- 3. JOIN-ТАБЛИЦЫ (many-to-many)
-- ============================================================================

-- Attack <-> Prompt (many-to-many)
CREATE TABLE IF NOT EXISTS attack_prompt (
    attack_id   TEXT NOT NULL REFERENCES attack(id) ON DELETE CASCADE,
    prompt_id   TEXT NOT NULL REFERENCES prompt(id) ON DELETE CASCADE,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (attack_id, prompt_id)
);

CREATE INDEX IF NOT EXISTS idx_attack_prompt_attack ON attack_prompt(attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_prompt_prompt ON attack_prompt(prompt_id);

-- Attack <-> DetectorSubstring (many-to-many)
CREATE TABLE IF NOT EXISTS attack_detector_substring (
    attack_id              TEXT NOT NULL REFERENCES attack(id) ON DELETE CASCADE,
    detector_substring_id  TEXT NOT NULL REFERENCES detector_substring(id) ON DELETE CASCADE,
    PRIMARY KEY (attack_id, detector_substring_id)
);

CREATE INDEX IF NOT EXISTS idx_attack_det_attack ON attack_detector_substring(attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_det_substr ON attack_detector_substring(detector_substring_id);

-- Attack <-> Tool (many-to-many)
CREATE TABLE IF NOT EXISTS attack_tool (
    attack_id TEXT NOT NULL REFERENCES attack(id) ON DELETE CASCADE,
    tool_id   TEXT NOT NULL REFERENCES tool(id) ON DELETE CASCADE,
    PRIMARY KEY (attack_id, tool_id)
);

CREATE INDEX IF NOT EXISTS idx_attack_tool_attack ON attack_tool(attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_tool_tool   ON attack_tool(tool_id);

-- ============================================================================
-- 4. РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ
-- ============================================================================

-- Сессия сканирования (один запуск сканера)
CREATE TABLE IF NOT EXISTS scan_session (
    id              TEXT PRIMARY KEY,
    target_url      TEXT    NOT NULL,
    target_model    TEXT    NOT NULL,
    attacker_url    TEXT,
    attacker_model  TEXT,
    judge_url       TEXT,
    judge_model     TEXT,
    mode            TEXT    NOT NULL,                  -- simple | advanced
    config_snapshot TEXT    NOT NULL DEFAULT '',        -- full resolved config
    status          TEXT    NOT NULL DEFAULT 'pending', -- pending | running | completed | failed
    started_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    finished_at     TEXT,

    CHECK (mode IN ('simple', 'advanced')),
    CHECK (status IN ('pending', 'running', 'completed', 'failed'))
);

-- Запуск одной атаки внутри сессии
CREATE TABLE IF NOT EXISTS attack_run (
    id              TEXT    PRIMARY KEY,
    scan_session_id TEXT    NOT NULL REFERENCES scan_session(id) ON DELETE CASCADE,
    attack_id       TEXT    NOT NULL REFERENCES attack(id) ON DELETE RESTRICT,
    total_prompts   INTEGER NOT NULL DEFAULT 0,
    successful_hits INTEGER NOT NULL DEFAULT 0,
    success_rate    REAL    NOT NULL DEFAULT 0.0,
    status          TEXT    NOT NULL DEFAULT 'pending',
    started_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    finished_at     TEXT,

    CHECK (status IN ('pending', 'running', 'completed', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_attack_run_session ON attack_run(scan_session_id);
CREATE INDEX IF NOT EXISTS idx_attack_run_attack  ON attack_run(attack_id);

-- Результат одного промпта в рамках AttackRun
CREATE TABLE IF NOT EXISTS attack_result (
    id                      TEXT    PRIMARY KEY,
    attack_run_id           TEXT    NOT NULL REFERENCES attack_run(id) ON DELETE CASCADE,
    prompt_id               TEXT    REFERENCES prompt(id) ON DELETE SET NULL,
    turn_number             INTEGER NOT NULL DEFAULT 1,
    original_prompt         TEXT    NOT NULL,
    converted_prompt        TEXT    NOT NULL DEFAULT '',
    response                TEXT    NOT NULL DEFAULT '',
    response_tool_calls     TEXT,                             -- JSON array of tool_calls from model response
    detector_verdict        TEXT    NOT NULL DEFAULT 'miss', -- hit | miss | error
    detector_score          REAL    NOT NULL DEFAULT 0.0,
    judge_reasoning         TEXT,
    is_hit                  INTEGER NOT NULL DEFAULT 0,
    conversation_history    TEXT,                             -- JSON, nullable
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    CHECK (detector_verdict IN ('hit', 'miss', 'error'))
);

CREATE INDEX IF NOT EXISTS idx_attack_result_run    ON attack_result(attack_run_id);
CREATE INDEX IF NOT EXISTS idx_attack_result_prompt ON attack_result(prompt_id);
CREATE INDEX IF NOT EXISTS idx_attack_result_hit    ON attack_result(is_hit);
