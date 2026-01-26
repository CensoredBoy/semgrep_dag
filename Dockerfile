# LLM Fuzzer Dockerfile
# Собирает образ с Garak из исходников и PyRIT

FROM python:3.11-slim

# Метаданные
LABEL maintainer="LLM Security Team"
LABEL description="Universal LLM Security Fuzzing Service"
LABEL version="0.1.0"

# Переменные окружения
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем Rust (требуется для некоторых зависимостей Garak)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Создаём рабочую директорию
WORKDIR /app

# Клонируем и устанавливаем Garak из исходников
RUN git clone --depth 1 https://github.com/NVIDIA/garak.git /app/garak && \
    cd /app/garak && \
    pip install -e .

# Устанавливаем PyRIT и другие зависимости
RUN pip install \
    pyrit>=0.10.0 \
    typer>=0.9.0 \
    rich>=13.0.0 \
    pydantic>=2.0.0 \
    pyyaml>=6.0.0 \
    python-dotenv>=1.0.0 \
    httpx>=0.27.0

# Копируем проект llm-fuzzer
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Устанавливаем llm-fuzzer
RUN pip install -e .

# Копируем кастомные плагины garak
COPY custom_garak/ /app/custom_garak/

# Устанавливаем переменную для кастомных плагинов
ENV GARAK_PLUGIN_PATH=/app/custom_garak

# Копируем конфигурации
COPY configs/ /app/configs/

# Создаём директорию для отчётов
RUN mkdir -p /app/reports

# Создаём непривилегированного пользователя
RUN useradd -m -s /bin/bash fuzzer && \
    chown -R fuzzer:fuzzer /app

USER fuzzer

# Точка входа
ENTRYPOINT ["llm-fuzzer"]

# Команда по умолчанию
CMD ["--help"]
