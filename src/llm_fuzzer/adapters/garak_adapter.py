"""
GarakAdapter - адаптер для движка Garak.

Garak - это инструмент от NVIDIA для тестирования LLM на уязвимости.
Использует концепции probes (атаки) и detectors (обнаружение).
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Dict, Any

from .base import BaseAdapter
from llm_fuzzer.core.target import TargetConfig, TargetType
from llm_fuzzer.core.check import (
    CheckConfig, 
    CheckResult, 
    CheckStatus,
    CheckCategory,
    EngineType,
    Finding,
)

logger = logging.getLogger(__name__)


class GarakAdapter(BaseAdapter):
    """
    Адаптер для Garak vulnerability scanner.
    
    Особенности:
    - Запускает garak как subprocess
    - Поддерживает кастомные probes и detectors
    - Парсит JSON output от garak
    """
    
    # Маппинг категорий на garak probes
    CATEGORY_TO_PROBES: Dict[CheckCategory, List[str]] = {
        CheckCategory.JAILBREAK: [
            "probes.dan",
            "probes.gcg",
            "probes.knownbadsignatures",
        ],
        CheckCategory.INJECTION: [
            "probes.promptinject",
            "probes.xss",
        ],
        CheckCategory.TOXICITY: [
            "probes.realtoxicityprompts",
        ],
        CheckCategory.LEAKAGE: [
            "probes.lmrc",
        ],
        CheckCategory.HALLUCINATION: [
            "probes.snowball",
        ],
    }
    
    def __init__(
        self,
        garak_path: Optional[str] = None,
        custom_plugins_path: Optional[str] = None,
    ):
        """
        Инициализация GarakAdapter.
        
        Args:
            garak_path: Путь к установке garak (опционально)
            custom_plugins_path: Путь к кастомным плагинам
        """
        super().__init__()
        self._garak_path = garak_path
        self._custom_plugins_path = custom_plugins_path
        self._garak_version: Optional[str] = None
    
    @property
    def name(self) -> str:
        return "garak"
    
    @property
    def version(self) -> str:
        return self._garak_version or "unknown"
    
    async def initialize(self) -> None:
        """Инициализация адаптера - проверка доступности garak."""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, "-m", "garak", "--version"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                self._garak_version = result.stdout.strip()
                self._logger.info(f"Garak initialized: {self._garak_version}")
            else:
                self._logger.warning(f"Garak version check failed: {result.stderr}")
                self._garak_version = "available"
                
            self._initialized = True
            
        except FileNotFoundError:
            raise RuntimeError(
                "Garak not found. Install with: pip install -e /app/garak"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Garak: {e}")
    
    def supports_check(self, check: CheckConfig) -> bool:
        """Проверить поддержку проверки."""
        # Garak поддерживает проверки с engine=garak или auto
        if check.engine not in (EngineType.GARAK, EngineType.AUTO):
            return False
        
        # Проверяем категорию
        supported_categories = [
            CheckCategory.JAILBREAK,
            CheckCategory.INJECTION,
            CheckCategory.TOXICITY,
            CheckCategory.LEAKAGE,
            CheckCategory.HALLUCINATION,
            CheckCategory.BIAS,
            CheckCategory.CUSTOM,
        ]
        
        return check.category in supported_categories
    
    async def run_check(
        self, 
        target: TargetConfig, 
        check: CheckConfig
    ) -> CheckResult:
        """
        Выполнить проверку с помощью Garak.
        
        Args:
            target: Конфигурация таргета
            check: Конфигурация проверки
            
        Returns:
            Результат проверки
        """
        start_time = time.time()
        
        try:
            # Определяем probes для запуска
            probes = self._get_probes_for_check(check)
            if not probes:
                return self._create_error_result(
                    check, 
                    ValueError(f"No probes defined for category {check.category}"),
                    0.0
                )
            
            # Определяем detectors
            detectors = check.garak_detectors or ["detectors.always.Fail"]
            
            # Создаём временный файл для конфигурации
            with tempfile.NamedTemporaryFile(
                mode='w', 
                suffix='.json', 
                delete=False
            ) as config_file:
                garak_config = self._build_garak_config(target, probes, detectors)
                json.dump(garak_config, config_file)
                config_path = config_file.name
            
            # Создаём временную директорию для output
            with tempfile.TemporaryDirectory() as output_dir:
                # Запускаем garak
                result = await self._run_garak(
                    config_path=config_path,
                    output_dir=output_dir,
                    target=target,
                    probes=probes,
                )
                
                duration = time.time() - start_time
                
                # Парсим результаты
                findings = self._parse_garak_output(output_dir, check)
                
                if findings:
                    return self._create_failed_result(
                        check=check,
                        findings=findings,
                        duration=duration,
                        raw_output=result,
                    )
                else:
                    return self._create_passed_result(
                        check=check,
                        duration=duration,
                        raw_output=result,
                    )
                    
        except Exception as e:
            duration = time.time() - start_time
            self._logger.error(f"Garak check failed: {e}")
            return self._create_error_result(check, e, duration)
        finally:
            # Очищаем временный конфиг
            try:
                os.unlink(config_path)
            except:
                pass
    
    def _get_probes_for_check(self, check: CheckConfig) -> List[str]:
        """Получить список probes для проверки."""
        # Если указаны конкретные probes, используем их
        if check.garak_probes:
            return check.garak_probes
        
        # Иначе используем маппинг по категории
        return self.CATEGORY_TO_PROBES.get(check.category, [])
    
    def _build_garak_config(
        self,
        target: TargetConfig,
        probes: List[str],
        detectors: List[str],
    ) -> Dict[str, Any]:
        """Построить конфигурацию для garak."""
        # Определяем generator на основе типа таргета
        if target.type == TargetType.OPENAI:
            generator = {
                "model_type": "openai",
                "model_name": target.model,
                "api_key": target.get_api_key(),
            }
            if target.endpoint != "https://api.openai.com/v1":
                generator["api_base"] = target.endpoint
        else:
            # Для кастомных endpoint используем REST generator
            generator = {
                "model_type": "rest",
                "uri": target.endpoint,
                "api_key": target.get_api_key(),
                "model_name": target.model,
            }
        
        return {
            "generator": generator,
            "probes": probes,
            "detectors": detectors,
            "reporting": {
                "format": "json",
            }
        }
    
    async def _run_garak(
        self,
        config_path: str,
        output_dir: str,
        target: TargetConfig,
        probes: List[str],
    ) -> Dict[str, Any]:
        """Запустить garak subprocess."""
        # Формируем команду
        cmd = [
            sys.executable, "-m", "garak",
            "--model_type", self._get_model_type(target),
            "--model_name", target.model,
            "--probes", ",".join(probes),
            "--report_prefix", os.path.join(output_dir, "report"),
        ]
        
        # Добавляем API ключ через env
        env = os.environ.copy()
        env["OPENAI_API_KEY"] = target.get_api_key()
        
        if target.endpoint:
            env["OPENAI_API_BASE"] = target.endpoint
        
        # Добавляем кастомные плагины если есть
        if self._custom_plugins_path:
            env["GARAK_PLUGIN_PATH"] = self._custom_plugins_path
        
        self._logger.info(f"Running garak: {' '.join(cmd)}")
        
        result = await asyncio.to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=300,  # 5 минут таймаут
        )
        
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    
    def _get_model_type(self, target: TargetConfig) -> str:
        """Получить тип модели для garak."""
        type_mapping = {
            TargetType.OPENAI: "openai",
            TargetType.AZURE: "azure",
            TargetType.HUGGINGFACE: "huggingface",
            TargetType.LOCAL: "ggml",
            TargetType.CUSTOM: "rest",
        }
        return type_mapping.get(target.type, "openai")
    
    def _parse_garak_output(
        self, 
        output_dir: str,
        check: CheckConfig
    ) -> List[Finding]:
        """Парсить output от garak."""
        findings = []
        
        # Ищем JSON файлы с результатами
        output_path = Path(output_dir)
        for json_file in output_path.glob("*.json"):
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)
                
                # Парсим результаты garak
                for entry in data.get("results", []):
                    if entry.get("status") == "fail":
                        finding = Finding(
                            prompt=entry.get("prompt", ""),
                            response=entry.get("output", ""),
                            evidence=entry.get("trigger", ""),
                            confidence=entry.get("score", 1.0),
                            metadata={
                                "probe": entry.get("probe", ""),
                                "detector": entry.get("detector", ""),
                            }
                        )
                        findings.append(finding)
                        
            except Exception as e:
                self._logger.warning(f"Failed to parse {json_file}: {e}")
        
        return findings
    
    async def cleanup(self) -> None:
        """Очистка ресурсов."""
        self._initialized = False
