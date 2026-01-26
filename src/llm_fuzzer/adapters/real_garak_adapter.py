"""
RealGarakAdapter - чистый интерфейс к Garak.

LLM Fuzzer НЕ содержит логики детекции — только адаптация вызовов Garak.
Вся логика атак и детекции внутри Garak.
"""

import asyncio
import json
import logging
import tempfile
import os
from typing import List, Optional, Dict, Any
from pathlib import Path

from .base import BaseAdapter
from llm_fuzzer.core.target import TargetConfig
from llm_fuzzer.core.check import (
    CheckConfig, 
    CheckResult, 
    CheckStatus,
    CheckCategory,
    EngineType,
    Finding,
)

logger = logging.getLogger(__name__)


class RealGarakAdapter(BaseAdapter):
    """
    Чистый адаптер к Garak.
    
    НЕ содержит логики детекции!
    Только:
    1. Конфигурация Garak generator
    2. Запуск Garak probes + detectors через harness
    3. Адаптация результатов Garak в наш формат
    """
    
    def __init__(self):
        super().__init__()
        self._garak_available = False
        self._garak_version: Optional[str] = None
    
    @property
    def name(self) -> str:
        return "garak"
    
    @property
    def version(self) -> str:
        return self._garak_version or "unknown"
    
    async def initialize(self) -> None:
        """Проверка доступности Garak."""
        try:
            import garak
            from garak.generators.rest import RestGenerator
            
            self._garak_version = getattr(garak, "__version__", "available")
            self._garak_available = True
            self._initialized = True
            
            self._logger.info(f"Garak initialized: v{self._garak_version}")
            
        except ImportError as e:
            self._logger.warning(f"Garak not available: {e}")
            self._garak_available = False
            self._initialized = False
    
    def supports_check(self, check: CheckConfig) -> bool:
        from llm_fuzzer.core.check import EngineType
        return check.engine in [EngineType.GARAK, EngineType.AUTO, None]
    
    async def cleanup(self) -> None:
        pass
    
    async def run_check(
        self, 
        target: TargetConfig, 
        check: CheckConfig
    ) -> CheckResult:
        """Запустить проверку через Garak."""
        import time
        start_time = time.time()
        
        if not self._garak_available:
            return self._create_error_result(
                check, 
                Exception("Garak not available"),
                time.time() - start_time
            )
        
        try:
            # Запускаем Garak и получаем его результаты
            loop = asyncio.get_event_loop()
            result_data = await loop.run_in_executor(
                None,
                lambda: self._run_garak_sync(target, check)
            )
            
            duration = time.time() - start_time
            findings = result_data["findings"]
            total_prompts = result_data["total_prompts"]
            successful_attacks = result_data["successful_attacks"]
            
            if findings:
                return self._create_failed_result(
                    check, findings, duration, total_prompts, successful_attacks
                )
            else:
                return self._create_passed_result(check, duration, total_prompts)
                
        except Exception as e:
            duration = time.time() - start_time
            self._logger.error(f"Garak check failed: {e}")
            return self._create_error_result(check, e, duration)
    
    def _run_garak_sync(
        self,
        target: TargetConfig,
        check: CheckConfig
    ) -> Dict[str, Any]:
        """
        Запустить Garak синхронно — ВСЯ логика внутри Garak!
        
        Используем:
        - garak.generators.rest.RestGenerator
        - garak.probes.* (реальные probes)
        - garak.detectors.* (реальные детекторы)
        - garak.harnesses.base.Harness
        - garak.evaluators
        """
        from garak import _config
        from garak import _plugins
        from garak.generators.rest import RestGenerator
        from garak.harnesses.base import Harness
        from garak import evaluators
        
        findings = []
        
        # Создаём временные файлы для отчётов Garak
        tmpdir = tempfile.mkdtemp()
        report_path = os.path.join(tmpdir, "garak_report.jsonl")
        hit_path = os.path.join(tmpdir, "garak_hits.jsonl")
        
        try:
            # Инициализация Garak
            _config.load_base_config()
            _config.transient.reportfile = open(report_path, "w")
            _config.transient.hitlogfile = open(hit_path, "w")
            
            # 1. Создаём РЕАЛЬНЫЙ Garak RestGenerator
            generator = self._create_generator(target, check)
            
            # 2. Загружаем РЕАЛЬНЫЕ Garak probes с учётом max_prompts
            probe_names = check.garak_probes or self._get_default_probes(check.category)
            probes = self._load_probes(probe_names, max_prompts=check.max_prompts)
            
            if not probes:
                self._logger.warning(f"No probes loaded for {check.id}")
                return {"findings": [], "total_prompts": 0, "successful_attacks": 0}
            
            # 3. Загружаем РЕАЛЬНЫЕ Garak detectors
            detector_names = check.garak_detectors or self._get_default_detectors(check.category)
            detectors = self._load_detectors(detector_names)
            
            if not detectors:
                self._logger.warning(f"No detectors loaded for {check.id}")
                return {"findings": [], "total_prompts": 0, "successful_attacks": 0}
            
            # 4. Создаём evaluator
            evaluator = evaluators.ThresholdEvaluator()
            
            # 5. Создаём harness
            harness = Harness()
            
            # 6. Запускаем Garak harness — ВСЯ логика здесь!
            harness.run(
                model=generator,
                probes=probes,
                detectors=detectors,
                evaluator=evaluator,
                announce_probe=False
            )
            
            # Закрываем файлы
            _config.transient.reportfile.close()
            _config.transient.hitlogfile.close()
            
            # 7. Парсим результаты Garak
            result_data = self._parse_garak_results(report_path, hit_path, check)
            
        except Exception as e:
            self._logger.error(f"Garak execution error: {e}")
            raise
        finally:
            # Cleanup
            try:
                if os.path.exists(report_path):
                    os.remove(report_path)
                if os.path.exists(hit_path):
                    os.remove(hit_path)
                os.rmdir(tmpdir)
            except:
                pass
        
        return result_data
    
    def _create_generator(self, target: TargetConfig, check: Optional[CheckConfig] = None):
        """
        Создать Garak RestGenerator.
        
        Args:
            target: Конфигурация цели
            check: Конфигурация проверки (для generations)
        """
        from garak.generators.rest import RestGenerator
        
        # Формируем endpoint
        endpoint = target.endpoint
        if not endpoint.endswith("/chat/completions"):
            endpoint = endpoint.rstrip("/") + "/chat/completions"
        
        # Создаём generator
        gen = RestGenerator(uri=endpoint)
        gen.verify_ssl = False
        gen.headers = {
            "Authorization": f"Bearer {target.get_api_key()}",
            "Content-Type": "application/json",
        }
        gen.req_template = json.dumps({
            "model": target.model or "gpt-4",
            "messages": [{"role": "user", "content": "$INPUT"}],
            "max_tokens": 1024,
        })
        gen.response_json = False  # Мы парсим JSON вручную
        gen.name = target.model or "gpt-4"
        gen.request_timeout = target.timeout or 60
        
        # Количество генераций (повторов для каждого промпта)
        if check and check.generations > 1:
            gen.generations = check.generations
            self._logger.debug(f"Set generations: {check.generations}")
        
        return gen
    
    def _load_probes(
        self, 
        probe_names: List[str],
        max_prompts: Optional[int] = None
    ) -> list:
        """
        Загрузить РЕАЛЬНЫЕ Garak probes.
        
        Args:
            probe_names: Список имён probes
            max_prompts: Ограничить количество промптов в каждом probe
        """
        from garak import _plugins
        
        probes = []
        for name in probe_names:
            try:
                # Формат: "dan.Dan_11_0" или "probes.dan.Dan_11_0"
                if name.startswith("probes."):
                    plugin_name = name
                else:
                    plugin_name = f"probes.{name}"
                
                probe = _plugins.load_plugin(plugin_name)
                if probe:
                    # Применяем max_prompts если указан
                    if max_prompts and hasattr(probe, 'prompts'):
                        original_count = len(probe.prompts)
                        probe.prompts = probe.prompts[:max_prompts]
                        self._logger.debug(
                            f"Limited probe {name}: {original_count} -> {len(probe.prompts)} prompts"
                        )
                    
                    probes.append(probe)
                    self._logger.debug(f"Loaded probe: {name}")
                    
            except Exception as e:
                self._logger.warning(f"Failed to load probe {name}: {e}")
        
        return probes
    
    def _load_detectors(self, detector_names: List[str]) -> list:
        """Загрузить РЕАЛЬНЫЕ Garak detectors."""
        from garak import _plugins
        
        detectors = []
        for name in detector_names:
            try:
                # Формат: "mitigation.MitigationBypass" или "detectors.mitigation.MitigationBypass"
                if name.startswith("detectors."):
                    plugin_name = name
                else:
                    plugin_name = f"detectors.{name}"
                
                detector = _plugins.load_plugin(plugin_name)
                if detector:
                    detectors.append(detector)
                    self._logger.debug(f"Loaded detector: {name}")
                    
            except Exception as e:
                self._logger.warning(f"Failed to load detector {name}: {e}")
        
        return detectors
    
    def _parse_garak_results(
        self, 
        report_path: str, 
        hit_path: str,
        check: CheckConfig
    ) -> Dict[str, Any]:
        """
        Парсинг результатов Garak — только адаптация формата.
        
        Garak записывает:
        - report.jsonl — все attempts
        - hits.jsonl — успешные атаки (уязвимости)
        
        Возвращает словарь с findings, total_prompts, successful_attacks.
        """
        findings = []
        total_prompts = 0
        
        # Читаем hits — это успешные атаки (уязвимости)
        try:
            with open(hit_path, "r") as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        
                        # Извлекаем prompt
                        prompt = ""
                        if "prompt" in record:
                            prompt_data = record["prompt"]
                            if isinstance(prompt_data, dict) and "turns" in prompt_data:
                                for turn in prompt_data["turns"]:
                                    if turn.get("role") == "user":
                                        content = turn.get("content", {})
                                        if isinstance(content, dict):
                                            prompt = content.get("text", "")
                                        else:
                                            prompt = str(content)
                                        break
                            else:
                                prompt = str(prompt_data)
                        
                        # Извлекаем response
                        response = ""
                        if "output" in record:
                            output = record["output"]
                            if isinstance(output, dict):
                                response = output.get("text", str(output))
                            else:
                                response = str(output)
                            
                            # Garak возвращает JSON — парсим content
                            try:
                                data = json.loads(response)
                                if "choices" in data:
                                    response = data["choices"][0].get("message", {}).get("content", response)
                            except:
                                pass
                        
                        # Извлекаем detector info
                        detector = record.get("detector", "")
                        score = record.get("score", 1.0)
                        
                        finding = Finding(
                            prompt=prompt,
                            response=response,
                            evidence=f"Garak detector: {detector}",
                            confidence=float(score) if isinstance(score, (int, float)) else 0.9,
                            metadata={
                                "probe": record.get("probe", ""),
                                "detector": detector,
                                "goal": record.get("goal", ""),
                                "engine": "garak",
                                "category": str(check.category),
                            }
                        )
                        findings.append(finding)
                        
                    except json.JSONDecodeError:
                        continue
                        
        except FileNotFoundError:
            pass
        
        # Если hits пусты, проверяем report на failures
        if not findings:
            try:
                with open(report_path, "r") as f:
                    for line in f:
                        try:
                            record = json.loads(line.strip())
                            
                            # Ищем attempts со status=2 (FAIL) и detector_results
                            if record.get("entry_type") == "attempt" and record.get("status") == 2:
                                detector_results = record.get("detector_results", {})
                                
                                for detector_name, scores in detector_results.items():
                                    if scores and any(s > 0.5 for s in scores):
                                        # Извлекаем prompt
                                        prompt = ""
                                        prompt_data = record.get("prompt", {})
                                        if isinstance(prompt_data, dict) and "turns" in prompt_data:
                                            for turn in prompt_data["turns"]:
                                                if turn.get("role") == "user":
                                                    content = turn.get("content", {})
                                                    if isinstance(content, dict):
                                                        prompt = content.get("text", "")
                                                    break
                                        
                                        # Извлекаем response
                                        response = ""
                                        outputs = record.get("outputs", [])
                                        if outputs:
                                            output = outputs[0]
                                            if isinstance(output, dict):
                                                response = output.get("text", "")
                                            else:
                                                response = str(output)
                                            
                                            # Parse JSON response
                                            try:
                                                data = json.loads(response)
                                                if "choices" in data:
                                                    response = data["choices"][0].get("message", {}).get("content", response)
                                            except:
                                                pass
                                        
                                        finding = Finding(
                                            prompt=prompt,
                                            response=response,
                                            evidence=f"Garak detector {detector_name}: scores {scores}",
                                            confidence=max(scores),
                                            metadata={
                                                "probe": record.get("probe_classname", ""),
                                                "detector": detector_name,
                                                "engine": "garak",
                                            }
                                        )
                                        findings.append(finding)
                                        
                        except json.JSONDecodeError:
                            continue
                            
            except FileNotFoundError:
                pass
        
        # Подсчитываем total_prompts из report.jsonl
        # Считаем уникальные prompts
        unique_prompts = set()
        try:
            with open(report_path, "r") as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        if record.get("entry_type") == "attempt":
                            total_prompts += 1
                            # Также сохраняем уникальные prompt для подсчёта
                            prompt_data = record.get("prompt", {})
                            if isinstance(prompt_data, dict) and "turns" in prompt_data:
                                for turn in prompt_data["turns"]:
                                    if turn.get("role") == "user":
                                        content = turn.get("content", {})
                                        if isinstance(content, dict):
                                            unique_prompts.add(content.get("text", "")[:100])
                                        break
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        
        # Уникальные уязвимые prompts
        vulnerable_prompts = set()
        for f in findings:
            vulnerable_prompts.add(f.prompt[:100])
        
        successful_attacks = len(vulnerable_prompts)
        
        return {
            "findings": findings,
            "total_prompts": total_prompts,
            "successful_attacks": successful_attacks,
        }
    
    def _get_default_probes(self, category: CheckCategory) -> List[str]:
        """Маппинг категорий на Garak probes."""
        mapping = {
            CheckCategory.JAILBREAK: [
                "dan.Dan_11_0",
                "dan.Dan_10_0",
            ],
            CheckCategory.INJECTION: [
                "promptinject.HijackHateHumansMini",
            ],
            CheckCategory.TOXICITY: [
                "realtoxicityprompts.RTPBlank",
            ],
            CheckCategory.LEAKAGE: [
                "lmrc.Anthropomorphisation",
            ],
        }
        return mapping.get(category, [])
    
    def _get_default_detectors(self, category: CheckCategory) -> List[str]:
        """Маппинг категорий на Garak detectors."""
        mapping = {
            CheckCategory.JAILBREAK: [
                "mitigation.MitigationBypass",
            ],
            CheckCategory.INJECTION: [
                "always.Fail",  # Для injection любой ответ = уязвимость
            ],
            CheckCategory.TOXICITY: [
                "toxicity.ToxicCommentModel",
            ],
            CheckCategory.LEAKAGE: [
                "always.Fail",
            ],
        }
        return mapping.get(category, ["mitigation.MitigationBypass"])
    
    def _create_passed_result(
        self, 
        check: CheckConfig, 
        duration: float,
        total_prompts: int = 0
    ) -> CheckResult:
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            status=CheckStatus.PASSED,
            category=check.category,
            severity=check.severity,
            engine_used=self.name,
            duration_seconds=duration,
            findings=[],
            total_prompts=total_prompts,
            successful_attacks=0,
        )
    
    def _create_failed_result(
        self, 
        check: CheckConfig, 
        findings: List[Finding],
        duration: float,
        total_prompts: int = 0,
        successful_attacks: int = 0
    ) -> CheckResult:
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            status=CheckStatus.FAILED,
            category=check.category,
            severity=check.severity,
            engine_used=self.name,
            duration_seconds=duration,
            findings=findings,
            total_prompts=total_prompts,
            successful_attacks=successful_attacks if successful_attacks else len(findings),
        )
    
    def _create_error_result(
        self,
        check: CheckConfig,
        error: Exception,
        duration: float
    ) -> CheckResult:
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            status=CheckStatus.ERROR,
            category=check.category,
            severity=check.severity,
            engine_used=self.name,
            duration_seconds=duration,
            findings=[],
            error_message=str(error),
        )
