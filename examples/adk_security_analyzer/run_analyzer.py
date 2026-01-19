#!/usr/bin/env python3
"""
CLI для запуска ADK Security Analyzer.

Использование:
    # Анализ одного файла
    python run_analyzer.py --file path/to/agent.py
    
    # Анализ директории
    python run_analyzer.py --directory path/to/agents/
    
    # Вывод в JSON
    python run_analyzer.py --file agent.py --output report.json
    
    # Подробный вывод
    python run_analyzer.py --file agent.py --verbose
    
    # Запуск с ADK Web UI
    python run_analyzer.py --web --port 8000
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

# Добавляем путь к модулю
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from examples.adk_security_analyzer.agent import (
    perform_full_analysis,
    format_report,
    security_analyzer_agent
)


def analyze_file(file_path: str, verbose: bool = False) -> Dict[str, Any]:
    """Анализирует один файл."""
    if verbose:
        print(f"Analyzing: {file_path}")
    
    result = perform_full_analysis(file_path)
    return result


def analyze_directory(directory: str, verbose: bool = False) -> List[Dict[str, Any]]:
    """Анализирует все Python файлы в директории."""
    results = []
    dir_path = Path(directory)
    
    if not dir_path.exists():
        print(f"Error: Directory not found: {directory}")
        return results
    
    python_files = list(dir_path.glob("*.py"))
    
    if not python_files:
        print(f"No Python files found in: {directory}")
        return results
    
    for file_path in python_files:
        if file_path.name.startswith("__"):
            continue
        
        if verbose:
            print(f"Analyzing: {file_path}")
        
        try:
            result = perform_full_analysis(str(file_path))
            results.append(result)
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            results.append({
                "status": "error",
                "file_path": str(file_path),
                "errors": [str(e)]
            })
    
    return results


def print_summary(results: List[Dict[str, Any]]) -> None:
    """Выводит сводку по всем проанализированным файлам."""
    print("\n" + "=" * 70)
    print("ANALYSIS SUMMARY")
    print("=" * 70)
    
    total_agents = 0
    total_vulns = 0
    scores = []
    
    for result in results:
        if result.get("status") == "error":
            print(f"❌ {result.get('file_path', 'unknown')}: Error - {result.get('errors', [])}")
            continue
        
        file_path = result.get("file_path", "unknown")
        reports = result.get("reports", [])
        
        for report in reports:
            agent_name = report.get("agent_name", "unknown")
            analysis = report.get("analysis", {})
            score = analysis.get("total_score", 0)
            vulns = analysis.get("vulnerability_summary", {}).get("total", 0)
            risk = analysis.get("risk_level", "UNKNOWN")
            
            risk_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }.get(risk, "⚪")
            
            print(f"{risk_emoji} {agent_name}: {score}/100 ({risk}) - {vulns} vulnerabilities")
            print(f"   File: {file_path}")
            
            total_agents += 1
            total_vulns += vulns
            scores.append(score)
    
    if scores:
        avg_score = sum(scores) / len(scores)
        print("\n" + "-" * 70)
        print(f"Total agents analyzed: {total_agents}")
        print(f"Total vulnerabilities found: {total_vulns}")
        print(f"Average security score: {avg_score:.1f}/100")


def save_json_report(results: List[Dict[str, Any]], output_path: str) -> None:
    """Сохраняет результаты в JSON файл."""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\nReport saved to: {output_path}")


def run_web_interface(port: int = 8000) -> None:
    """Запускает ADK Web интерфейс."""
    try:
        import subprocess
        print(f"Starting ADK Web UI on port {port}...")
        print(f"Open http://localhost:{port} in your browser")
        print("Press Ctrl+C to stop")
        
        # Переходим в директорию с агентом
        agent_dir = Path(__file__).parent
        subprocess.run(
            ["adk", "web", "--port", str(port)],
            cwd=agent_dir
        )
    except KeyboardInterrupt:
        print("\nStopped")
    except FileNotFoundError:
        print("Error: 'adk' command not found. Install with: pip install google-adk")


def run_interactive() -> None:
    """Запускает интерактивный режим анализа."""
    print("=" * 70)
    print("ADK SECURITY ANALYZER - Interactive Mode")
    print("=" * 70)
    print("Enter path to a Python file with ADK agent to analyze.")
    print("Type 'quit' or 'exit' to stop.")
    print("")
    
    while True:
        try:
            user_input = input("File path> ").strip()
            
            if user_input.lower() in ('quit', 'exit', 'q'):
                print("Goodbye!")
                break
            
            if not user_input:
                continue
            
            if not Path(user_input).exists():
                print(f"File not found: {user_input}")
                continue
            
            result = analyze_file(user_input, verbose=True)
            report = format_report(result)
            print("\n" + report + "\n")
            
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


def run_with_agent(file_path: str) -> None:
    """Запускает анализ с использованием LLM агента."""
    if security_analyzer_agent is None:
        print("Error: google-adk not installed.")
        print("Install with: pip install google-adk")
        print("Falling back to direct analysis...")
        result = analyze_file(file_path, verbose=True)
        print(format_report(result))
        return
    
    import asyncio
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types
    
    async def run_agent():
        session_service = InMemorySessionService()
        session = await session_service.create_session(
            app_name="security_analyzer",
            user_id="analyst",
            session_id="session1"
        )
        
        runner = Runner(
            agent=security_analyzer_agent,
            app_name="security_analyzer",
            session_service=session_service
        )
        
        query = f"Проанализируй безопасность агента из файла: {file_path}"
        content = types.Content(role='user', parts=[types.Part(text=query)])
        
        print("Running analysis with LLM agent...")
        
        async for event in runner.run_async(
            user_id="analyst",
            session_id="session1",
            new_message=content
        ):
            if event.is_final_response() and event.content:
                for part in event.content.parts:
                    if part.text:
                        print(part.text)
    
    try:
        asyncio.run(run_agent())
    except Exception as e:
        print(f"Error running agent: {e}")
        print("Falling back to direct analysis...")
        result = analyze_file(file_path, verbose=True)
        print(format_report(result))


def main():
    parser = argparse.ArgumentParser(
        description="ADK Security Analyzer - анализ безопасности ADK агентов",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python run_analyzer.py --file test_agents/vulnerable_agent.py
  python run_analyzer.py --directory test_agents/ --output report.json
  python run_analyzer.py --interactive
  python run_analyzer.py --web --port 8000
        """
    )
    
    parser.add_argument(
        "--file", "-f",
        type=str,
        help="Путь к Python файлу с агентом для анализа"
    )
    
    parser.add_argument(
        "--directory", "-d",
        type=str,
        help="Путь к директории с агентами для анализа"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Путь для сохранения JSON отчёта"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Подробный вывод"
    )
    
    parser.add_argument(
        "--web", "-w",
        action="store_true",
        help="Запустить ADK Web интерфейс"
    )
    
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8000,
        help="Порт для Web интерфейса (по умолчанию: 8000)"
    )
    
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Запустить в интерактивном режиме"
    )
    
    parser.add_argument(
        "--use-agent",
        action="store_true",
        help="Использовать LLM агента для анализа (требует API ключ)"
    )
    
    args = parser.parse_args()
    
    # Проверяем аргументы
    if args.web:
        run_web_interface(args.port)
        return
    
    if args.interactive:
        run_interactive()
        return
    
    if not args.file and not args.directory:
        # По умолчанию анализируем тестовые агенты
        test_dir = Path(__file__).parent / "test_agents"
        if test_dir.exists():
            print("No file or directory specified. Analyzing test agents...")
            args.directory = str(test_dir)
        else:
            parser.print_help()
            return
    
    results = []
    
    if args.file:
        if args.use_agent:
            run_with_agent(args.file)
            return
        else:
            result = analyze_file(args.file, args.verbose)
            results.append(result)
            
            if args.verbose or not args.output:
                print(format_report(result))
    
    if args.directory:
        dir_results = analyze_directory(args.directory, args.verbose)
        results.extend(dir_results)
        
        if not args.output:
            for result in dir_results:
                print(format_report(result))
                print("\n" + "=" * 70 + "\n")
        
        print_summary(dir_results)
    
    if args.output:
        save_json_report(results, args.output)


if __name__ == "__main__":
    main()

