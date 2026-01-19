"""
Парсер Python-кода для извлечения определений ADK агентов.

Использует AST для статического анализа исходного кода и извлечения:
- Определений Agent/LlmAgent
- Инструкций (instruction)
- Инструментов (tools)
- Описаний (description)
- Моделей (model)
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ToolDefinition:
    """Определение инструмента агента."""
    name: str
    source_code: str
    docstring: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    line_number: int = 0


@dataclass
class AgentDefinition:
    """Определение агента, извлечённое из кода."""
    name: str
    variable_name: str
    model: Optional[str] = None
    instruction: Optional[str] = None
    description: Optional[str] = None
    tools: List[ToolDefinition] = field(default_factory=list)
    tool_names: List[str] = field(default_factory=list)
    line_number: int = 0
    raw_source: str = ""


class AgentCodeParser(ast.NodeVisitor):
    """AST-визитор для извлечения определений агентов."""
    
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.source_lines = source_code.split('\n')
        self.agents: List[AgentDefinition] = []
        self.functions: Dict[str, ToolDefinition] = {}
        self.current_file = ""
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Извлекает определения функций (потенциальные инструменты)."""
        # Получаем исходный код функции
        start_line = node.lineno - 1
        end_line = node.end_lineno if node.end_lineno else start_line + 1
        source_lines = self.source_lines[start_line:end_line]
        source_code = '\n'.join(source_lines)
        
        # Получаем docstring
        docstring = ast.get_docstring(node)
        
        # Получаем параметры
        parameters = []
        for arg in node.args.args:
            param_name = arg.arg
            if arg.annotation:
                try:
                    param_type = ast.unparse(arg.annotation)
                    parameters.append(f"{param_name}: {param_type}")
                except:
                    parameters.append(param_name)
            else:
                parameters.append(param_name)
        
        self.functions[node.name] = ToolDefinition(
            name=node.name,
            source_code=source_code,
            docstring=docstring,
            parameters=parameters,
            line_number=node.lineno
        )
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Извлекает определения агентов через присваивание."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                variable_name = target.id
                if isinstance(node.value, ast.Call):
                    self._process_agent_call(node.value, variable_name, node.lineno)
        
        self.generic_visit(node)
    
    def _process_agent_call(self, call: ast.Call, variable_name: str, line_number: int) -> None:
        """Обрабатывает вызов Agent/LlmAgent."""
        # Определяем имя вызываемого класса
        func_name = ""
        if isinstance(call.func, ast.Name):
            func_name = call.func.id
        elif isinstance(call.func, ast.Attribute):
            func_name = call.func.attr
        
        # Проверяем, является ли это агентом
        if func_name not in ("Agent", "LlmAgent"):
            return
        
        agent = AgentDefinition(
            name="",
            variable_name=variable_name,
            line_number=line_number
        )
        
        # Извлекаем аргументы
        for keyword in call.keywords:
            if keyword.arg == "name":
                agent.name = self._extract_string_value(keyword.value)
            elif keyword.arg == "model":
                agent.model = self._extract_string_value(keyword.value)
            elif keyword.arg == "instruction":
                agent.instruction = self._extract_string_value(keyword.value)
            elif keyword.arg == "description":
                agent.description = self._extract_string_value(keyword.value)
            elif keyword.arg == "tools":
                agent.tool_names = self._extract_tool_names(keyword.value)
        
        # Если имя не задано, используем имя переменной
        if not agent.name:
            agent.name = variable_name
        
        # Связываем инструменты с их определениями
        for tool_name in agent.tool_names:
            if tool_name in self.functions:
                agent.tools.append(self.functions[tool_name])
        
        # Получаем исходный код определения агента
        try:
            start_line = line_number - 1
            # Находим конец определения
            end_line = start_line + 1
            paren_count = 0
            started = False
            for i, line in enumerate(self.source_lines[start_line:], start=start_line):
                for char in line:
                    if char == '(':
                        paren_count += 1
                        started = True
                    elif char == ')':
                        paren_count -= 1
                if started and paren_count == 0:
                    end_line = i + 1
                    break
            agent.raw_source = '\n'.join(self.source_lines[start_line:end_line])
        except:
            pass
        
        self.agents.append(agent)
    
    def _extract_string_value(self, node: ast.expr) -> str:
        """Извлекает строковое значение из AST узла."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Str):  # Python 3.7 compatibility
            return node.s
        elif isinstance(node, ast.JoinedStr):  # f-string
            # Попытка извлечь статические части f-string
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.Str):
                    parts.append(value.s)
            return ''.join(parts)
        return ""
    
    def _extract_tool_names(self, node: ast.expr) -> List[str]:
        """Извлекает имена инструментов из списка."""
        names = []
        if isinstance(node, ast.List):
            for elt in node.elts:
                if isinstance(elt, ast.Name):
                    names.append(elt.id)
                elif isinstance(elt, ast.Call):
                    # Может быть FunctionTool(func=...)
                    if isinstance(elt.func, ast.Name):
                        names.append(f"[wrapped]{elt.func.id}")
        return names


def parse_agent_code(file_path: str) -> Dict[str, Any]:
    """
    Парсит Python-файл и извлекает определения агентов.
    
    Args:
        file_path: Путь к Python-файлу с определением агента.
        
    Returns:
        Словарь с информацией об агентах:
        - agents: список найденных агентов
        - functions: список найденных функций (потенциальные tools)
        - errors: список ошибок парсинга
    """
    result = {
        "status": "success",
        "file_path": file_path,
        "agents": [],
        "functions": [],
        "errors": []
    }
    
    path = Path(file_path)
    
    # Проверяем существование файла
    if not path.exists():
        result["status"] = "error"
        result["errors"].append(f"File not found: {file_path}")
        return result
    
    if not path.suffix == ".py":
        result["status"] = "error"
        result["errors"].append(f"Not a Python file: {file_path}")
        return result
    
    try:
        source_code = path.read_text(encoding='utf-8')
    except Exception as e:
        result["status"] = "error"
        result["errors"].append(f"Failed to read file: {str(e)}")
        return result
    
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        result["status"] = "error"
        result["errors"].append(f"Syntax error in file: {str(e)}")
        return result
    
    parser = AgentCodeParser(source_code)
    parser.visit(tree)
    
    # Преобразуем результаты в сериализуемый формат
    for agent in parser.agents:
        agent_dict = {
            "name": agent.name,
            "variable_name": agent.variable_name,
            "model": agent.model,
            "instruction": agent.instruction,
            "description": agent.description,
            "tool_names": agent.tool_names,
            "line_number": agent.line_number,
            "tools": []
        }
        
        for tool in agent.tools:
            agent_dict["tools"].append({
                "name": tool.name,
                "source_code": tool.source_code,
                "docstring": tool.docstring,
                "parameters": tool.parameters,
                "line_number": tool.line_number
            })
        
        result["agents"].append(agent_dict)
    
    for func_name, func_def in parser.functions.items():
        result["functions"].append({
            "name": func_def.name,
            "source_code": func_def.source_code,
            "docstring": func_def.docstring,
            "parameters": func_def.parameters,
            "line_number": func_def.line_number
        })
    
    if not result["agents"]:
        result["errors"].append("No Agent/LlmAgent definitions found in file")
    
    return result


def parse_agent_code_from_string(source_code: str, filename: str = "<string>") -> Dict[str, Any]:
    """
    Парсит Python-код из строки и извлекает определения агентов.
    
    Args:
        source_code: Исходный код Python.
        filename: Имя файла для сообщений об ошибках.
        
    Returns:
        Словарь с информацией об агентах.
    """
    result = {
        "status": "success",
        "file_path": filename,
        "agents": [],
        "functions": [],
        "errors": []
    }
    
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        result["status"] = "error"
        result["errors"].append(f"Syntax error: {str(e)}")
        return result
    
    parser = AgentCodeParser(source_code)
    parser.visit(tree)
    
    # Преобразуем результаты
    for agent in parser.agents:
        agent_dict = {
            "name": agent.name,
            "variable_name": agent.variable_name,
            "model": agent.model,
            "instruction": agent.instruction,
            "description": agent.description,
            "tool_names": agent.tool_names,
            "line_number": agent.line_number,
            "tools": []
        }
        
        for tool in agent.tools:
            agent_dict["tools"].append({
                "name": tool.name,
                "source_code": tool.source_code,
                "docstring": tool.docstring,
                "parameters": tool.parameters,
                "line_number": tool.line_number
            })
        
        result["agents"].append(agent_dict)
    
    for func_name, func_def in parser.functions.items():
        result["functions"].append({
            "name": func_def.name,
            "source_code": func_def.source_code,
            "docstring": func_def.docstring,
            "parameters": func_def.parameters,
            "line_number": func_def.line_number
        })
    
    return result

