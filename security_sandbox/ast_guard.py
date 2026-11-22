import ast
from typing import List, Set, Tuple

class SecurityViolationError(Exception):
    """Raised when an AST node violates code execution policy."""
    pass

class ASTSecurityGuard(ast.NodeVisitor):
    """
    Static AST Code Inspector for LLM-Generated Python Scripts.
    Detects unauthorized OS calls, dunder exploits, dynamic evaluation,
    and filesystem write escapes prior to execution.
    """

    DEFAULT_BLOCKED_MODULES: Set[str] = {
        "os", "sys", "subprocess", "shutil", "socket", "pty",
        "ctypes", "multiprocessing", "threading", "signal",
        "posix", "winreg", "builtins", "__builtin__", "importlib"
    }

    DEFAULT_BLOCKED_CALLS: Set[str] = {
        "eval", "exec", "compile", "__import__", "globals",
        "locals", "breakpoint", "getattr", "setattr", "delattr"
    }

    def __init__(self, blocked_modules: Set[str] = None, blocked_calls: Set[str] = None):
        self.blocked_modules = blocked_modules or self.DEFAULT_BLOCKED_MODULES
        self.blocked_calls = blocked_calls or self.DEFAULT_BLOCKED_CALLS
        self.violations: List[Tuple[int, str]] = []

    def validate(self, source_code: str) -> bool:
        """
        Parses source code into an AST and visits all nodes.
        Raises SecurityViolationError if malicious patterns are discovered.
        """
        self.violations.clear()
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            raise SecurityViolationError(f"Syntax error in candidate script: {e}")

        self.visit(tree)

        if self.violations:
            details = "; ".join(f"Line {line}: {msg}" for line, msg in self.violations)
            raise SecurityViolationError(f"Security validation failed ({len(self.violations)} violations): {details}")

        return True

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            base_pkg = alias.name.split('.')[0]
            if base_pkg in self.blocked_modules:
                self.violations.append((node.lineno, f"Unauthorized module import: '{alias.name}'"))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            base_pkg = node.module.split('.')[0]
            if base_pkg in self.blocked_modules:
                self.violations.append((node.lineno, f"Unauthorized from-import module: '{node.module}'"))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Check standard identifier calls (e.g. eval(...))
        if isinstance(node.func, ast.Name):
            if node.func.id in self.blocked_calls:
                self.violations.append((node.lineno, f"Forbidden direct function call: '{node.func.id}()'"))
        
        # Check method/attribute calls (e.g. os.system(...))
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in self.blocked_calls:
                self.violations.append((node.lineno, f"Forbidden method call: '.{node.func.attr}()'"))
        
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # Dunder exploit prevention (e.g. __class__.__base__.__subclasses__)
        if node.attr.startswith("__") and node.attr.endswith("__"):
            if node.attr not in {"__init__", "__name__", "__doc__"}:
                self.violations.append((node.lineno, f"Dunder attribute access forbidden: '{node.attr}'"))
        self.generic_visit(node)
