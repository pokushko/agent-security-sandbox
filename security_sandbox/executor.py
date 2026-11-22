import io
import contextlib
from typing import Dict, Any
from .ast_guard import ASTSecurityGuard

class SafeCodeExecutor:
    """
    In-memory isolated execution engine for sanitized script blocks.
    Enforces AST inspection, restricts global execution context,
    and captures standard output deterministically.
    """

    def __init__(self, guard: ASTSecurityGuard = None):
        self.guard = guard or ASTSecurityGuard()

    def execute(self, code: str, allowed_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Executes code safely after passing AST validation.
        Returns execution artifacts and captured stdout.
        """
        # Step 1: Pre-flight AST validation
        self.guard.validate(code)

        # Step 2: Establish sandboxed namespace
        safe_globals = {
            "__builtins__": {
                "print": print,
                "range": range,
                "len": len,
                "int": int,
                "float": float,
                "str": str,
                "bool": bool,
                "list": list,
                "dict": dict,
                "set": set,
                "tuple": tuple,
                "min": min,
                "max": max,
                "sum": sum,
                "abs": abs,
                "enumerate": enumerate,
                "zip": zip,
                "sorted": sorted,
                "round": round
            }
        }
        if allowed_context:
            safe_globals.update(allowed_context)

        safe_locals: Dict[str, Any] = {}
        stdout_buf = io.StringIO()

        # Step 3: Sandboxed execution with stdout capture
        try:
            with contextlib.redirect_stdout(stdout_buf):
                exec(code, safe_globals, safe_locals)
        except Exception as e:
            raise RuntimeError(f"Runtime execution error: {e}") from e

        return {
            "success": True,
            "stdout": stdout_buf.getvalue(),
            "variables": {k: v for k, v in safe_locals.items() if not k.startswith("__")}
        }
