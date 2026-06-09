import ast
import os
import sys
import time
import re
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------

def supports_color():
    return not os.getenv("NO_COLOR") and sys.stdout.isatty()

COLORS = {
    "RED": "\033[91m", "YELLOW": "\033[93m", "CYAN": "\033[96m",
    "WHITE": "\033[97m", "GREEN": "\033[92m", "RESET": "\033[0m"
} if supports_color() else {k: "" for k in ("RED", "YELLOW", "CYAN", "WHITE", "GREEN", "RESET")}

EXCLUDE_DIRS = {'.git', '__pycache__', 'venv', 'env', '.venv', 'node_modules'}
SQL_PATTERN = re.compile(r'\b(select|insert|update|delete|create|drop|alter|replace|merge|truncate)\b', re.IGNORECASE)
HIGH_ENTROPY_MIN_LEN = 20
HIGH_ENTROPY_RATIO = 0.45

# Enum for auto-fix actions
class FixAction(Enum):
    COMMENT_LINE = auto()
    DELETE_LINE = auto()
    REPLACE_EXCEPT = auto()

RULES = {
    ("eval", None): ("VULNERABILITY", "Dangerous eval() call", "Executes arbitrary code", "Use ast.literal_eval()"),
    ("exec", None): ("VULNERABILITY", "Dangerous exec() call", "Executes dynamic code", "Use ast.literal_eval()"),
    ("os", "system"): ("VULNERABILITY", "os.system()", "Vulnerable to command injection", "Use subprocess.run()"),
    ("os", "popen"): ("VULNERABILITY", "os.popen()", "Vulnerable to command injection", "Use subprocess.run()"),
    ("yaml", "load"): ("VULNERABILITY", "Unsafe YAML load", "May execute arbitrary code", "Use yaml.safe_load()"),
    ("hashlib", "md5"): ("VULNERABILITY", "Weak hashing algorithm md5()", "Unsafe for passwords", "Use sha256"),
    ("hashlib", "sha1"): ("VULNERABILITY", "Weak hashing algorithm sha1()", "Unsafe for passwords", "Use sha256"),
    ("pickle", "load"): ("VULNERABILITY", "pickle.load()", "Executes malicious code", "Use JSON instead"),
    ("pickle", "loads"): ("VULNERABILITY", "pickle.loads()", "Executes malicious code", "Use JSON instead"),
    ("os", "chmod"): ("VULNERABILITY", "Dangerous chmod", "Overly permissive rights", "Limit to 600 or 700"),
    ("urllib.request", "urlretrieve"): ("VULNERABILITY", "urlretrieve()", "Path traversal risk", "Use requests.get()"),
    ("webbrowser", "open"): ("VULNERABILITY", "webbrowser.open() with dynamic URL", "May open local files", "Validate URL (http://, https://)"),
    ("tempfile", "mktemp"): ("VULNERABILITY", "tempfile.mktemp()", "Race condition", "Use mkstemp()"),
    ("subprocess", "getoutput"): ("VULNERABILITY", "getoutput() uses shell", "Command injection", "Use run() with capture_output=True"),
    ("subprocess", "getstatusoutput"): ("VULNERABILITY", "getstatusoutput() uses shell", "Command injection", "Use run() with capture_output=True"),
}

# ----------------------------------------------------------------------
# Analyzer
# ----------------------------------------------------------------------

class CodeAnalyzer(ast.NodeVisitor):
    """AST visitor that detects vulnerabilities and code smells."""

    def __init__(self, file_name: str, source_lines: List[str]):
        self.file_name = file_name
        self.source_lines = source_lines
        self.issues = []
        self.imports = {}
        self.fixes = {}

    # ---- Helper methods ----
    def _get_code(self, node: ast.AST) -> str:
        """Extract source code fragment for a given AST node."""
        try:
            return ast.unparse(node)
        except:
            pass
        try:
            if node.lineno and self.source_lines:
                lines = self.source_lines[node.lineno-1:node.end_lineno]
                if lines:
                    if node.end_col_offset is not None:
                        lines[-1] = lines[-1][:node.end_col_offset]
                    if node.col_offset is not None:
                        lines[0] = lines[0][node.col_offset:]
                    return " ".join(l.strip() for l in lines)
        except:
            pass
        return "<code>"

    def _is_high_entropy(self, text: str) -> bool:
        """Detect high-entropy strings that may be secrets/keys."""
        if len(text) < HIGH_ENTROPY_MIN_LEN or " " in text:
            return False
        low = text.lower()
        if low.startswith(('test', 'example', 'dummy', 'fake')):
            return False
        if re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', text, re.I):
            return False
        if len(set(text)) == 1:
            return False
        if re.fullmatch(r'[A-Za-z0-9+/=]+', text):
            return True
        if re.fullmatch(r'[0-9a-fA-F]+', text):
            return len(text) >= 32
        return (len(set(text)) / len(text)) > HIGH_ENTROPY_RATIO

    def _already_fixed(self, lineno: int, typ: str = "comment") -> bool:
        """Check if a line was already auto-fixed (commented or marked)."""
        if 0 < lineno <= len(self.source_lines):
            line = self.source_lines[lineno-1]
            if typ == "comment":
                return line.lstrip().startswith("#")
            return "Auto-fixed" in line
        return False

    def _add_issue(self, level: str, title: str, line: int, code: str, reason: str, fix: str):
        """Store a detected issue."""
        self.issues.append({
            "level": level, "title": title, "line": line,
            "code": code, "reason": reason, "fix": fix
        })

    def _print_issues(self):
        """Print all stored vulnerabilities."""
        for issue in sorted([i for i in self.issues if i["level"] == "VULNERABILITY"], key=lambda x: x["line"]):
            print(f"\n{COLORS['RED']}[{issue['level']}] {self.file_name}:{issue['line']} -> {issue['title']}{COLORS['RESET']}")
            print(f"  {COLORS['WHITE']}Code:{COLORS['RESET']} {issue['code']}")
            print(f"  {COLORS['WHITE']}Why:{COLORS['RESET']} {issue['reason']}")
            print(f"  {COLORS['WHITE']}Fix:{COLORS['RESET']} {issue['fix']}")
            print(f"{COLORS['CYAN']}{'-'*50}{COLORS['RESET']}")

    # ---- AST visitors ----
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = (alias.name, None, alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.level > 0:
            full = "." * node.level + (node.module or "")
            short = node.module.split('.')[-1] if node.module else ""
        else:
            full = node.module or ""
            short = full
        for alias in node.names:
            self.imports[alias.asname or alias.name] = (full, alias.name, short)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        self._add_issue("VULNERABILITY", "assert used for security", node.lineno,
                        self._get_code(node), "assert is disabled with -O flag", "Replace with if and raise")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict)):
                self._add_issue("CODE_SMELL", "Mutable default argument", node.lineno,
                                f"def {node.name}(...)", "Object created once, changes accumulate", "Use default=None")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Check assignments for secrets, hardcoded URLs, and debug flags."""
        if not node.lineno or not isinstance(node.value, ast.Constant):
            self.generic_visit(node)
            return

        value = node.value.value
        value_str = str(value).lower()

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id.lower()
            self._check_secret_assignment(node, var_name, value, value_str)
            self._check_url_assignment(node, var_name, value, value_str)
            self._check_debug_assignment(node, var_name, value)

        self.generic_visit(node)

    def _check_secret_assignment(self, node: ast.Assign, var_name: str, value: any, value_str: str):
        """Detect passwords, tokens, API keys hardcoded."""
        secret_keywords = ("password", "token", "secret", "api_key", "passwd", "pwd")
        if not any(k in var_name for k in secret_keywords) or not isinstance(value, str):
            return

        default_passwords = ("admin", "root", "12345", "qwerty")
        if any(dp in value_str for dp in default_passwords):
            self._add_issue("VULNERABILITY", "Default credentials in code", node.lineno,
                            self._get_code(node), "Default password left", "Change and use .env")
        else:
            self._add_issue("VULNERABILITY", "Password or secret in code", node.lineno,
                            f"{var_name} = '...'", "Sensitive data exposed", "Move to .env")
            if self._is_high_entropy(value) and not var_name.startswith("_"):
                self._add_issue("VULNERABILITY", "Hidden hardcoded key/token", node.lineno,
                                "[HIGH ENTROPY]", "Looks like API key or hash", "Move to .env")

    def _check_url_assignment(self, node: ast.Assign, var_name: str, value: any, value_str: str):
        """Detect hardcoded URLs and credentials in URLs."""
        url_prefixes = ("http://", "redis://", "amqp://", "mongodb://", "postgres://")
        if not any(p in value_str for p in url_prefixes) or not isinstance(value, str):
            return

        if "://" in value_str and "@" in value_str and value_str.find("@") > value_str.find("://") and \
           not any(l in value_str for l in ("localhost", "127.0.0.1")):
            self._add_issue("VULNERABILITY", "Credentials inside URL", node.lineno,
                            self._get_code(node), "Username/password in URL", "Use environment variables")
        elif not any(l in value_str for l in ("localhost", "127.0.0.1")):
            self._add_issue("CODE_SMELL", "Hardcoded URL/Protocol", node.lineno,
                            self._get_code(node), "External service address hardcoded", "Move to .env")

    def _check_debug_assignment(self, node: ast.Assign, var_name: str, value: any):
        """Warn if DEBUG = True is found."""
        if var_name == "debug" and value is True:
            self._add_issue("VULNERABILITY", "DEBUG = True in production", node.lineno,
                            self._get_code(node), "Debug mode allows arbitrary code execution", "Set DEBUG = False")

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """Mark empty except blocks for auto-fix."""
        if node.lineno and len(node.body) == 1:
            action = node.body[0]
            if action.lineno and (isinstance(action, ast.Pass) or
                                  (isinstance(action, ast.Expr) and isinstance(action.value, ast.Constant))):
                if not self._already_fixed(action.lineno, "except"):
                    self._add_issue("CODE_SMELL", "Empty except block", node.lineno,
                                    "except: pass", "Errors silently ignored", "Auto-fix added")
                    self.fixes[action.lineno] = (FixAction.REPLACE_EXCEPT,
                                                 "pass  # Auto-fixed: suppressed exception placeholder")
        self.generic_visit(node)

    # ---- Name resolution helpers ----
    def _resolve_chain(self, node: ast.AST, depth: int = 0) -> Tuple[Optional[str], List[str]]:
        """Resolve attribute chain like a.b.c -> (base_name, ['b','c'])."""
        if depth > 100:
            return None, []
        if isinstance(node, ast.Name):
            return node.id, []
        if isinstance(node, ast.Attribute):
            base, chain = self._resolve_chain(node.value, depth + 1)
            if base:
                return base, chain + [node.attr]
        return None, []

    def _resolve_module_and_function(self, node: ast.Call) -> Tuple[Optional[str], Optional[str]]:
        """Given a call node, resolve the module name and function name."""
        base, chain = self._resolve_chain(node.func)
        if not base:
            return None, None

        if base in self.imports:
            full_module, imported_name, short = self.imports[base]
            module_name = short if short else full_module
            if imported_name:
                func_name = f"{imported_name}.{'.'.join(chain)}" if chain else imported_name
            else:
                func_name = '.'.join(chain) if chain else None
        else:
            module_name = base
            func_name = '.'.join(chain) if chain else None

        return module_name, func_name

    # ---- YAML and open helpers ----
    def _safe_yaml(self, node: ast.Call) -> bool:
        """Check if yaml.load uses SafeLoader."""
        for kw in node.keywords:
            if kw.arg == "Loader":
                try:
                    loader_name = ast.unparse(kw.value)
                except:
                    loader_name = ""
                if "SafeLoader" in loader_name and isinstance(kw.value, (ast.Name, ast.Attribute)):
                    return True
        return False

    def _safe_open_arg(self, node: ast.AST) -> bool:
        """Heuristic to decide if an argument to open() is 'safe' (not user-controlled)."""
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == 'join':
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        return True
            if isinstance(func, ast.Name) and func.id == 'Path':
                return True
            if isinstance(func, ast.Attribute) and func.attr == 'dirname':
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id == '__file__':
                        return True
            if isinstance(func, ast.Attribute) and func.attr == 'cwd' and isinstance(func.value, ast.Name) and func.value.id == 'Path':
                return True
            if isinstance(func, ast.Name) and func.id == 'getcwd':
                return True
            if isinstance(func, ast.Name) and (func.id.startswith('safe_') or func.id.startswith('validate_')):
                return True
            if isinstance(func, ast.Attribute) and (func.attr.startswith('safe_') or func.attr.startswith('validate_')):
                return True
        # Variables with meaningful names
        if isinstance(node, ast.Name):
            if any(s in node.id.lower() for s in ('path', 'file', 'filename', 'dir', 'folder', 'name')):
                return True
        if isinstance(node, ast.Attribute):
            if any(s in node.attr.lower() for s in ('path', 'file', 'filename', 'dir', 'folder', 'name')):
                return True
        return False

    # ---- Individual checkers for visit_Call ----
    def _check_dangerous_functions(self, node: ast.Call, module_name: Optional[str], func_name: Optional[str]) -> bool:
        """Check against RULES dictionary."""
        if not module_name:
            return False
        key = (module_name, func_name) if (module_name, func_name) in RULES else (module_name, None) if (module_name, None) in RULES else None
        if not key:
            return False
        if key == ("yaml", "load") and self._safe_yaml(node):
            return False
        level, title, reason, fix = RULES[key]
        if level != "CODE_SMELL" or not self._already_fixed(node.lineno, "comment"):
            self._add_issue(level, title, node.lineno, self._get_code(node), reason, fix)
            return True
        return False

    def _check_xml_parser(self, node: ast.Call, module_name: Optional[str]):
        """Unsafe XML parser (XXE)."""
        if module_name and "xml" in module_name.lower() and "defusedxml" not in module_name.lower():
            self._add_issue("VULNERABILITY", "Unsafe XML parser", node.lineno,
                            self._get_code(node), "Vulnerable to XXE attacks", "Use defusedxml")

    def _check_subprocess_shell(self, node: ast.Call, module_name: Optional[str], func_name: Optional[str]):
        """subprocess call with shell=True."""
        if module_name == "subprocess" and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords):
            self._add_issue("VULNERABILITY", f"subprocess.{func_name}(shell=True)", node.lineno,
                            self._get_code(node), "Command injection risk", "Set shell=False")

    def _check_open_path_traversal(self, node: ast.Call, module_name: Optional[str], func_name: Optional[str]):
        """open() with dynamic path (potential path traversal)."""
        if (module_name == "open" or (func_name == "open" and not module_name)) and node.args:
            arg = node.args[0]
            if not isinstance(arg, ast.Constant) and not self._safe_open_arg(arg):
                self._add_issue("CODE_SMELL", "Potential path traversal in open()", node.lineno,
                                self._get_code(node), "Dynamic path passed to open()", "Use pathlib.Path()")

    def _check_debug_calls(self, node: ast.Call, base_name: Optional[str]):
        """Auto-fix forgotten print() and breakpoint() calls (no chain)."""
        if base_name and not hasattr(node.func, 'attr'):  # simple name, no attribute
            if base_name == "print" and not self._already_fixed(node.lineno, "comment"):
                self._add_issue("CODE_SMELL", "Forgotten print()", node.lineno, self._get_code(node),
                                "Clutters output", "Auto-commented")
                self.fixes[node.lineno] = (FixAction.COMMENT_LINE, "COMMENT_LINE")
            elif base_name == "breakpoint" and not self._already_fixed(node.lineno, "comment"):
                self._add_issue("CODE_SMELL", "Forgotten breakpoint()", node.lineno, self._get_code(node),
                                "Stops script", "Auto-deleted")
                self.fixes[node.lineno] = (FixAction.DELETE_LINE, "DELETE_LINE")

    def _check_ssl_host_config(self, node: ast.Call):
        """verify=False or host='0.0.0.0' in kwargs."""
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add_issue("VULNERABILITY", "SSL verification disabled", node.lineno,
                                self._get_code(node), "Man-in-the-middle attacks", "Remove verify=False")
            if kw.arg == "host" and isinstance(kw.value, ast.Constant) and kw.value.value == "0.0.0.0":
                self._add_issue("VULNERABILITY", "Server binds to 0.0.0.0", node.lineno,
                                self._get_code(node), "Exposed to entire network", "Use '127.0.0.1'")

    def _check_dynamic_command(self, node: ast.Call, module_name: Optional[str], func_name: Optional[str], rule_triggered: bool):
        """Suspicious dynamic command call (exec, system, etc.) with non-constant argument."""
        if rule_triggered:
            return
        dangerous_funcs = ("run", "exec", "system", "cmd", "shell", "spawn", "popen")
        if func_name and any(df in func_name for df in dangerous_funcs):
            safe_modules = ("json", "sys", "math", "time")
            if module_name and module_name.lower() not in safe_modules and node.args and not isinstance(node.args[0], ast.Constant):
                self._add_issue("VULNERABILITY", "Suspicious dynamic command call", node.lineno,
                                self._get_code(node), f"Dynamic argument passed to {func_name}", "Use safe APIs")

    def _check_deserialization(self, node: ast.Call, module_name: Optional[str], func_name: Optional[str]):
        """Unsafe deserialization (pickle.load, marshal.load, etc.)."""
        if func_name in ("load", "loads") and any(bm in str(module_name).lower() for bm in ("pickle", "marshal", "shelve", "yaml")):
            self._add_issue("VULNERABILITY", f"Potentially unsafe deserialization .{func_name}", node.lineno,
                            self._get_code(node), "Unsafe parser", "Verify data source")

    def _check_star_kwargs(self, node: ast.Call):
        """Check **kwargs expansions for dangerous flags."""
        code = self._get_code(node)
        for kw in node.keywords:
            if kw.arg is None and isinstance(kw.value, ast.Dict):
                for key_node, value_node in zip(kw.value.keys, kw.value.values):
                    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                        key = key_node.value.lower()
                        if key == "verify" and isinstance(value_node, ast.Constant) and value_node.value is False:
                            self._add_issue("VULNERABILITY", "SSL verification disabled via **kwargs", node.lineno,
                                            code, "Disables certificate checks", "Remove verify=False")
                        elif key == "shell" and isinstance(value_node, ast.Constant) and value_node.value is True:
                            self._add_issue("VULNERABILITY", "shell=True via **kwargs", node.lineno,
                                            code, "Command injection risk", "Set shell=False")
                        elif key == "host" and isinstance(value_node, ast.Constant) and value_node.value == "0.0.0.0":
                            self._add_issue("VULNERABILITY", "host='0.0.0.0' via **kwargs", node.lineno,
                                            code, "Server exposed to whole world", "Use '127.0.0.1'")

    # ---- Main call visitor ----
    def visit_Call(self, node: ast.Call):
        """Main entry point for function call analysis."""
        if not node.lineno:
            self.generic_visit(node)
            return
        if isinstance(node.func, ast.Call):
            self.generic_visit(node)
            return

        module_name, func_name = self._resolve_module_and_function(node)
        rule_triggered = self._check_dangerous_functions(node, module_name, func_name)

        self._check_xml_parser(node, module_name)
        self._check_subprocess_shell(node, module_name, func_name)
        self._check_open_path_traversal(node, module_name, func_name)

        base_name = None
        if isinstance(node.func, ast.Name):
            base_name = node.func.id
        self._check_debug_calls(node, base_name)

        self._check_ssl_host_config(node)
        self._check_dynamic_command(node, module_name, func_name, rule_triggered)
        self._check_deserialization(node, module_name, func_name)
        self._check_star_kwargs(node)

        self.generic_visit(node)

    # ---- SQL injection checks ----
    def visit_BinOp(self, node: ast.BinOp):
        self._check_sql(node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        self._check_sql(node)
        self.generic_visit(node)

    def _check_sql(self, node: ast.AST):
        """Detect potential SQL injection via concatenation or f-strings."""
        try:
            txt = self._get_code(node)
            if txt and SQL_PATTERN.search(txt.lower()) and ('+' in txt or '{' in txt):
                self._add_issue("VULNERABILITY", "Potential SQL injection", node.lineno,
                                txt, "Dynamic SQL via f-string or concatenation", "Use parameters")
        except:
            pass


# ----------------------------------------------------------------------
# Auto-fixes application
# ----------------------------------------------------------------------

def apply_fixes(file_path: Path, fixes: Dict[int, Tuple[FixAction, str]], lines: List[str]) -> List[Tuple[FixAction, str]]:
    """Apply auto-fixes to the file and return logs."""
    new_lines = []
    logs = []
    for idx, line in enumerate(lines, 1):
        if idx in fixes:
            action, _ = fixes[idx]
            end = "\r\n" if line.endswith("\r\n") else "\n"
            clean_line = line.rstrip("\r\n")
            indent = len(clean_line) - len(clean_line.lstrip())
            if action == FixAction.COMMENT_LINE:
                new_lines.append(clean_line[:indent] + "# " + clean_line[indent:] + end)
                logs.append((action, f"Line {idx}: print commented"))
            elif action == FixAction.DELETE_LINE:
                logs.append((action, f"Line {idx}: breakpoint removed, pass added below"))
                # Remove the line, add pass below with same indent
                new_lines.append(" " * indent + "pass  # Auto-removed breakpoint" + end)
            elif action == FixAction.REPLACE_EXCEPT:
                new_lines.append(clean_line[:indent] + "pass  # Auto-fixed: suppressed exception placeholder" + end)
                logs.append((action, f"Line {idx}: empty except protected"))
        else:
            new_lines.append(line)
    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    return logs


# ----------------------------------------------------------------------
# Main function
# ----------------------------------------------------------------------

def main():
    start_time = time.time()
    print(f"{COLORS['CYAN']}==================================================\n         PYTHON SECURITY ANALYZER (v1.0)\n=================================================={COLORS['RESET']}\n")

    targets = []
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    if path.is_file():
        targets.append(path)
    elif path.is_dir():
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for f in files:
                if f.endswith(".py") and f != Path(__file__).name:
                    targets.append(Path(root) / f)

    if not targets:
        print(f"{COLORS['YELLOW']}No Python files found.{COLORS['RESET']}")
        return

    total_vuln = 0

    for idx, fpath in enumerate(targets, 1):
        try:
            name = fpath.name
            print(f"\r{COLORS['CYAN']}{idx}/{len(targets)} {name:<30}{COLORS['RESET']}", end='', flush=True)
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
            if not src.strip():
                continue
            lines = src.splitlines(keepends=True)
            analyzer = CodeAnalyzer(name, lines)
            analyzer.visit(ast.parse(src))

            fix_details = []
            if analyzer.fixes:
                applied = apply_fixes(fpath, analyzer.fixes, lines)
                for action, msg in applied:
                    fix_details.append(msg)

            analyzer._print_issues()
            total_vuln += len([i for i in analyzer.issues if i["level"] == "VULNERABILITY"])

            if fix_details:
                cnt_print = sum(1 for d in fix_details if 'print commented' in d)
                cnt_bp = sum(1 for d in fix_details if 'breakpoint' in d)
                cnt_except = sum(1 for d in fix_details if 'empty except' in d)
                parts = []
                if cnt_print: parts.append(f"print:{cnt_print}")
                if cnt_bp: parts.append(f"breakpoint:{cnt_bp}")
                if cnt_except: parts.append(f"except:{cnt_except}")
                print(f"\n{COLORS['GREEN']}[CLEANED] {name}: {len(fix_details)} lines cleaned ({', '.join(parts)}){COLORS['RESET']}")
                for detail in fix_details:
                    print(f"  {COLORS['YELLOW']}->{COLORS['RESET']} {detail}")
                print()

        except Exception as e:
            print(f"\n{COLORS['RED']}[ERROR] {fpath.name}: {e}{COLORS['RESET']}")

    elapsed = time.time() - start_time
    print(f"{COLORS['CYAN']}{'='*50}{COLORS['RESET']}")
    print(f"Time: {elapsed:.3f} seconds")
    print(f"Vulnerabilities found: " + (f"{COLORS['GREEN']}NONE{COLORS['RESET']}" if total_vuln == 0 else f"{COLORS['RED']}{total_vuln}{COLORS['RESET']}"))
    print(f"{COLORS['CYAN']}{'='*50}{COLORS['RESET']}")
    if os.environ.get("CI") != "true":
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
