import ast
import os
import sys
import time
import re
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
    def __init__(self, file_name, source_lines):
        self.file_name = file_name
        self.source_lines = source_lines
        self.issues = []
        self.imports = {}
        self.fixes = {}

    # ---- Helper methods ----
    def _get_code(self, node):
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

    def _is_high_entropy(self, text):
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

    def _already_fixed(self, lineno, typ="comment"):
        if 0 < lineno <= len(self.source_lines):
            line = self.source_lines[lineno-1]
            if typ == "comment":
                return line.lstrip().startswith("#")
            return "Auto-fixed" in line
        return False

    def _add_issue(self, level, title, line, code, reason, fix):
        self.issues.append({
            "level": level, "title": title, "line": line,
            "code": code, "reason": reason, "fix": fix
        })

    def _print_issues(self):
        for issue in sorted([i for i in self.issues if i["level"] == "VULNERABILITY"], key=lambda x: x["line"]):
            print(f"\n{COLORS['RED']}[{issue['level']}] {self.file_name}:{issue['line']} -> {issue['title']}{COLORS['RESET']}")
            print(f"  {COLORS['WHITE']}Code:{COLORS['RESET']} {issue['code']}")
            print(f"  {COLORS['WHITE']}Why:{COLORS['RESET']} {issue['reason']}")
            print(f"  {COLORS['WHITE']}Fix:{COLORS['RESET']} {issue['fix']}")
            print(f"{COLORS['CYAN']}{'-'*50}{COLORS['RESET']}")

    # ---- AST visitors ----
    def visit_Import(self, node):
        for n in node.names:
            self.imports[n.asname or n.name] = (n.name, None, n.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.level > 0:
            full = "."*node.level + (node.module or "")
            short = node.module.split('.')[-1] if node.module else ""
        else:
            full = node.module or ""
            short = full
        for n in node.names:
            self.imports[n.asname or n.name] = (full, n.name, short)
        self.generic_visit(node)

    def visit_Assert(self, node):
        self._add_issue("VULNERABILITY", "assert used for security", node.lineno,
                        self._get_code(node), "assert is disabled with -O flag", "Replace with if and raise")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for d in node.args.defaults:
            if isinstance(d, (ast.List, ast.Dict)):
                self._add_issue("CODE_SMELL", "Mutable default argument", node.lineno,
                                f"def {node.name}(...)", "Object created once, changes accumulate", "Use default=None")
        self.generic_visit(node)

    def visit_Assign(self, node):
        if not node.lineno or not isinstance(node.value, ast.Constant):
            self.generic_visit(node)
            return
        val = node.value.value
        val_str = str(val).lower()
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id.lower()
            # Secrets
            if any(k in name for k in ("password","token","secret","api_key","passwd","pwd")) and isinstance(val, str):
                if any(dp in val_str for dp in ("admin","root","12345","qwerty")):
                    self._add_issue("VULNERABILITY", "Default credentials in code", node.lineno,
                                    self._get_code(node), "Default password left", "Change and use .env")
                else:
                    self._add_issue("VULNERABILITY", "Password or secret in code", node.lineno,
                                    f"{target.id} = '...'", "Sensitive data exposed", "Move to .env")
                    if self._is_high_entropy(val) and not name.startswith("_"):
                        self._add_issue("VULNERABILITY", "Hidden hardcoded key/token", node.lineno,
                                        "[HIGH ENTROPY]", "Looks like API key or hash", "Move to .env")
            # URLs
            if any(p in val_str for p in ("http://","redis://","amqp://","mongodb://","postgres://")) and isinstance(val, str):
                if "://" in val_str and "@" in val_str and val_str.find("@") > val_str.find("://") and not any(l in val_str for l in ("localhost","127.0.0.1")):
                    self._add_issue("VULNERABILITY", "Credentials inside URL", node.lineno,
                                    self._get_code(node), "Username/password in URL", "Use environment variables")
                elif not any(l in val_str for l in ("localhost","127.0.0.1")):
                    self._add_issue("CODE_SMELL", "Hardcoded URL/Protocol", node.lineno,
                                    self._get_code(node), "External service address hardcoded", "Move to .env")
            # DEBUG
            if name == "debug" and val is True:
                self._add_issue("VULNERABILITY", "DEBUG = True in production", node.lineno,
                                self._get_code(node), "Debug mode allows arbitrary code execution", "Set DEBUG = False")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if node.lineno and len(node.body) == 1:
            act = node.body[0]
            if act.lineno and (isinstance(act, ast.Pass) or (isinstance(act, ast.Expr) and isinstance(act.value, ast.Constant))):
                if not self._already_fixed(act.lineno, "except"):
                    self._add_issue("CODE_SMELL", "Empty except block", node.lineno,
                                    "except: pass", "Errors silently ignored", "Auto-fix added")
                    self.fixes[act.lineno] = ("EXCEPT", "pass  # Auto-fixed: suppressed exception placeholder")
        self.generic_visit(node)

    def _resolve_chain(self, node, depth=0):
        if depth > 100:
            return None, []
        if isinstance(node, ast.Name):
            return node.id, []
        if isinstance(node, ast.Attribute):
            base, chain = self._resolve_chain(node.value, depth+1)
            if base:
                return base, chain + [node.attr]
        return None, []

    def _safe_yaml(self, node):
        for kw in node.keywords:
            if kw.arg == "Loader":
                try:
                    name = ast.unparse(kw.value)
                except:
                    name = ""
                if "SafeLoader" in name and isinstance(kw.value, (ast.Name, ast.Attribute)):
                    return True
        return False

    def _safe_open_arg(self, node):
        # Safe function calls
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == 'join':
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        return True
            if isinstance(f, ast.Name) and f.id == 'Path':
                return True
            if isinstance(f, ast.Attribute) and f.attr == 'dirname':
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id == '__file__':
                        return True
            if isinstance(f, ast.Attribute) and f.attr == 'cwd' and isinstance(f.value, ast.Name) and f.value.id == 'Path':
                return True
            if isinstance(f, ast.Name) and f.id == 'getcwd':
                return True
            if isinstance(f, ast.Name) and (f.id.startswith('safe_') or f.id.startswith('validate_')):
                return True
            if isinstance(f, ast.Attribute) and (f.attr.startswith('safe_') or f.attr.startswith('validate_')):
                return True
        # Variables with meaningful names
        if isinstance(node, ast.Name):
            if any(s in node.id.lower() for s in ('path','file','filename','dir','folder','name')):
                return True
        if isinstance(node, ast.Attribute):
            if any(s in node.attr.lower() for s in ('path','file','filename','dir','folder','name')):
                return True
        return False

    def _check_star_kwargs(self, node):
        code = self._get_code(node)
        for kw in node.keywords:
            if kw.arg is None and isinstance(kw.value, ast.Dict):
                for k, v in zip(kw.value.keys, kw.value.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        key = k.value.lower()
                        if key == "verify" and isinstance(v, ast.Constant) and v.value is False:
                            self._add_issue("VULNERABILITY", "SSL verification disabled via **kwargs", node.lineno,
                                            code, "Disables certificate checks", "Remove verify=False")
                        elif key == "shell" and isinstance(v, ast.Constant) and v.value is True:
                            self._add_issue("VULNERABILITY", "shell=True via **kwargs", node.lineno,
                                            code, "Command injection risk", "Set shell=False")
                        elif key == "host" and isinstance(v, ast.Constant) and v.value == "0.0.0.0":
                            self._add_issue("VULNERABILITY", "host='0.0.0.0' via **kwargs", node.lineno,
                                            code, "Server exposed to whole world", "Use '127.0.0.1'")

    def visit_Call(self, node):
        if not node.lineno:
            return self.generic_visit(node)
        try:
            if isinstance(node.func, ast.Call):
                self.generic_visit(node)
                return

            code = self._get_code(node)
            base, chain = self._resolve_chain(node.func)
            mod, func = None, None

            if base:
                if base in self.imports:
                    full, imp, short = self.imports[base]
                    mod = short if short else full
                    if imp:
                        func = f"{imp}.{'.'.join(chain)}" if chain else imp
                    else:
                        func = '.'.join(chain) if chain else None
                else:
                    mod = base
                    func = '.'.join(chain) if chain else None

            mod_low = str(mod).lower() if mod else ""
            func_low = str(func).lower() if func else ""

            trig = False
            if mod:
                key = (mod, func) if (mod, func) in RULES else (mod, None) if (mod, None) in RULES else None
                if key:
                    if key == ("yaml", "load") and self._safe_yaml(node):
                        pass
                    else:
                        lvl, ttl, rsn, fx = RULES[key]
                        if lvl != "CODE_SMELL" or not self._already_fixed(node.lineno, "comment"):
                            self._add_issue(lvl, ttl, node.lineno, code, rsn, fx)
                            trig = True

            if "xml" in mod_low and "defusedxml" not in mod_low:
                self._add_issue("VULNERABILITY", "Unsafe XML parser", node.lineno,
                                code, "Vulnerable to XXE attacks", "Use defusedxml")

            if mod == "subprocess" and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                self._add_issue("VULNERABILITY", f"subprocess.{func}(shell=True)", node.lineno,
                                code, "Command injection risk", "Set shell=False")

            if (mod == "open" or (func == "open" and not mod)) and node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant) and not self._safe_open_arg(arg):
                    self._add_issue("CODE_SMELL", "Potential path traversal in open()", node.lineno,
                                    code, "Dynamic path passed to open()", "Use pathlib.Path()")

            if base and not chain:
                if base == "print" and not self._already_fixed(node.lineno, "comment"):
                    self._add_issue("CODE_SMELL", "Forgotten print()", node.lineno, code, "Clutters output", "Auto-commented")
                    self.fixes[node.lineno] = ("PRINT", "COMMENT_LINE")
                elif base == "breakpoint" and not self._already_fixed(node.lineno, "comment"):
                    self._add_issue("CODE_SMELL", "Forgotten breakpoint()", node.lineno, code, "Stops script", "Auto-deleted")
                    self.fixes[node.lineno] = ("BREAKPOINT", "DELETE_LINE")

            if any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
                self._add_issue("VULNERABILITY", "SSL verification disabled", node.lineno, code, "Man-in-the-middle attacks", "Remove verify=False")

            if any(k.arg == "host" and isinstance(k.value, ast.Constant) and k.value.value == "0.0.0.0" for k in node.keywords):
                self._add_issue("VULNERABILITY", "Server binds to 0.0.0.0", node.lineno, code, "Exposed to entire network", "Use '127.0.0.1'")

            if not trig and func_low and any(dk in func_low for dk in ("run","exec","system","cmd","shell","spawn","popen")):
                if mod_low not in ("json","sys","math","time") and node.args and not isinstance(node.args[0], ast.Constant):
                    self._add_issue("VULNERABILITY", "Suspicious dynamic command call", node.lineno,
                                    code, f"Dynamic argument passed to {func}", "Use safe APIs")

            if func_low in ("load","loads") and any(bm in mod_low for bm in ("pickle","marshal","shelve","yaml")):
                self._add_issue("VULNERABILITY", f"Potentially unsafe deserialization .{func}", node.lineno,
                                code, "Unsafe parser", "Verify data source")

            self._check_star_kwargs(node)

        except Exception:
            pass
        self.generic_visit(node)

    # SQL
    def visit_BinOp(self, node):
        self._check_sql(node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        self._check_sql(node)
        self.generic_visit(node)

    def _check_sql(self, node):
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

def apply_fixes(file_path, fixes, lines):
    new_lines = []
    logs = []
    for idx, line in enumerate(lines, 1):
        if idx in fixes:
            typ, act = fixes[idx]
            end = "\r\n" if line.endswith("\r\n") else "\n"
            cl = line.rstrip("\r\n")
            ind = len(cl) - len(cl.lstrip())
            if act == "COMMENT_LINE":
                new_lines.append(cl[:ind] + "# " + cl[ind:] + end)
                logs.append((typ, f"Line {idx}: print commented -> [{cl.strip()}]"))
            elif act == "DELETE_LINE":
                logs.append((typ, f"Line {idx}: breakpoint removed -> [{cl.strip()}]"))
                continue
            else:
                new_lines.append(cl[:ind] + act + end)
                logs.append((typ, f"Line {idx}: empty except protected -> [{cl.strip()}]"))
        else:
            new_lines.append(line)
    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    return logs

# ----------------------------------------------------------------------
# Main function
# ----------------------------------------------------------------------

def main():
    start = time.time()
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
    stats = {"PRINT":0, "BREAKPOINT":0, "EXCEPT":0}
    all_logs = []

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

            if analyzer.fixes:
                applied = apply_fixes(fpath, analyzer.fixes, lines)
                print(f"\n{COLORS['GREEN']}[CLEANED] {name}: {len(applied)} lines cleaned{COLORS['RESET']}")
                for typ, msg in applied:
                    print(f"  {COLORS['YELLOW']}->{COLORS['RESET']} {msg}")
                    stats[typ] += 1
                    all_logs.append(msg)

            analyzer._print_issues()
            total_vuln += len([i for i in analyzer.issues if i["level"] == "VULNERABILITY"])

        except Exception as e:
            print(f"\n{COLORS['RED']}[ERROR] {fpath.name}: {e}{COLORS['RESET']}")

    print(f"\n{COLORS['CYAN']}{'='*50}\nTime: {time.time()-start:.3f} sec\n{'-'*50}\nSUMMARY OF FIXES:{COLORS['RESET']}")
    if not all_logs:
        print(f" {COLORS['GREEN']}✔ No debug leftovers found{COLORS['RESET']}")
    for k, v in stats.items():
        if v:
            print(f" {COLORS['GREEN']}✔ {k}: {v}{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}{'='*50}{COLORS['RESET']}\nVulnerabilities found: " +
          (f"{COLORS['GREEN']}NONE{COLORS['RESET']}" if total_vuln==0 else f"{COLORS['RED']}{total_vuln}{COLORS['RESET']}"))
    print(f"{COLORS['CYAN']}{'='*50}{COLORS['RESET']}\n")
    if os.environ.get("CI") != "true":
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
