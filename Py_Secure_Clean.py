import ast
import os
import sys
import time
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ----------------------------------------------------------------------
# Настройки
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
    ("eval", None): ("УЯЗВИМОСТЬ", "Опасный вызов eval()", "Выполняет произвольный код", "Используйте ast.literal_eval()"),
    ("exec", None): ("УЯЗВИМОСТЬ", "Опасный вызов exec()", "Выполняет динамический код", "Используйте ast.literal_eval()"),
    ("os", "system"): ("УЯЗВИМОСТЬ", "os.system()", "Уязвимо к инъекциям", "Замените на subprocess.run()"),
    ("os", "popen"): ("УЯЗВИМОСТЬ", "os.popen()", "Уязвимо к инъекциям", "Замените на subprocess.run()"),
    ("yaml", "load"): ("УЯЗВИМОСТЬ", "Небезопасная загрузка YAML", "Может выполнить код", "Используйте yaml.safe_load()"),
    ("hashlib", "md5"): ("УЯЗВИМОСТЬ", "Слабый алгоритм md5()", "Небезопасно для паролей", "Используйте sha256"),
    ("hashlib", "sha1"): ("УЯЗВИМОСТЬ", "Слабый алгоритм sha1()", "Небезопасно для паролей", "Используйте sha256"),
    ("pickle", "load"): ("УЯЗВИМОСТЬ", "pickle.load()", "Выполняет вредоносный код", "Используйте JSON"),
    ("pickle", "loads"): ("УЯЗВИМОСТЬ", "pickle.loads()", "Выполняет вредоносный код", "Используйте JSON"),
    ("os", "chmod"): ("УЯЗВИМОСТЬ", "Опасные права chmod", "Слишком широкие права", "Ограничьте 600 или 700"),
    ("urllib.request", "urlretrieve"): ("УЯЗВИМОСТЬ", "urlretrieve()", "Path traversal", "Используйте requests.get()"),
    ("webbrowser", "open"): ("УЯЗВИМОСТЬ", "webbrowser.open() с динамическим URL", "Может открыть локальные файлы", "Валидируйте URL"),
    ("tempfile", "mktemp"): ("УЯЗВИМОСТЬ", "tempfile.mktemp()", "Race condition", "Используйте mkstemp()"),
    ("subprocess", "getoutput"): ("УЯЗВИМОСТЬ", "getoutput() использует shell", "Уязвимо к инъекциям", "Используйте run()"),
    ("subprocess", "getstatusoutput"): ("УЯЗВИМОСТЬ", "getstatusoutput() использует shell", "Уязвимо к инъекциям", "Используйте run()"),
}

# ----------------------------------------------------------------------
# Анализатор
# ----------------------------------------------------------------------

class CodeAnalyzer(ast.NodeVisitor):
    def __init__(self, file_name, source_lines):
        self.file_name = file_name
        self.source_lines = source_lines
        self.issues = []
        self.imports = {}
        self.fixes = {}

    # ---- Вспомогательные методы ----
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
        return "<код>"

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
        for issue in sorted([i for i in self.issues if i["level"] == "УЯЗВИМОСТЬ"], key=lambda x: x["line"]):
            print(f"\n{COLORS['RED']}[{issue['level']}] {self.file_name}:{issue['line']} -> {issue['title']}{COLORS['RESET']}")
            print(f"  {COLORS['WHITE']}Код:{COLORS['RESET']} {issue['code']}")
            print(f"  {COLORS['WHITE']}Почему:{COLORS['RESET']} {issue['reason']}")
            print(f"  {COLORS['WHITE']}Исправить:{COLORS['RESET']} {issue['fix']}")
            print(f"{COLORS['CYAN']}{'-'*50}{COLORS['RESET']}")

    # ---- Обход AST ----
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
        self._add_issue("УЯЗВИМОСТЬ", "assert для безопасности", node.lineno,
                        self._get_code(node), "assert отключается флагом -O", "Замените на if и raise")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for d in node.args.defaults:
            if isinstance(d, (ast.List, ast.Dict)):
                self._add_issue("МУСОР И СТИЛЬ", "Мутабельный аргумент по умолчанию", node.lineno,
                                f"def {node.name}(...)", "Объект создаётся один раз", "Используйте default=None")
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
            # Секреты
            if any(k in name for k in ("password","token","secret","api_key","passwd","pwd")) and isinstance(val, str):
                if any(dp in val_str for dp in ("admin","root","12345","qwerty")):
                    self._add_issue("УЯЗВИМОСТЬ", "Дефолтные учетные данные", node.lineno,
                                    self._get_code(node), "Стандартный пароль", "Смените и вынесите в .env")
                else:
                    self._add_issue("УЯЗВИМОСТЬ", "Пароль или секрет в коде", node.lineno,
                                    f"{target.id} = '...'", "Чувствительные данные", "Перенесите в .env")
                    if self._is_high_entropy(val) and not name.startswith("_"):
                        self._add_issue("УЯЗВИМОСТЬ", "Скрытый ключ/токен", node.lineno,
                                        "[ВЫСОКАЯ ЭНТРОПИЯ]", "Похоже на API-ключ", "Вынесите в .env")
            # URL
            if any(p in val_str for p in ("http://","redis://","amqp://","mongodb://","postgres://")) and isinstance(val, str):
                if "://" in val_str and "@" in val_str and val_str.find("@") > val_str.find("://") and not any(l in val_str for l in ("localhost","127.0.0.1")):
                    self._add_issue("УЯЗВИМОСТЬ", "Учетные данные внутри URL", node.lineno,
                                    self._get_code(node), "Логин и пароль в URL", "Используйте переменные окружения")
                elif not any(l in val_str for l in ("localhost","127.0.0.1")):
                    self._add_issue("МУСОР И СТИЛЬ", "Захардкоженный URL", node.lineno,
                                    self._get_code(node), "Адрес внешнего сервиса в коде", "Вынесите в .env")
            # DEBUG
            if name == "debug" and val is True:
                self._add_issue("УЯЗВИМОСТЬ", "DEBUG = True в продакшене", node.lineno,
                                self._get_code(node), "Режим отладки опасен", "Установите DEBUG = False")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if node.lineno and len(node.body) == 1:
            act = node.body[0]
            if act.lineno and (isinstance(act, ast.Pass) or (isinstance(act, ast.Expr) and isinstance(act.value, ast.Constant))):
                if not self._already_fixed(act.lineno, "except"):
                    self._add_issue("МУСОР И СТИЛЬ", "Пустой except", node.lineno,
                                    "except: pass", "Ошибки игнорируются", "Автозаглушка")
                    self.fixes[act.lineno] = ("EXCEPT", "pass  # Auto-fixed")
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
        # Безопасные вызовы
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
        # Переменные с понятными именами
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
                            self._add_issue("УЯЗВИМОСТЬ", "verify=False через **kwargs", node.lineno,
                                            code, "Отключена проверка SSL", "Удалите verify=False")
                        elif key == "shell" and isinstance(v, ast.Constant) and v.value is True:
                            self._add_issue("УЯЗВИМОСТЬ", "shell=True через **kwargs", node.lineno,
                                            code, "Выполнение через shell", "Установите shell=False")
                        elif key == "host" and isinstance(v, ast.Constant) and v.value == "0.0.0.0":
                            self._add_issue("УЯЗВИМОСТЬ", "host='0.0.0.0' через **kwargs", node.lineno,
                                            code, "Сервер доступен всем", "Используйте '127.0.0.1'")

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
                        if lvl != "МУСОР И СТИЛЬ" or not self._already_fixed(node.lineno, "comment"):
                            self._add_issue(lvl, ttl, node.lineno, code, rsn, fx)
                            trig = True

            if "xml" in mod_low and "defusedxml" not in mod_low:
                self._add_issue("УЯЗВИМОСТЬ", "Небезопасный парсер XML", node.lineno,
                                code, "Уязвим к XXE", "Используйте defusedxml")

            if mod == "subprocess" and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                self._add_issue("УЯЗВИМОСТЬ", f"subprocess.{func}(shell=True)", node.lineno,
                                code, "Инъекция команд", "Установите shell=False")

            if (mod == "open" or (func == "open" and not mod)) and node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant) and not self._safe_open_arg(arg):
                    self._add_issue("МУСОР И СТИЛЬ", "Потенциальный path traversal", node.lineno,
                                    code, "Динамический путь в open()", "Используйте pathlib.Path()")

            if base and not chain:
                if base == "print" and not self._already_fixed(node.lineno, "comment"):
                    self._add_issue("МУСОР И СТИЛЬ", "Забытый print", node.lineno, code, "Засоряет вывод", "Автокомментарий")
                    self.fixes[node.lineno] = ("PRINT", "COMMENT_LINE")
                elif base == "breakpoint" and not self._already_fixed(node.lineno, "comment"):
                    self._add_issue("МУСОР И СТИЛЬ", "Забытый breakpoint", node.lineno, code, "Останавливает скрипт", "Автоудаление")
                    self.fixes[node.lineno] = ("BREAKPOINT", "DELETE_LINE")

            if any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
                self._add_issue("УЯЗВИМОСТЬ", "verify=False", node.lineno, code, "MitM-атаки", "Удалите verify=False")

            if any(k.arg == "host" and isinstance(k.value, ast.Constant) and k.value.value == "0.0.0.0" for k in node.keywords):
                self._add_issue("УЯЗВИМОСТЬ", "Сервер слушает 0.0.0.0", node.lineno, code, "Доступен всем", "Используйте '127.0.0.1'")

            if not trig and func_low and any(dk in func_low for dk in ("run","exec","system","cmd","shell","spawn","popen")):
                if mod_low not in ("json","sys","math","time") and node.args and not isinstance(node.args[0], ast.Constant):
                    self._add_issue("УЯЗВИМОСТЬ", "Динамический вызов команды", node.lineno,
                                    code, f"В {func} передан динамический аргумент", "Используйте безопасные API")

            if func_low in ("load","loads") and any(bm in mod_low for bm in ("pickle","marshal","shelve","yaml")):
                self._add_issue("УЯЗВИМОСТЬ", f"Опасная десериализация .{func}", node.lineno,
                                code, "Небезопасный парсер", "Проверьте источник данных")

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
                self._add_issue("УЯЗВИМОСТЬ", "Потенциальная SQL-инъекция", node.lineno,
                                txt, "Динамический SQL", "Используйте параметры")
        except:
            pass

# ----------------------------------------------------------------------
# Автофиксы
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
                logs.append((typ, f"Строка {idx}: закомментирован print -> [{cl.strip()}]"))
            elif act == "DELETE_LINE":
                logs.append((typ, f"Строка {idx}: удалён breakpoint -> [{cl.strip()}]"))
                continue
            else:
                new_lines.append(cl[:ind] + act + end)
                logs.append((typ, f"Строка {idx}: защищён пустой except -> [{cl.strip()}]"))
        else:
            new_lines.append(line)
    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    return logs

# ----------------------------------------------------------------------
# Главная функция
# ----------------------------------------------------------------------

def main():
    start = time.time()
    print(f"{COLORS['CYAN']}==================================================\n         АНАЛИЗАТОР БЕЗОПАСНОСТИ (v1.0)\n=================================================={COLORS['RESET']}\n")

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
        print(f"{COLORS['YELLOW']}Python-файлы не найдены.{COLORS['RESET']}")
        return

    total = 0
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
                print(f"\n{COLORS['GREEN']}[ОЧИЩЕНО] {name}: {len(applied)} строк{COLORS['RESET']}")
                for typ, msg in applied:
                    print(f"  {COLORS['YELLOW']}->{COLORS['RESET']} {msg}")
                    stats[typ] += 1
                    all_logs.append(msg)

            analyzer._print_issues()
            total += len([i for i in analyzer.issues if i["level"] == "УЯЗВИМОСТЬ"])

        except Exception as e:
            print(f"\n{COLORS['RED']}[ОШИБКА] {fpath.name}: {e}{COLORS['RESET']}")

    print(f"\n{COLORS['CYAN']}{'='*50}\nВремя: {time.time()-start:.3f} сек\n{'-'*50}\nОТЧЁТ ПО ИСПРАВЛЕНИЯМ:{COLORS['RESET']}")
    if not all_logs:
        print(f" {COLORS['GREEN']}✔ Отладочный мусор отсутствует{COLORS['RESET']}")
    for k, v in stats.items():
        if v:
            print(f" {COLORS['GREEN']}✔ {k}: {v}{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}{'='*50}{COLORS['RESET']}\nОпасные уязвимости: " +
          (f"{COLORS['GREEN']}НЕ НАЙДЕНЫ{COLORS['RESET']}" if total==0 else f"{COLORS['RED']}{total}{COLORS['RESET']}"))
    print(f"{COLORS['CYAN']}{'='*50}{COLORS['RESET']}\n")
    if os.environ.get("CI") != "true":
        input("Нажмите Enter...")

if __name__ == "__main__":
    main()