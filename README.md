Статический анализатор AST и инструмент автоматического рефакторинга для Python, работающий без внешних зависимостей. Моментально находит уязвимости, захардкоженные секреты и вычищает отладочный мусор.

🛠️ Что умеет
----------------------------------

AST-аудит безопасности: Выцепляет eval, exec, os.system, os.popen, небезопасный pickle/yaml и слабые хэши (md5/sha1).

Анализ энтропии: Находит скрытые в коде API-ключи, токены и пароли по алгоритму Шеннона.

Умный контекст: Игнорирует динамические пути в open(), если они собраны безопасно через pathlib или os.path.join (минимум ложных тревог).

Auto-Fix (Клининг): Сам комментирует забытые print(), полностью удаляет breakpoint() и закрывает пустые блоки except: pass безопасными заглушками с сохранением структуры отступов.

Static AST analyzer and automatic refactoring tool for Python that works without external dependencies. Instantly finds vulnerabilities, hard-coded secrets, and removes debug junk.

🛠️ What it can do
---------------------------------------------

AST security audit: Detects eval, exec, os.system, os.popen, insecure pickle/yaml, and weak hashes (md5/sha1).

Entropy Analysis: Finds API keys, tokens, and passwords hidden in the code using the Shannon algorithm.

Smart Context: Ignores dynamic paths in open() if they are collected safely using pathlib or os.path.join (minimum false positives).

Auto-Fix (Cleaning): Comments out forgotten print(), removes breakpoint() completely, and closes empty except: pass blocks with safe stubs while preserving the indentation structure.
