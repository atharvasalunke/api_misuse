import os
import ast
import json

class CryptoAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.hardcoded_keys = {}
        self.function_defs = {}
        self.issues = []

    def visit_FunctionDef(self, node):
        self.function_defs[node.name] = node
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Detect hardcoded keys
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes)):
            if isinstance(node.value.value, (str, bytes)):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.hardcoded_keys[target.id] = node.lineno
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = self._get_call_func_name(node)

        # AES.new(...) detections
        if func_name == 'AES.new':
            self._check_aes_usage(node)

        # PBKDF2(...) salt detection
        if func_name == 'PBKDF2':
            self._check_pbkdf2_usage(node)

        self.generic_visit(node)

    def _check_aes_usage(self, node):
        if len(node.args) >= 2:
            mode_arg = node.args[1]
            if isinstance(mode_arg, ast.Attribute):
                if mode_arg.attr == "MODE_ECB":
                    self.issues.append((node.lineno, "Insecure AES.MODE_ECB detected"))
                elif mode_arg.attr in ("MODE_CBC", "MODE_CFB"):
                    if len(node.args) < 3:
                        self.issues.append((node.lineno, f"Missing IV in AES.{mode_arg.attr} mode"))

        # Hardcoded key usage
        if len(node.args) >= 1 and isinstance(node.args[0], ast.Name):
            key_name = node.args[0].id
            if key_name in self.hardcoded_keys:
                self.issues.append((node.lineno, f"Hardcoded key used in AES.new(): {key_name}"))

    def _check_pbkdf2_usage(self, node):
        salt_var_name = None

        # Case 1: salt passed as positional argument
        if len(node.args) >= 2:
            salt_arg = node.args[1]
            if isinstance(salt_arg, ast.Constant):
                if salt_arg.value is None:
                    self.issues.append((node.lineno, "PBKDF2 used with None as salt"))
                elif isinstance(salt_arg.value, (str, bytes)):
                    self.issues.append((node.lineno, "PBKDF2 used with hardcoded salt (positional)"))
            elif isinstance(salt_arg, ast.Name):
                salt_var_name = salt_arg.id

        # Case 2: salt passed as keyword argument
        else:
            for kw in node.keywords:
                if kw.arg == "salt":
                    if isinstance(kw.value, ast.Constant):
                        if kw.value.value is None:
                            self.issues.append((node.lineno, "PBKDF2 used with None as salt"))
                        elif isinstance(kw.value.value, (str, bytes)):
                            self.issues.append((node.lineno, "PBKDF2 used with hardcoded salt (keyword)"))
                    elif isinstance(kw.value, ast.Name):
                        salt_var_name = kw.value.id

        # Check if the variable used as salt was hardcoded earlier
        if salt_var_name and salt_var_name in self.hardcoded_keys:
            self.issues.append((node.lineno, f"PBKDF2 used with hardcoded salt variable: {salt_var_name}"))

    @staticmethod
    def _get_call_func_name(node):
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return None

    def report(self):
        return [
            {
                "line": lineno,
                "issue": issue
            }
            for lineno, issue in sorted(self.issues, key=lambda x: x[0])
        ]


def analyze_file(filepath):
    with open(filepath, "r") as file:
        source = file.read()
    tree = ast.parse(source, filename=filepath)
    analyzer = CryptoAnalyzer()
    analyzer.visit(tree)
    return analyzer.report()

def analyze_path(path):
    results = {}
    if os.path.isfile(path) and path.endswith('.py'):
        results[path] = analyze_file(path)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith('.py'):
                    full_path = os.path.join(root, file)
                    results[full_path] = analyze_file(full_path)
    return results

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python basic_checker.py <file_or_directory> [<file_or_directory> ...]")
    else:
        all_results = {}
        for path in sys.argv[1:]:
            all_results.update(analyze_path(path))
        print(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()