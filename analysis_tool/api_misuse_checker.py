import sys
import os
import ast
import json

class CryptoAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.hardcoded_keys = {}
        self.function_defs = {}
        self.issues = []
        self.call_graph = {}
        self.current_function = None

    # Store function definitions and track current function context
    def visit_FunctionDef(self, node):
        self.function_defs[node.name] = node
        previous_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = previous_function

    # Detect hardcoded string or byte values assigned to variables
    def visit_Assign(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.hardcoded_keys[target.id] = node.lineno
        self.generic_visit(node)

    # Process function calls, track call graph, and check cryptographic API usage
    def visit_Call(self, node):
        func_name = self._get_call_func_name(node)
        if self.current_function and func_name:
            self._track_function_call(self.current_function, func_name)

        if func_name == 'AES.new':
            self._check_aes_usage(node)

        if func_name == 'PBKDF2':
            self._check_pbkdf2_usage(node)

        self.generic_visit(node)

    # Maintain a call graph mapping callers to callees
    def _track_function_call(self, caller, callee):
        if caller not in self.call_graph:
            self.call_graph[caller] = set()
        self.call_graph[caller].add(callee)

    # Perform backward data flow analysis to trace arguments to their source
    def trace_data_flow(self):
        # Build reverse call graph (callee -> list of callers)
        reverse_graph = {}
        for caller, callees in self.call_graph.items():
            for callee in callees:
                reverse_graph.setdefault(callee, set()).add(caller)

        # For each function that calls AES.new or PBKDF2, trace arguments
        for func_name, func_node in self.function_defs.items():
            for node in ast.walk(func_node):
                if isinstance(node, ast.Call):
                    api_name = self._get_call_func_name(node)
                    if api_name in {'AES.new', 'PBKDF2'}:
                        if node.args:
                            suspect_arg = node.args[0] if api_name == 'AES.new' else node.args[1] if len(node.args) > 1 else None
                            if isinstance(suspect_arg, ast.Name):
                                arg_name = suspect_arg.id
                                self._trace_argument_source(func_name, arg_name, {func_name}, reverse_graph, usage_site=(func_name, node.lineno))

    # Recursively trace the source of an argument to detect if it's hardcoded
    def _trace_argument_source(self, func_name, arg_name, visited, reverse_graph, usage_site):
        # Check if variable is hardcoded in this function
        func_node = self.function_defs.get(func_name)
        if not func_node:
            return
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == arg_name:
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes)):
                            usage_func, usage_line = usage_site
                            self.issues.append((
                                node.lineno,
                                f"{arg_name} traced to hardcoded value in {func_name}(), used in {usage_func}() at line {usage_line}"
                            ))
                            return

        # Otherwise check the callers and trace the passed argument
        callers = reverse_graph.get(func_name, set())
        for caller in callers:
            if caller in visited:
                continue
            visited.add(caller)
            caller_node = self.function_defs.get(caller)
            if not caller_node:
                continue
            for call in ast.walk(caller_node):
                if isinstance(call, ast.Call):
                    called_name = self._get_call_func_name(call)
                    if called_name == func_name:
                        # Match argument position
                        for i, arg in enumerate(call.args):
                            if isinstance(arg, ast.Name):
                                self._trace_argument_source(caller, arg.id, visited, reverse_graph, usage_site)

    # Extract the name of a called function from an AST node
    @staticmethod
    def _get_call_func_name(node):
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return None

    # Check for insecure AES modes and hardcoded keys in AES.new() calls
    def _check_aes_usage(self, node):
        if len(node.args) >= 2:
            mode_arg = node.args[1]
            if isinstance(mode_arg, ast.Attribute):
                if mode_arg.attr == "MODE_ECB":
                    self.issues.append((node.lineno, "Insecure AES.MODE_ECB detected"))
                elif mode_arg.attr in ("MODE_CBC", "MODE_CFB"):
                    if len(node.args) < 3:
                        self.issues.append((node.lineno, f"Missing IV in AES.{mode_arg.attr} mode"))

        if len(node.args) >= 1 and isinstance(node.args[0], ast.Name):
            key_name = node.args[0].id
            if key_name in self.hardcoded_keys:
                self.issues.append((node.lineno, f"Hardcoded key used in AES.new(): {key_name}"))

    # Check for hardcoded or missing salts in PBKDF2 usage
    def _check_pbkdf2_usage(self, node):
        salt_var_name = None

        if len(node.args) >= 2:
            salt_arg = node.args[1]
            if isinstance(salt_arg, ast.Constant):
                if salt_arg.value is None:
                    self.issues.append((node.lineno, "PBKDF2 used with None as salt"))
                elif isinstance(salt_arg.value, (str, bytes)):
                    self.issues.append((node.lineno, "PBKDF2 used with hardcoded salt (positional)"))
            elif isinstance(salt_arg, ast.Name):
                salt_var_name = salt_arg.id
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

        if salt_var_name and salt_var_name in self.hardcoded_keys:
            self.issues.append((node.lineno, f"PBKDF2 used with hardcoded salt variable: {salt_var_name}"))

    # Generate a sorted list of detected issues with line numbers
    def report(self):
        return [
            {
                "line": lineno,
                "issue": issue
            }
            for lineno, issue in sorted(self.issues, key=lambda x: x[0])
        ]


# Parse and analyze a single Python file for crypto API misuses
def analyze_file(filepath):
    with open(filepath, "r") as file:
        source = file.read()
    tree = ast.parse(source, filename=filepath)
    analyzer = CryptoAnalyzer()
    analyzer.visit(tree)
    analyzer.trace_data_flow()
    return analyzer.report()

# Recursively analyze all Python files in a directory or analyze a single file
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

# Entry point to run analysis on given files or directories and print JSON results
def main():
    if len(sys.argv) < 2:
        print("Usage: python api_misuse_checker.py <file_or_directory> [<file_or_directory> ...]")
    else:
        all_results = {}
        for path in sys.argv[1:]:
            all_results.update(analyze_path(path))
        print(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()