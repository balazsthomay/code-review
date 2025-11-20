import chromadb
from chromadb.config import Settings

# Initialize ChromaDB with persistent storage
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# Create collection for best practices patterns
best_practices_collection = chroma_client.get_or_create_collection(
    name="best_practices_patterns",
    metadata={"description": "Python best practices patterns for code review"}
)

# Best practices patterns extracted from official sources:
# - PEP 8: https://peps.python.org/pep-0008/
# - PEP 257: https://peps.python.org/pep-0257/
# - Real Python Error Handling: https://realpython.com/python-exceptions/
# - Miguel Grinberg Error Handling: https://blog.miguelgrinberg.com/post/the-ultimate-guide-to-error-handling-in-python
# - Python Anti-Patterns: https://docs.quantifiedcode.com/python-anti-patterns/

best_practices_patterns = [
    # Error Handling Patterns
    {
        "id": "missing_error_handling",
        "pattern_name": "Missing Error Handling",
        "category": "Error Handling",
        "source": "PEP 8, Python Best Practices",
        "description": "Functions that perform error-prone operations (file I/O, database operations, network calls) without try-except blocks. Python follows EAFP (Easier to Ask Forgiveness than Permission) - use exceptions for error handling.",
        "vulnerable_example": "def read_file(path): f = open(path); data = f.read(); f.close(); return data - No exception handling for missing file or read errors",
        "detection": "Look for file operations (open, read, write), database operations (execute, commit), network calls (requests), or external system calls without surrounding try-except blocks",
        "prevention": "Wrap error-prone operations in try-except blocks. Catch specific exceptions (IOError, ValueError, etc.) not bare except. Use context managers (with statement) for resource management.",
        "severity": "medium",
        "reference": "https://peps.python.org/pep-0008/#programming-recommendations"
    },
    {
        "id": "bare_except",
        "pattern_name": "Bare Except Clause",
        "category": "Error Handling",
        "source": "PEP 8",
        "description": "Using bare except: clause catches all exceptions including SystemExit and KeyboardInterrupt, making it harder to interrupt programs and masking bugs",
        "vulnerable_example": "try: risky_operation() except: pass - Catches ALL exceptions including Ctrl+C",
        "detection": "Look for except: without specifying exception type, or except Exception: which is too broad",
        "prevention": "Catch specific exceptions: except ValueError: or except (IOError, OSError): Always specify which exceptions to handle",
        "severity": "medium",
        "reference": "https://peps.python.org/pep-0008/#programming-recommendations"
    },
    {
        "id": "overly_broad_try",
        "pattern_name": "Overly Broad Try Block",
        "category": "Error Handling",
        "source": "PEP 8, Error Handling Best Practices",
        "description": "Try blocks that contain too much code make it difficult to determine which statement caused an exception and can mask bugs",
        "vulnerable_example": "try: value = collection[key]; result = handle_value(value); return result except KeyError: return default - Will catch KeyError from handle_value too",
        "detection": "Try blocks with multiple statements or function calls that could raise the same exception type",
        "prevention": "Limit try clause to absolute minimum code necessary. Use try-except-else to separate risky operations from post-success code",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0008/#programming-recommendations"
    },
    
    # Input Validation Patterns
    {
        "id": "missing_input_validation",
        "pattern_name": "Missing Input Validation",
        "category": "Input Validation",
        "source": "Python Best Practices, OWASP",
        "description": "Functions accepting parameters without validating type, range, or format. Can lead to runtime errors, unexpected behavior, or security issues",
        "vulnerable_example": "def divide(a, b): return a / b - No check for b==0, no type validation",
        "detection": "Look for functions with parameters that: don't check for None, don't validate numeric ranges (age < 0, count < 0), don't validate string formats (email, phone), don't check empty collections",
        "prevention": "Validate inputs at function entry. Check for None, validate ranges with if statements, use isinstance() for type checking when necessary, raise ValueError for invalid inputs",
        "severity": "medium",
        "reference": "https://www.datacamp.com/tutorial/python-user-input"
    },
    {
        "id": "no_edge_case_handling",
        "pattern_name": "Missing Edge Case Handling",
        "category": "Input Validation",
        "source": "Python Best Practices",
        "description": "Functions don't handle edge cases like empty lists, zero values, negative numbers, or boundary conditions",
        "vulnerable_example": "def get_last_n(items, n): return items[-n:] - Breaks when n=0 or n>len(items)",
        "detection": "Look for array/list operations without checking: empty collections, zero or negative indices, boundary values in loops",
        "prevention": "Add explicit checks for edge cases: if not items, if n <= 0, if n > len(items). Document expected input ranges in docstrings",
        "severity": "medium",
        "reference": "https://www.geeksforgeeks.org/python/input-validation-in-python/"
    },
    
    # Docstring Patterns
    {
        "id": "missing_docstring",
        "pattern_name": "Missing Docstrings",
        "category": "Documentation",
        "source": "PEP 257",
        "description": "Public modules, functions, classes, and methods without docstrings. Docstrings are essential for code understanding and maintainability",
        "vulnerable_example": "def calculate_tax(income, rate): return income * rate - No docstring explaining purpose, parameters, or return value",
        "detection": "Check for class definitions, function definitions (especially public ones) without docstring as first statement",
        "prevention": "Add docstrings to all public modules, classes, and functions. Use triple quotes. For functions: describe purpose, parameters, return value, and exceptions raised",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0257/"
    },
    {
        "id": "poor_docstring_format",
        "pattern_name": "Poor Docstring Format",
        "category": "Documentation",
        "source": "PEP 257",
        "description": "Docstrings that don't follow PEP 257 conventions: one-liner docstrings should be on one line, multi-line docstrings should have summary line + blank line + details",
        "vulnerable_example": "def complex(): '''This function does something really complex and returns a value''' - One-liner too long, should be multi-line",
        "detection": "Check docstring format: one-liners over 79 chars, multi-line without blank line after summary, closing quotes not on separate line",
        "prevention": "One-liners: '''Do something and return result.''' Multi-line: '''Summary line.\\n\\nDetailed description.\\n'''",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0257/"
    },
    
    # Resource Management Patterns
    {
        "id": "unclosed_resource",
        "pattern_name": "Unclosed Resource",
        "category": "Resource Management",
        "source": "PEP 8, Python Best Practices",
        "description": "Resources (files, database connections, cursors, network sockets) opened but not explicitly closed. Leads to resource leaks",
        "vulnerable_example": "f = open('file.txt'); data = f.read() - File never closed, file descriptor leaked",
        "detection": "Look for open(), connect(), cursor() calls without corresponding close() or without using context manager (with statement)",
        "prevention": "Always use context managers (with statement): with open('file.txt') as f: data = f.read(). Or use try-finally to ensure cleanup",
        "severity": "medium",
        "reference": "https://peps.python.org/pep-0008/#programming-recommendations"
    },
    {
        "id": "no_context_manager",
        "pattern_name": "Not Using Context Manager",
        "category": "Resource Management",
        "source": "PEP 8",
        "description": "Opening resources without using with statement. Context managers ensure resources are cleaned up even if exceptions occur",
        "vulnerable_example": "cursor = db.cursor(); cursor.execute(query); cursor.close() - No context manager, won't close on exception",
        "detection": "File operations, database connections, locks without with statement",
        "prevention": "Use with statement: with db.cursor() as cursor: cursor.execute(query). Resources auto-close when leaving block",
        "severity": "medium",
        "reference": "https://peps.python.org/pep-0008/#programming-recommendations"
    },
    
    # Code Complexity Patterns  
    {
        "id": "excessive_nesting",
        "pattern_name": "Excessive Nesting Depth",
        "category": "Code Complexity",
        "source": "PEP 8, Python Best Practices",
        "description": "Functions with deeply nested if/for/while statements (>3 levels) are hard to read and maintain",
        "vulnerable_example": "if a: if b: if c: if d: if e: return x - 5 levels of nesting",
        "detection": "Count indentation levels in function body. Flag functions with >3 nested levels",
        "prevention": "Use guard clauses (early returns): if not a: return; if not b: return. Extract nested blocks into separate functions. Use all() for multiple conditions",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0008/"
    },
    {
        "id": "magic_numbers",
        "pattern_name": "Magic Numbers",
        "category": "Code Complexity",
        "source": "PEP 8",
        "description": "Unexplained numeric literals in code reduce readability and make maintenance difficult",
        "vulnerable_example": "if age < 18 or score > 100 or discount == 0.15 - What do these numbers mean?",
        "detection": "Look for numeric literals (except 0, 1, -1) used directly in comparisons or calculations without explanation",
        "prevention": "Define named constants: MIN_AGE = 18; MAX_SCORE = 100; DISCOUNT_RATE = 0.15. Add comments explaining significance",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0008/"
    },
    {
        "id": "unclear_variable_names",
        "pattern_name": "Unclear Variable Names",
        "category": "Code Complexity",
        "source": "PEP 8",
        "description": "Single-letter variables (except i, j, k in loops) or unclear abbreviations make code hard to understand",
        "vulnerable_example": "def calc(a, b, c, d, e): x = a * b; y = c + d; z = x - y - Meaningless names",
        "detection": "Check for single-letter variable names (a, b, x, y, z) outside loop contexts, unclear abbreviations like tmp, val, num",
        "prevention": "Use descriptive names: price, quantity, total_cost. Follow PEP 8: lowercase_with_underscores for variables and functions",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0008/#naming-conventions"
    },
    
    # Import Patterns
    {
        "id": "wildcard_import",
        "pattern_name": "Wildcard Import",
        "category": "Imports",
        "source": "PEP 8",
        "description": "Using from module import * makes it unclear which names are in namespace and can cause name conflicts",
        "vulnerable_example": "from math import * - Imports everything, pollutes namespace, unclear which functions come from math",
        "detection": "Look for from X import * statements",
        "prevention": "Import specific items: from math import sqrt, pi or import module: import math; math.sqrt()",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0008/#imports"
    },
    {
        "id": "incorrect_import_order",
        "pattern_name": "Incorrect Import Order",
        "category": "Imports",
        "source": "PEP 8",
        "description": "Imports not grouped correctly. Should be: standard library, third-party, local application imports, with blank lines between groups",
        "vulnerable_example": "import requests; from .mymodule import func; import os - Wrong order, no grouping",
        "detection": "Check if imports are ordered: stdlib first, then third-party, then local. Check for blank lines between groups",
        "prevention": "Group imports: 1) stdlib (import os, sys), 2) third-party (import requests), 3) local (from . import mymod). Separate groups with blank line",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0008/#imports"
    },
    
    # Antipatterns
    {
        "id": "using_mutable_default_arg",
        "pattern_name": "Mutable Default Argument",
        "category": "Antipatterns",
        "source": "Python Anti-Patterns",
        "description": "Using mutable objects (list, dict, set) as default arguments. The default is created once and shared across all calls, leading to unexpected behavior",
        "vulnerable_example": "def add_item(item, items=[]): items.append(item); return items - list is shared across calls!",
        "detection": "Check function signatures for default arguments that are lists, dicts, or sets: def func(arg=[])",
        "prevention": "Use None as default: def add_item(item, items=None): if items is None: items = []; items.append(item)",
        "severity": "high",
        "reference": "https://docs.quantifiedcode.com/python-anti-patterns/"
    },
    {
        "id": "returning_different_types",
        "pattern_name": "Inconsistent Return Types",
        "category": "Antipatterns",
        "source": "Python Anti-Patterns, PEP 8",
        "description": "Function returns different types in different code paths (e.g., sometimes list, sometimes None). Makes calling code fragile",
        "vulnerable_example": "def get_users(count): if count > 0: return [users]; return None - Returns list OR None",
        "detection": "Check if function has multiple return statements with different types: return [], return None, return False",
        "prevention": "Return consistent types: always return list (empty if no results), always return dict. Document return type. Raise exception for errors instead of returning None/False",
        "severity": "medium",
        "reference": "https://docs.quantifiedcode.com/python-anti-patterns/"
    },
    {
        "id": "comparing_types_incorrectly",
        "pattern_name": "Incorrect Type Comparison",
        "category": "Antipatterns",
        "source": "PEP 8",
        "description": "Using type(obj) == type(1) instead of isinstance() for type checking. Less flexible and doesn't handle inheritance",
        "vulnerable_example": "if type(obj) is type(1): - Doesn't work with inheritance or virtual subclasses",
        "detection": "Look for type(x) == type(y) or type(x) is type(y) patterns",
        "prevention": "Use isinstance(): if isinstance(obj, int): - Works with inheritance",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0008/#programming-recommendations"
    },
    {
        "id": "comparing_bool_to_true",
        "pattern_name": "Comparing Boolean to True/False",
        "category": "Antipatterns",
        "source": "PEP 8",
        "description": "Explicitly comparing boolean values to True or False using == is redundant and less Pythonic",
        "vulnerable_example": "if is_valid == True: or if is_valid is True: - Redundant comparison",
        "detection": "Look for == True, == False, is True, is False in conditionals",
        "prevention": "Use direct boolean evaluation: if is_valid: or if not is_valid:",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0008/#programming-recommendations"
    },
    {
        "id": "using_len_for_empty_check",
        "pattern_name": "Using len() for Empty Check",
        "category": "Antipatterns",
        "source": "PEP 8",
        "description": "Using len(seq) to check if sequence is empty. Empty sequences are falsy in Python, so direct check is more Pythonic",
        "vulnerable_example": "if len(items) == 0: or if len(items): - Unnecessary len() call",
        "detection": "Look for len(x) == 0, len(x) > 0, if len(x):, if not len(x):",
        "prevention": "Use direct check: if not items: for empty, if items: for non-empty",
        "severity": "low",
        "reference": "https://peps.python.org/pep-0008/#programming-recommendations"
    },
    {
        "id": "not_using_enumerate",
        "pattern_name": "Not Using enumerate()",
        "category": "Antipatterns",
        "source": "Python Anti-Patterns",
        "description": "Using range(len()) to get both index and value when iterating. enumerate() is cleaner and more Pythonic",
        "vulnerable_example": "for i in range(len(items)): print(i, items[i]) - Verbose and error-prone",
        "detection": "Look for range(len(x)) pattern in for loops",
        "prevention": "Use enumerate: for i, item in enumerate(items): print(i, item)",
        "severity": "low",
        "reference": "https://docs.quantifiedcode.com/python-anti-patterns/"
    },
]

# Add documents to ChromaDB
documents = [
    p["pattern_name"] + ": " + p["description"] + " " + 
    p["vulnerable_example"] + " Prevention: " + p["prevention"] + 
    " Detection: " + p["detection"] 
    for p in best_practices_patterns
]

metadatas = [
    {k: v for k, v in p.items() if k not in ['pattern_name', 'description', 'vulnerable_example', 'prevention', 'detection']} 
    for p in best_practices_patterns
]

ids = [p["id"] for p in best_practices_patterns]

best_practices_collection.add(
    documents=documents,
    metadatas=metadatas,
    ids=ids
)

print(f"Added {len(best_practices_patterns)} best practices patterns to ChromaDB")
print(f"Collection now has {best_practices_collection.count()} documents")

# Test retrieval
print("\n" + "="*60)
print("Testing retrieval with sample queries:")
print("="*60)

# Test 1: Missing error handling
test_query_1 = "def read_config(filename): data = open(filename).read(); return data"
results_1 = best_practices_collection.query(
    query_texts=[test_query_1],
    n_results=3
)

print(f"\nQuery 1: {test_query_1}")
print(f"\nTop 3 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results_1['documents'][0], results_1['metadatas'][0]), 1):
    print(f"\n{i}. Pattern: {metadata['id']}")
    print(f"   Category: {metadata['category']}")
    print(f"   Severity: {metadata['severity']}")
    print(f"   Snippet: {doc[:120]}...")

# Test 2: Missing docstring
print("\n" + "="*60)
test_query_2 = "def calculate_total(items, tax_rate): return sum(items) * (1 + tax_rate)"
results_2 = best_practices_collection.query(
    query_texts=[test_query_2],
    n_results=3
)

print(f"\nQuery 2: {test_query_2}")
print(f"\nTop 3 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results_2['documents'][0], results_2['metadatas'][0]), 1):
    print(f"\n{i}. Pattern: {metadata['id']}")
    print(f"   Category: {metadata['category']}")
    print(f"   Severity: {metadata['severity']}")
    print(f"   Snippet: {doc[:120]}...")

# Test 3: Missing input validation
print("\n" + "="*60)
test_query_3 = "def get_last_n_items(items, n): return items[-n:]"
results_3 = best_practices_collection.query(
    query_texts=[test_query_3],
    n_results=3
)

print(f"\nQuery 3: {test_query_3}")
print(f"\nTop 3 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results_3['documents'][0], results_3['metadatas'][0]), 1):
    print(f"\n{i}. Pattern: {metadata['id']}")
    print(f"   Category: {metadata['category']}")
    print(f"   Severity: {metadata['severity']}")
    print(f"   Snippet: {doc[:120]}...")

print("\n" + "="*60)
print("Best Practices Knowledge Base built successfully!")
print("="*60)