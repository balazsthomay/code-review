import chromadb
from chromadb.config import Settings

# Initialize ChromaDB with persistent storage
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# Create collection for Python gotchas patterns
python_gotchas_collection = chroma_client.get_or_create_collection(
    name="python_gotchas_patterns",
    metadata={"description": "Python-specific gotchas and common mistakes for code review"}
)

# Python gotchas patterns extracted from official sources:
# - Python.org Official Programming FAQ: https://docs.python.org/3/faq/programming.html
# - The Hitchhiker's Guide to Python: https://docs.python-guide.org/writing/gotchas/
# - Python Language Reference: https://docs.python.org/3/reference/

python_gotchas_patterns = [
    # Late Binding and Closures
    {
        "id": "late_binding_closures",
        "pattern_name": "Late Binding in Closures",
        "category": "Closures & Scoping",
        "source": "Python.org FAQ, Hitchhiker's Guide",
        "description": "Python's closures are late binding. The values of variables used in closures are looked up at the time the inner function is called, not when it's defined. All closures created in a loop reference the same final variable value.",
        "vulnerable_example": "def create_multipliers(): return [lambda x: i * x for i in range(5)] - All functions will use i=4 (final loop value), printing 8,8,8,8,8 instead of 0,2,4,6,8",
        "detection": "Look for lambda functions or nested function definitions inside loops that reference loop variables. Check for list comprehensions creating functions that use outer loop variables.",
        "prevention": "Use default arguments to capture current value: lambda x, i=i: i * x. Or use functools.partial: partial(mul, i). This binds the variable at definition time rather than call time.",
        "severity": "medium",
        "reference": "https://docs.python-guide.org/writing/gotchas/#late-binding-closures"
    },
    {
        "id": "unbound_local_error",
        "pattern_name": "UnboundLocalError with Variable Assignment",
        "category": "Closures & Scoping",
        "source": "Python.org FAQ",
        "description": "When a variable is assigned anywhere in a function, Python treats it as local throughout the entire function scope, even before the assignment. This causes references before assignment to raise UnboundLocalError.",
        "vulnerable_example": "x = 10; def foo(): print(x); x = 5 - Raises UnboundLocalError because x is assigned later in function, making it local throughout",
        "detection": "Look for functions that: 1) reference a variable, 2) later assign to that same variable name, 3) don't declare it as global or nonlocal",
        "prevention": "Use global x or nonlocal x declaration before first use if you intend to modify outer scope variable. Or use different variable names.",
        "severity": "medium",
        "reference": "https://docs.python.org/3/faq/programming.html#why-am-i-getting-an-unboundlocalerror-when-the-variable-has-a-value"
    },

    # Mutable Default Arguments (complementing existing best_practices pattern)
    {
        "id": "mutable_default_state_leakage",
        "pattern_name": "Mutable Default Argument State Leakage",
        "category": "Function Definitions",
        "source": "Python.org FAQ, Hitchhiker's Guide",
        "description": "Default parameter values are created exactly once when the function is defined, not each time the function is called. Modifying mutable defaults (lists, dicts, sets) persists state across all invocations.",
        "vulnerable_example": "def append_to(element, to=[]): to.append(element); return to - Second call returns [first_element, second_element] because same list object is reused",
        "detection": "Check function signatures for default arguments that are lists [], dicts {}, sets set(), or any mutable object. Look for def func(arg=[]): or def func(arg={}):",
        "prevention": "Use None as sentinel: def append_to(element, to=None): if to is None: to = []; to.append(element). Create fresh mutable object inside function body.",
        "severity": "high",
        "reference": "https://docs.python-guide.org/writing/gotchas/#mutable-default-arguments"
    },

    # List/Object References
    {
        "id": "list_assignment_reference",
        "pattern_name": "List Assignment Creates References Not Copies",
        "category": "Object References",
        "source": "Python.org FAQ",
        "description": "Using y = x for lists/dicts creates a reference to the same object, not a copy. Modifications through either name affect the shared object.",
        "vulnerable_example": "x = [1, 2, 3]; y = x; y.append(4) - Now x is also [1, 2, 3, 4] because x and y point to same list object",
        "detection": "Look for assignments like y = x where x is a list, dict, or other mutable container, followed by mutations to y. Check if code expects independent copies.",
        "prevention": "Use explicit copying: y = x.copy() for shallow copy, or import copy; y = copy.deepcopy(x) for deep copy. For lists: y = x[:] or y = list(x)",
        "severity": "medium",
        "reference": "https://docs.python.org/3/faq/programming.html#how-do-i-create-a-multidimensional-list"
    },
    {
        "id": "shared_reference_replication",
        "pattern_name": "Shared References in Container Replication",
        "category": "Object References",
        "source": "Python.org FAQ",
        "description": "Replicating a list with * doesn't create copies, it only creates references. [[None] * 2] * 3 creates multiple references to the same inner list, so changes appear in all rows.",
        "vulnerable_example": "matrix = [[None] * 2] * 3; matrix[0][0] = 5 - All rows become [5, None] because all rows reference same inner list",
        "detection": "Look for nested list creation using * operator: [[x] * n] * m pattern. Check for 2D array initialization using multiplication.",
        "prevention": "Use list comprehension to create independent objects: matrix = [[None] * 2 for _ in range(3)]. Each iteration creates new inner list.",
        "severity": "high",
        "reference": "https://docs.python.org/3/faq/programming.html#how-do-i-create-a-multidimensional-list"
    },

    # Identity vs Equality
    {
        "id": "identity_vs_equality",
        "pattern_name": "Identity vs Equality Confusion",
        "category": "Comparisons",
        "source": "Python.org FAQ",
        "description": "The is operator tests object identity (same memory address), not value equality. Using is for value comparison can fail unexpectedly, especially with integers, strings, and other values that may or may not be cached.",
        "vulnerable_example": "a = 256; b = 256; a is b - Returns True (cached). But a = 257; b = 257; a is b - Returns False (not cached). Using is for value comparison is unreliable.",
        "detection": "Look for is or is not used to compare: numbers, strings, lists, dicts, or any non-singleton values. Only None, True, False should use is.",
        "prevention": "Use == for value equality: if x == 5. Reserve is only for: if x is None, if x is True, if x is False. Use is only when checking object identity is specifically required.",
        "severity": "medium",
        "reference": "https://docs.python.org/3/faq/programming.html#how-do-i-test-whether-a-variable-is-defined"
    },

    # Mutation Return Values
    {
        "id": "mutation_returns_none",
        "pattern_name": "Mutating Methods Return None",
        "category": "Method Behaviors",
        "source": "Python.org FAQ",
        "description": "Methods that mutate an object in-place return None to make it clear the object was modified. This is consistent across list.sort(), list.reverse(), random.shuffle(), etc.",
        "vulnerable_example": "sorted_list = my_list.sort() - sorted_list is None! The sort() method modified my_list in place and returned None",
        "detection": "Look for assignments capturing return values of mutating methods: result = list.sort(), result = list.reverse(), result = dict.clear()",
        "prevention": "Don't assign return value of mutating methods. Use method for side effect only: my_list.sort(). Or use non-mutating versions: sorted_list = sorted(my_list)",
        "severity": "low",
        "reference": "https://docs.python.org/3/faq/programming.html#why-doesn-t-list-sort-return-the-sorted-list"
    },

    # Import Issues
    {
        "id": "circular_import_failure",
        "pattern_name": "Circular Import Failure",
        "category": "Imports",
        "source": "Python.org FAQ",
        "description": "Using from module import name at module level fails with circular imports because names aren't available during initial module loading. Module is partially initialized when circular import occurs.",
        "vulnerable_example": "Module A: from B import func_b; Module B: from A import func_a - Fails because when A tries to import from B, B tries to import from A which isn't finished loading",
        "detection": "Look for from X import Y at top level in modules that might have circular dependencies. Check import order when ImportError or AttributeError occurs during import.",
        "prevention": "Refactor to remove circular dependencies. Or use import module then module.name. Or move imports inside functions. Or restructure code to extract shared functionality to third module.",
        "severity": "medium",
        "reference": "https://docs.python.org/3/faq/programming.html#what-are-the-best-practices-for-using-import-in-a-module"
    },
    {
        "id": "module_import_caching",
        "pattern_name": "Module Reimports Don't Reflect Changes",
        "category": "Imports",
        "source": "Python.org FAQ",
        "description": "Python only reads the module file on the first time a module is imported. Subsequent import statements bind the module name to the already-loaded module object. Code changes aren't reflected without restart.",
        "vulnerable_example": "import mymodule; # modify mymodule.py; import mymodule - Changes not loaded because module is cached",
        "detection": "Look for development/debugging code that imports modules multiple times expecting changes to be reflected. Check for test code that modifies and re-imports modules.",
        "prevention": "Use importlib.reload(module) to force re-reading: import importlib; importlib.reload(mymodule). Or restart Python interpreter. In production, this is desired behavior for performance.",
        "severity": "low",
        "reference": "https://docs.python.org/3/faq/programming.html#how-do-i-make-a-python-script-executable-on-unix"
    },

    # Tuple Immutability Edge Case
    {
        "id": "tuple_augmented_assignment",
        "pattern_name": "Augmented Assignment on Tuple Elements",
        "category": "Immutability",
        "source": "Python.org FAQ",
        "description": "Using += on tuple elements that contain mutable objects causes partial failure. The mutable object is modified (mutation succeeds) but then assignment fails (tuple is immutable), leaving object in modified state.",
        "vulnerable_example": "t = ([1, 2], 3); t[0] += [3] - Raises TypeError but t[0] is modified to [1, 2, 3]. Mutation succeeded but reassignment failed.",
        "detection": "Look for augmented assignment operators (+=, -=, *=, etc.) used on elements of tuples: tuple[index] += value",
        "prevention": "Extract element, modify, then recreate tuple: temp = t[0]; temp += [3]; t = (temp, t[1]). Or don't use mutable objects in tuples if you need to modify them.",
        "severity": "low",
        "reference": "https://docs.python.org/3/faq/programming.html#why-does-a-tuple-i-item-raise-an-exception-when-the-addition-works"
    },
]

# Add documents to ChromaDB
documents = [
    p["pattern_name"] + ": " + p["description"] + " " +
    p["vulnerable_example"] + " Prevention: " + p["prevention"] +
    " Detection: " + p["detection"]
    for p in python_gotchas_patterns
]

metadatas = [
    {k: v for k, v in p.items() if k not in ['pattern_name', 'description', 'vulnerable_example', 'prevention', 'detection']}
    for p in python_gotchas_patterns
]

ids = [p["id"] for p in python_gotchas_patterns]

python_gotchas_collection.add(
    documents=documents,
    metadatas=metadatas,
    ids=ids
)

print(f"Added {len(python_gotchas_patterns)} Python gotcha patterns to ChromaDB")
print(f"Collection now has {python_gotchas_collection.count()} documents")

# Test retrieval
print("\n" + "="*60)
print("Testing retrieval with sample queries:")
print("="*60)

# Test 1: Late binding closure
test_query_1 = "def create_funcs(): return [lambda x: i * x for i in range(5)]"
results_1 = python_gotchas_collection.query(
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

# Test 2: Mutable default
print("\n" + "="*60)
test_query_2 = "def add_item(item, items=[]): items.append(item); return items"
results_2 = python_gotchas_collection.query(
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

# Test 3: List assignment
print("\n" + "="*60)
test_query_3 = "x = [1, 2, 3]; y = x; y.append(4)"
results_3 = python_gotchas_collection.query(
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
print("Python Gotchas Knowledge Base built successfully!")
print("="*60)
