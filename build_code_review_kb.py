import chromadb
from chromadb.config import Settings

# Initialize ChromaDB with persistent storage
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# Create collection for code review patterns
code_review_collection = chroma_client.get_or_create_collection(
    name="code_review_patterns",
    metadata={"description": "Code review patterns for detecting breaking changes and design issues"}
)

# Code review patterns extracted from official sources:
# - Google Engineering Practices: https://google.github.io/eng-practices/review/
# - API Breaking Changes Best Practices: https://apidriftalert.com/
# - Martin Fowler Refactoring: https://martinfowler.com/

code_review_patterns = [
    # Breaking Changes & Deletions
    {
        "id": "deleted_function_breaking_callers",
        "pattern_name": "Deleted Function Breaking Callers",
        "category": "Breaking Changes",
        "source": "API Breaking Changes Best Practices",
        "description": "Removing functions, methods, or classes without checking if they're called elsewhere in the codebase. This is a common breaking change that breaks existing functionality.",
        "vulnerable_example": "Deleting helper function trim_filename() that's called from other modules. Removing validation functions that are used by multiple callers. Deleting utility methods without deprecation period.",
        "detection": "When reviewing deletions (lines starting with -), check: 1) Is this a function/class/method definition? 2) Search codebase for calls to this name. 3) Check if removed from public API. 4) Look for imports of deleted names in other files.",
        "prevention": "Before deleting, search entire codebase for usage: git grep 'function_name'. Use deprecation warnings first: @deprecated decorator. Provide migration path. Update all callers in same PR or coordinate with dependent teams.",
        "severity": "critical",
        "reference": "https://apidriftalert.com/api-breaking-changes-detection-best-practices-for-maintaining-compatibility/"
    },
    {
        "id": "api_signature_change",
        "pattern_name": "API Signature Changes",
        "category": "Breaking Changes",
        "source": "API Breaking Changes Best Practices",
        "description": "Changing function signatures by adding required parameters, removing parameters, changing parameter order, or changing return types breaks existing callers.",
        "vulnerable_example": "Changing def process(data) to def process(data, config) where config is required. Changing return type from list to dict. Reordering parameters: def func(a, b) to def func(b, a).",
        "detection": "Look for function signature modifications: added parameters without defaults, removed parameters, changed parameter order, changed return types. Check if function is used externally or in multiple places.",
        "prevention": "Add new parameters as optional with defaults: def process(data, config=None). Keep old signature and add new version: process_v2(). Use **kwargs for extensibility. Provide backward compatibility layer.",
        "severity": "critical",
        "reference": "https://blog.treblle.com/5-ways-to-test-apis-breaking-changes/"
    },
    {
        "id": "removed_import_breaking_modules",
        "pattern_name": "Removed Import Breaking Dependent Modules",
        "category": "Breaking Changes",
        "source": "Google Engineering Practices",
        "description": "Removing import statements that are needed by other modules or removing exports from __init__.py that other modules depend on. Multi-file changes where one file's import affects another.",
        "vulnerable_example": "File A removes: from module import helper. File B uses: from A import helper (re-exporting). Now File B breaks. Or removing from __init__ import Class breaks external imports.",
        "detection": "When reviewing removed imports, check: 1) Does this module re-export these names? 2) Do other modules import from this module? 3) Is this in __init__.py affecting package API? 4) Search for from this_module import removed_name.",
        "prevention": "Maintain public exports in __init__.py. Don't remove imports that are re-exported. When refactoring imports, update all dependent modules in same PR. Use __all__ to explicitly define public API.",
        "severity": "high",
        "reference": "https://google.github.io/eng-practices/review/reviewer/looking-for.html"
    },
    {
        "id": "mandatory_field_addition",
        "pattern_name": "Adding Mandatory Fields",
        "category": "Breaking Changes",
        "source": "API Breaking Changes Best Practices",
        "description": "Adding required fields to data structures, making optional parameters mandatory, or adding non-null constraints breaks existing code that doesn't provide these fields.",
        "vulnerable_example": "API endpoint adds mandatory field: {name: str, email: str, phone: str (new, required)} breaks existing requests. Database column added with NOT NULL without default.",
        "detection": "Look for: new required function parameters without defaults, new required fields in request/response schemas, new database columns without defaults, new required configuration keys.",
        "prevention": "Make new fields optional with sensible defaults. Provide default values in function signatures. Use nullable database columns initially. Add validation warnings before making fields required in next version.",
        "severity": "high",
        "reference": "https://blog.treblle.com/5-ways-to-test-apis-breaking-changes/"
    },

    # Cross-File Dependencies
    {
        "id": "cross_file_dependency_break",
        "pattern_name": "Cross-File Dependency Break",
        "category": "Multi-File Changes",
        "source": "Google Engineering Practices",
        "description": "Changes in one file breaking functionality in another file due to shared dependencies, interfaces, or contracts. Especially common with imports, function calls, and data structures.",
        "vulnerable_example": "File A changes function signature. File B calls that function with old signature - breaks. File A removes helper class. File C imports that helper class - breaks.",
        "detection": "For multi-file PRs: 1) Check if modified functions are called from other files. 2) Search for imports of modified/deleted names. 3) Look for shared data structures being changed. 4) Run tests across all affected modules.",
        "prevention": "Keep changes backward compatible. Update all callers in same PR. Use deprecation warnings for gradual migration. Run full test suite. Use static analysis tools to find all references.",
        "severity": "high",
        "reference": "https://google.github.io/eng-practices/review/reviewer/looking-for.html"
    },

    # Design Issues
    {
        "id": "unnecessary_abstraction",
        "pattern_name": "Unnecessary Abstraction & Over-Engineering",
        "category": "Design",
        "source": "Google Engineering Practices",
        "description": "Developers solving anticipated future problems instead of current ones. Code that's more generic than necessary for present requirements adds complexity without benefit.",
        "vulnerable_example": "Adding plugin system when only one implementation exists. Creating elaborate factory patterns for simple object creation. Building configurable framework when specific solution would work.",
        "detection": "Look for: abstract base classes with only one implementation, extensive configuration systems with few options used, generic handlers with single use case, 'what if we need...' comments.",
        "prevention": "YAGNI principle: You Aren't Gonna Need It. Solve current problem with simplest solution. Add abstraction when second use case appears. Trust that future refactoring is possible.",
        "severity": "medium",
        "reference": "https://google.github.io/eng-practices/review/reviewer/looking-for.html#functionality"
    },
    {
        "id": "missing_concurrency_safety",
        "pattern_name": "Missing Concurrency Safety",
        "category": "Design",
        "source": "Google Engineering Practices",
        "description": "Parallel programming code without proper synchronization leads to race conditions, deadlocks, or data corruption. Shared mutable state accessed from multiple threads without locks.",
        "vulnerable_example": "Multiple threads modifying shared list without lock. Async functions sharing mutable global state. Database writes without transactions. Cache updates without atomic operations.",
        "detection": "Look for: shared mutable variables in multi-threaded code, async functions modifying shared state, missing locks around critical sections, non-atomic read-modify-write operations.",
        "prevention": "Use thread-safe data structures: queue.Queue, threading.Lock. Prefer immutable objects. Use copy-on-write. Apply locks around critical sections. Use atomic operations. Consider async/await for concurrency instead of threads.",
        "severity": "critical",
        "reference": "https://google.github.io/eng-practices/review/reviewer/looking-for.html#functionality"
    },
    {
        "id": "poor_integration_with_codebase",
        "pattern_name": "Poor Integration with Existing System",
        "category": "Design",
        "source": "Google Engineering Practices",
        "description": "New code doesn't integrate well with existing architecture. Inconsistent patterns, duplicated functionality, or mismatched abstraction levels indicate poor system integration.",
        "vulnerable_example": "Adding REST handler when codebase uses GraphQL. Implementing custom logging when framework provides it. Using different ORM than rest of codebase. Inconsistent error handling.",
        "detection": "Compare new code to existing patterns: Does it use same frameworks? Same error handling? Same data structures? Same architectural patterns? Look for reinventing existing functionality.",
        "prevention": "Review existing codebase before implementing. Use established patterns and libraries. Refactor existing code if it needs improvement rather than creating parallel implementation. Ask team about conventions.",
        "severity": "medium",
        "reference": "https://google.github.io/eng-practices/review/reviewer/looking-for.html#design"
    },
]

# Add documents to ChromaDB
documents = [
    p["pattern_name"] + ": " + p["description"] + " " +
    p["vulnerable_example"] + " Prevention: " + p["prevention"] +
    " Detection: " + p["detection"]
    for p in code_review_patterns
]

metadatas = [
    {k: v for k, v in p.items() if k not in ['pattern_name', 'description', 'vulnerable_example', 'prevention', 'detection']}
    for p in code_review_patterns
]

ids = [p["id"] for p in code_review_patterns]

code_review_collection.add(
    documents=documents,
    metadatas=metadatas,
    ids=ids
)

print(f"Added {len(code_review_patterns)} code review patterns to ChromaDB")
print(f"Collection now has {code_review_collection.count()} documents")

# Test retrieval
print("\n" + "="*60)
print("Testing retrieval with sample queries:")
print("="*60)

# Test 1: Deleted function
test_query_1 = "def trim_filename(): pass  # This function is being removed"
results_1 = code_review_collection.query(
    query_texts=[test_query_1],
    n_results=3
)

print(f"\nQuery 1: Deleted function scenario")
print(f"\nTop 3 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results_1['documents'][0], results_1['metadatas'][0]), 1):
    print(f"\n{i}. Pattern: {metadata['id']}")
    print(f"   Category: {metadata['category']}")
    print(f"   Severity: {metadata['severity']}")
    print(f"   Snippet: {doc[:120]}...")

# Test 2: Import removed
print("\n" + "="*60)
test_query_2 = "Removed: from matplotlib.cbook import _setattr_cm"
results_2 = code_review_collection.query(
    query_texts=[test_query_2],
    n_results=3
)

print(f"\nQuery 2: Import removal scenario")
print(f"\nTop 3 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results_2['documents'][0], results_2['metadatas'][0]), 1):
    print(f"\n{i}. Pattern: {metadata['id']}")
    print(f"   Category: {metadata['category']}")
    print(f"   Severity: {metadata['severity']}")
    print(f"   Snippet: {doc[:120]}...")

# Test 3: Multi-file change
print("\n" + "="*60)
test_query_3 = "Changes in file A affect functionality in file B through shared imports"
results_3 = code_review_collection.query(
    query_texts=[test_query_3],
    n_results=3
)

print(f"\nQuery 3: Cross-file dependency scenario")
print(f"\nTop 3 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results_3['documents'][0], results_3['metadatas'][0]), 1):
    print(f"\n{i}. Pattern: {metadata['id']}")
    print(f"   Category: {metadata['category']}")
    print(f"   Severity: {metadata['severity']}")
    print(f"   Snippet: {doc[:120]}...")

print("\n" + "="*60)
print("Code Review Knowledge Base built successfully!")
print("="*60)
