import chromadb
from chromadb.config import Settings

# Initialize ChromaDB with persistent storage
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# Create collection for refactoring patterns
refactoring_collection = chroma_client.get_or_create_collection(
    name="refactoring_patterns",
    metadata={"description": "Refactoring patterns from Martin Fowler, Google AIP, and Refactoring Guru for detecting multi-file changes"}
)

# Refactoring patterns extracted from official sources:
# - Martin Fowler Refactoring Catalog: https://refactoring.com/catalog/
# - Refactoring Guru: https://refactoring.guru/
# - Google API Improvement Proposals (AIP-180): https://google.aip.dev/180
# - Kent Beck TDD: https://www.oreilly.com/library/view/test-driven-development/0321146530/

refactoring_patterns = [
    # Multi-File Changes
    {
        "id": "shotgun_surgery",
        "pattern_name": "Shotgun Surgery (Multi-File Coordinated Changes)",
        "category": "Multi-File Refactoring",
        "source": "Martin Fowler Refactoring, Refactoring Guru",
        "description": "Making a single logical change requires modifying many small parts scattered across multiple classes or files simultaneously. This indicates a single responsibility has been distributed among many locations, making changes expensive and error-prone.",
        "vulnerable_example": "Removing response_model_exclude_defaults parameter requires changes in applications.py (API layer), routing.py (request handling), encoders.py (serialization), and openapi/utils.py (schema generation). Each file needs 10+ line modifications to stay consistent.",
        "detection": "Look for: 1) Same parameter/function name changed in 3+ files in single PR. 2) Related functionality changes across layers (API → business logic → serialization). 3) Comment in one file saying 'also changed in X, Y, Z files'. 4) Multiple files importing/calling same removed function.",
        "prevention": "Use Move Method to consolidate scattered behavior into single class. Create new class if none exists to hold consolidated logic. After consolidation, use Inline Class to remove nearly-empty leftover classes. Apply change in coordinated manner: update all call sites in same commit.",
        "severity": "high",
        "reference": "https://refactoring.guru/smells/shotgun-surgery"
    },

    # Parameter Changes
    {
        "id": "change_function_declaration_breaking",
        "pattern_name": "Change Function Declaration Breaking Callers",
        "category": "Function Signature Changes",
        "source": "Martin Fowler Refactoring Catalog",
        "description": "Renaming functions, adding parameters, removing parameters, or changing parameter order breaks all existing callers. This refactoring (aliases: Rename Function, Add Parameter, Remove Parameter, Change Signature) must update every call site to avoid runtime errors.",
        "vulnerable_example": "def process(data, exclude_defaults=False, exclude_none=False) changed to def process(data, include_none=True). Old callers using exclude_none=True now fail. Parameter semantics inverted: exclude → include requires logic changes at every call site.",
        "detection": "For function signature changes: 1) List all call sites using grep/search. 2) Check if removed parameters had non-default values anywhere. 3) For parameter semantics inversion (exclude → include), verify inverse logic applied everywhere. 4) Search for kwargs usage that might pass old parameter names.",
        "prevention": "Before changing signature: search entire codebase for all callers. Keep old signature with deprecation warning, add new signature as separate function initially. Update all callers in same PR or use adapter pattern. For semantic inversions, create clear migration guide showing before/after for each usage.",
        "severity": "critical",
        "reference": "https://refactoring.com/catalog/changeFunctionDeclaration.html"
    },

    # Google AIP-180 Backward Compatibility
    {
        "id": "api_backward_compatibility_violation",
        "pattern_name": "API Backward Compatibility Violation",
        "category": "Breaking Changes",
        "source": "Google API Improvement Proposals (AIP-180)",
        "description": "Removing or renaming existing components (interfaces, methods, fields, parameters) from APIs breaks existing client code. Google's rule: components must not be removed in same major version. Renaming is semantically equivalent to 'remove and add' so old name must remain.",
        "vulnerable_example": "Removing response_model_exclude_defaults parameter from FastAPI route decorators breaks all existing code using it: @app.get('/', response_model_exclude_defaults=True) now raises TypeError: unexpected keyword argument. Wire-compatible changes like moving fields also break generated code imports.",
        "detection": "Check for: 1) Deleted parameters from public API functions. 2) Renamed parameters without keeping old name as alias. 3) Changed parameter types even if wire-compatible. 4) New required parameters without defaults. 5) Modified field formats (e.g., string length increases risk DB overflow). 6) Changed serialization of default values.",
        "prevention": "Don't remove components in same major version. For deprecation: add new component first, mark old as deprecated, support both for 24-36 months minimum. For renaming: keep old name as alias pointing to new name. Add required parameters as optional with defaults. Document all breaking changes clearly with migration paths.",
        "severity": "critical",
        "reference": "https://google.aip.dev/180"
    },

    # Parameter Object Pattern
    {
        "id": "introduce_parameter_object",
        "pattern_name": "Introduce Parameter Object (Parameter Group Refactoring)",
        "category": "Function Signature Changes",
        "source": "Martin Fowler Refactoring, Refactoring Guru",
        "description": "When methods contain repeating groups of parameters (data clumps), consolidating them into a parameter object simplifies signatures. However, removing individual parameters to introduce the object breaks all existing callers unless done carefully.",
        "vulnerable_example": "def configure(exclude_defaults=False, exclude_none=False, exclude_unset=False) refactored to def configure(exclusion_config: ExclusionConfig). All callers using individual kwargs now break: configure(exclude_none=True) → TypeError.",
        "detection": "Look for: 1) New class/object introduced as parameter. 2) Multiple related boolean/scalar parameters removed simultaneously. 3) Same parameter group appearing in 3+ method signatures. 4) PR description mentioning 'simplification' or 'consolidation' of parameters.",
        "prevention": "Use gradual migration: 1) Create parameter object class. 2) Add new object parameter alongside old parameters initially. 3) Internally, populate object from old params if object not provided. 4) Mark old parameters deprecated. 5) After migration period, remove old parameters. Keep both forms working during transition.",
        "severity": "high",
        "reference": "https://refactoring.guru/introduce-parameter-object"
    },

    # Flag Arguments / Boolean Parameters
    {
        "id": "flag_argument_semantic_inversion",
        "pattern_name": "Flag Argument Semantic Inversion",
        "category": "Function Signature Changes",
        "source": "Martin Fowler bliki",
        "description": "Changing boolean flag parameters, especially inverting their semantics (exclude → include, disable → enable), breaks code silently. Unlike removing parameters (loud failure), semantic inversions cause wrong behavior with no errors: exclude_none=True ≠ include_none=True.",
        "vulnerable_example": "def serialize(obj, exclude_none=False): changed to def serialize(obj, include_none=True). Caller using old default exclude_none=False (excludes None) now gets include_none=True (includes None) - opposite behavior, no error raised. Silent data corruption.",
        "detection": "Look for boolean parameter renames with semantic opposites: exclude→include, disable→enable, skip→process, ignore→handle. Check if default values inverted: exclude_none=False → include_none=True. Search for all call sites to verify logic inversion applied correctly.",
        "prevention": "Avoid inverting boolean semantics - breaking change requiring major version bump. If necessary: 1) Add new parameter alongside old. 2) Raise DeprecationWarning if old parameter used. 3) Document inverse relationship clearly. 4) Validate only one parameter provided. Better: use explicit methods instead of flags (Martin Fowler recommends regularBook()/premiumBook() over book(isPremium)).",
        "severity": "critical",
        "reference": "https://martinfowler.com/bliki/FlagArgument.html"
    },

    # Test Coverage
    {
        "id": "test_coverage_regression_during_refactoring",
        "pattern_name": "Test Coverage Regression During Refactoring",
        "category": "Testing",
        "source": "Kent Beck Test-Driven Development",
        "description": "Removing test files during refactoring without replacing them causes test coverage regression. TDD principle: refactoring must maintain green tests - 'everything that used to work still works'. Deleting tests for old behavior without adding tests for new behavior leaves code unvalidated.",
        "vulnerable_example": "tests/test_skip_defaults.py deleted entirely (testing exclude_defaults/exclude_none parameters). New include_none parameter added but no new tests written. Now serialization behavior untested: does include_none=False truly equal old exclude_none=True? Unknown - no tests verify equivalence.",
        "detection": "Look for: 1) Deleted test files without corresponding new test files. 2) Removed test functions without replacement tests for new behavior. 3) Refactored parameters/functions with no new test coverage. 4) Test file line count decreasing in PR. 5) Comments like 'removed obsolete tests' without adding new ones.",
        "prevention": "Follow TDD red-green-refactor cycle: 1) Before removing old tests, write new tests for new behavior (red). 2) Implement new behavior until tests pass (green). 3) Remove old tests only after confirming new tests cover equivalent functionality (refactor). Maintain or improve coverage during refactoring. Run full test suite after each change to verify 'everything that used to work still works'.",
        "severity": "high",
        "reference": "https://www.oreilly.com/library/view/test-driven-development/0321146530/"
    },

    # Cross-File Parameter Flow
    {
        "id": "cross_file_parameter_flow",
        "pattern_name": "Cross-File Parameter Flow Tracking",
        "category": "Multi-File Refactoring",
        "source": "Google Engineering Practices, Martin Fowler Refactoring",
        "description": "Parameters flowing through multiple layers (API → routing → business logic → serialization) must be tracked across all files. Removing a parameter at the API layer breaks if inner layers still expect it, or causes dead code if inner layers updated but API layer still passes it.",
        "vulnerable_example": "FastAPI API layer (applications.py) removes response_model_exclude_defaults → routing layer (routing.py) removes it from request handling → encoders layer (encoders.py) removes from serialization → openapi layer (utils.py) updates schema generation. Missing any layer causes TypeError or dead code. 4 files, 100+ lines changed.",
        "detection": "For parameter removal spanning multiple files: 1) Trace parameter from entry point (API) to exit point (serialization/storage). 2) List all layers parameter passes through. 3) Verify removal in ALL layers, not subset. 4) Check for partial updates: API layer changed but business logic unchanged indicates incomplete refactoring. 5) Look for **kwargs that might silently swallow removed parameters.",
        "prevention": "Map parameter flow across architecture layers before changing. Create checklist: API layer, validation layer, business logic, serialization, storage, schema generation. Use static analysis to find all references. Update all layers in single atomic commit. Add integration tests covering full parameter flow path. Consider using typed dataclasses to make parameter flow explicit and catch missing updates at compile time.",
        "severity": "critical",
        "reference": "https://google.github.io/eng-practices/review/reviewer/looking-for.html"
    },
]

# Add documents to ChromaDB
documents = [
    p["pattern_name"] + ": " + p["description"] + " " +
    p["vulnerable_example"] + " Prevention: " + p["prevention"] +
    " Detection: " + p["detection"]
    for p in refactoring_patterns
]

metadatas = [
    {k: v for k, v in p.items() if k not in ['pattern_name', 'description', 'vulnerable_example', 'prevention', 'detection']}
    for p in refactoring_patterns
]

ids = [p["id"] for p in refactoring_patterns]

refactoring_collection.add(
    documents=documents,
    metadatas=metadatas,
    ids=ids
)

print(f"Added {len(refactoring_patterns)} refactoring patterns to ChromaDB")
print(f"Collection now has {refactoring_collection.count()} documents")

# Test retrieval
print("\n" + "="*60)
print("Testing retrieval with fastapi/1 bug scenario:")
print("="*60)

# Test query mimicking fastapi/1 changes
test_query = """
Removed parameters: response_model_exclude_defaults, response_model_exclude_none
Changed parameters: exclude_none → include_none (semantic inversion)
Files changed: applications.py, routing.py, encoders.py, openapi/utils.py, test_skip_defaults.py
Tests deleted without replacement
"""

results = refactoring_collection.query(
    query_texts=[test_query],
    n_results=5
)

print(f"\nQuery: fastapi/1 multi-file parameter removal scenario")
print(f"\nTop 5 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results['documents'][0], results['metadatas'][0]), 1):
    print(f"\n{i}. Pattern: {metadata['id']}")
    print(f"   Category: {metadata['category']}")
    print(f"   Severity: {metadata['severity']}")
    print(f"   Source: {metadata['source']}")
    print(f"   Snippet: {doc[:150]}...")

print("\n" + "="*60)
print("Refactoring Patterns Knowledge Base built successfully!")
print("="*60)
