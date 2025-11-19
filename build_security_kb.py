import chromadb
from chromadb.config import Settings

# Initialize ChromaDB with persistent storage
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# Create collection for security patterns
security_collection = chroma_client.get_or_create_collection(
    name="security_patterns",
    metadata={"description": "Security vulnerability patterns for code review"}
)

# Security patterns extracted from official OWASP documentation
# Source: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
# Source: https://owasp.org/Top10/A03_2021-Injection/

security_patterns = [
    # From A01: Broken Access Control
    {
        "id": "path_traversal",
        "pattern_name": "Path Traversal",
        "owasp_category": "A01:2021-Broken Access Control",
        "cwe": "CWE-22",
        "description": "Bypassing access control checks by modifying the URL (parameter tampering or force browsing), internal application state, or the HTML page. Improper limitation of a pathname to a restricted directory.",
        "vulnerable_example": "Attacker modifies 'acct' parameter in URL: https://example.com/app/accountInfo?acct=notmyacct to access another user's account without verification.",
        "detection": "Look for URL parameters or file paths constructed directly from user input without validation. Check for '../' sequences or absolute path manipulation.",
        "prevention": "Validate and sanitize all user inputs. Use allowlists for permitted file paths. Implement proper access control checks before serving resources.",
        "severity": "high"
    },
    {
        "id": "insecure_direct_object_ref",
        "pattern_name": "Insecure Direct Object References",
        "owasp_category": "A01:2021-Broken Access Control",
        "cwe": "CWE-639",
        "description": "Permitting viewing or editing someone else's account by providing its unique identifier without proper authorization checks.",
        "vulnerable_example": "Application uses unverified data in SQL call accessing account information. Attacker modifies browser parameter to access any user account.",
        "detection": "Check if object references (IDs, filenames) from user input are used without verifying user authorization to access that object.",
        "prevention": "Implement access control checks that verify the user owns or has permission to access the requested resource. Use indirect reference maps.",
        "severity": "high"
    },
    {
        "id": "missing_api_access_controls",
        "pattern_name": "Missing Access Controls on API",
        "owasp_category": "A01:2021-Broken Access Control",
        "cwe": "CWE-285",
        "description": "Accessing API with missing access controls for POST, PUT and DELETE methods.",
        "vulnerable_example": "API allows POST/PUT/DELETE requests without proper authorization checks, enabling unauthorized data modification.",
        "detection": "Review API endpoints to ensure all methods (especially POST, PUT, DELETE) have proper authorization checks, not just GET.",
        "prevention": "Implement access control mechanisms for all API methods. Deny by default except for public resources. Use server-side enforcement.",
        "severity": "high"
    },
    {
        "id": "elevation_of_privilege",
        "pattern_name": "Elevation of Privilege",
        "owasp_category": "A01:2021-Broken Access Control",
        "cwe": "CWE-269",
        "description": "Acting as a user without being logged in or acting as an admin when logged in as a user. Violation of principle of least privilege.",
        "vulnerable_example": "Attacker force browses to admin page: https://example.com/app/admin_getappInfo without proper authentication/authorization checks.",
        "detection": "Test if unauthenticated users can access authenticated pages, or if regular users can access privileged/admin pages.",
        "prevention": "Implement proper authentication and authorization checks. Deny by default. Validate user roles and permissions on server-side for every privileged operation.",
        "severity": "critical"
    },
    {
        "id": "jwt_token_manipulation",
        "pattern_name": "JWT/Token Manipulation",
        "owasp_category": "A01:2021-Broken Access Control",
        "cwe": "CWE-345",
        "description": "Metadata manipulation such as replaying or tampering with a JSON Web Token (JWT) access control token, or a cookie or hidden field manipulated to elevate privileges or abusing JWT invalidation.",
        "vulnerable_example": "JWT tokens not properly validated, allowing attackers to modify claims or replay expired tokens.",
        "detection": "Check if JWT signature is validated, if tokens expire properly, if tokens are invalidated on logout.",
        "prevention": "Stateful session identifiers should be invalidated on server after logout. Stateless JWT tokens should be short-lived. Follow OAuth standards for token revocation.",
        "severity": "high"
    },
    {
        "id": "cors_misconfiguration",
        "pattern_name": "CORS Misconfiguration",
        "owasp_category": "A01:2021-Broken Access Control",
        "cwe": "CWE-346",
        "description": "CORS misconfiguration allows API access from unauthorized/untrusted origins.",
        "vulnerable_example": "API configured with overly permissive CORS headers (Access-Control-Allow-Origin: *) allowing any origin to access sensitive endpoints.",
        "detection": "Review CORS configuration. Check for wildcard origins or reflection of arbitrary Origin headers in responses.",
        "prevention": "Minimize CORS usage. Use specific allowed origins rather than wildcards. Validate Origin header against allowlist.",
        "severity": "medium"
    },
    {
        "id": "force_browsing",
        "pattern_name": "Force Browsing",
        "owasp_category": "A01:2021-Broken Access Control",
        "cwe": "CWE-425",
        "description": "Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user.",
        "vulnerable_example": "Direct URL access to admin or authenticated pages without proper checks: accessing /admin or /user/profile without being logged in.",
        "detection": "Attempt to access protected URLs without authentication or with insufficient privileges.",
        "prevention": "Implement server-side access control checks on all protected resources. Deny access by default.",
        "severity": "high"
    },
    
    # From A03: Injection
    {
        "id": "sql_injection",
        "pattern_name": "SQL Injection",
        "owasp_category": "A03:2021-Injection",
        "cwe": "CWE-89",
        "description": "Improper neutralization of special elements used in an SQL command. User-supplied data is not validated, filtered, or sanitized and is directly used or concatenated into SQL queries.",
        "vulnerable_example": "String query = \"SELECT * FROM accounts WHERE custID='\" + request.getParameter(\"id\") + \"'\"; - Attacker sends: ' UNION SELECT SLEEP(10);-- to modify query behavior.",
        "detection": "Look for string concatenation or string formatting (f-strings, %) used to build SQL queries with user input. Check for queries constructed without parameterization.",
        "prevention": "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL. Example: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
        "severity": "critical"
    },
    {
        "id": "command_injection",
        "pattern_name": "OS Command Injection",
        "owasp_category": "A03:2021-Injection",
        "cwe": "CWE-78",
        "description": "Improper neutralization of special elements used in an OS command. Hostile data is directly used or concatenated into system commands.",
        "vulnerable_example": "Executing os.system() or subprocess with unsanitized user input allows attackers to inject shell commands.",
        "detection": "Look for os.system(), subprocess.call(), eval(), exec() or similar functions that execute system commands with user-controlled input.",
        "prevention": "Avoid calling OS commands with user input. If necessary, use subprocess with argument lists (not shell=True), validate input against allowlist, escape special characters.",
        "severity": "critical"
    },
    {
        "id": "xss",
        "pattern_name": "Cross-Site Scripting (XSS)",
        "owasp_category": "A03:2021-Injection",
        "cwe": "CWE-79",
        "description": "Improper neutralization of input during web page generation. User-supplied data is rendered in HTML without proper encoding, allowing script injection.",
        "vulnerable_example": "User input directly embedded in HTML: <div> + user_input + </div> allows attacker to inject <script> tags.",
        "detection": "Look for user input being directly written to HTML responses without encoding or sanitization.",
        "prevention": "HTML-encode all user-supplied data before rendering in HTML context. Use templating engines with auto-escaping. Apply Content Security Policy headers.",
        "severity": "high"
    },
    {
        "id": "ldap_injection",
        "pattern_name": "LDAP Injection",
        "owasp_category": "A03:2021-Injection",
        "cwe": "CWE-90",
        "description": "Improper neutralization of special elements used in an LDAP query. User input concatenated into LDAP queries without sanitization.",
        "vulnerable_example": "LDAP queries built with string concatenation of user input allow attackers to modify query logic.",
        "detection": "Look for LDAP query construction using string concatenation with user input.",
        "prevention": "Use parameterized LDAP queries if available. Validate and sanitize user input. Escape LDAP special characters.",
        "severity": "high"
    },
    {
        "id": "nosql_injection",
        "pattern_name": "NoSQL Injection",
        "owasp_category": "A03:2021-Injection",
        "cwe": "CWE-943",
        "description": "Improper neutralization of special elements in NoSQL database queries. User input can manipulate query structure in MongoDB, CouchDB, etc.",
        "vulnerable_example": "MongoDB queries accepting user objects directly: db.collection.find({username: user_input}) can be exploited with operators like $ne, $gt.",
        "detection": "Look for NoSQL queries where user input is used directly without validation, especially in MongoDB operator contexts.",
        "prevention": "Validate user input types. Sanitize data before query construction. Use query builders that prevent operator injection.",
        "severity": "high"
    },
    {
        "id": "orm_injection",
        "pattern_name": "ORM Injection",
        "owasp_category": "A03:2021-Injection",
        "cwe": "CWE-564",
        "description": "Hostile data is used within object-relational mapping (ORM) search parameters to extract additional sensitive records. Even ORMs can be vulnerable if queries are built unsafely.",
        "vulnerable_example": "Query HQLQuery = session.createQuery(\"FROM accounts WHERE custID='\" + request.getParameter(\"id\") + \"'\"); - Using string concatenation in HQL/ORM queries.",
        "detection": "Look for ORM query methods that accept raw strings built from user input (createQuery, raw SQL in ORM).",
        "prevention": "Use ORM parameterized queries. Avoid raw SQL in ORM. Example: session.query(User).filter(User.id == user_id) instead of raw strings.",
        "severity": "high"
    }
]

# Add documents to ChromaDB
documents = [p["pattern_name"] + ": " + p["description"] + " " + p["vulnerable_example"] + " Prevention: " + p["prevention"] + " Detection: " + p["detection"] for p in security_patterns]
metadatas = [{k: v for k, v in p.items() if k not in ['pattern_name', 'description', 'vulnerable_example', 'prevention', 'detection']} for p in security_patterns]
ids = [p["id"] for p in security_patterns]

security_collection.add(
    documents=documents,
    metadatas=metadatas,
    ids=ids
)

print(f"Added {len(security_patterns)} security patterns to ChromaDB")
print(f"Collection now has {security_collection.count()} documents")

# Test retrieval
print("\n" + "="*60)
print("Testing retrieval with sample query:")
print("="*60)

test_query = "SELECT * FROM users WHERE username='" + "user_input" + "'"
results = security_collection.query(
    query_texts=[test_query],
    n_results=3
)

print(f"\nQuery: {test_query}")
print(f"\nTop 3 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results['documents'][0], results['metadatas'][0]), 1):
    print(f"\n{i}. Pattern: {metadata['id']}")
    print(f"   Category: {metadata['owasp_category']}")
    print(f"   Severity: {metadata['severity']}")
    print(f"   Snippet: {doc[:150]}...")