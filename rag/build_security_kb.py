import chromadb
from chromadb.config import Settings

# Initialize ChromaDB with persistent storage
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# Delete existing collection if it exists (to avoid duplicate ID errors)
try:
    chroma_client.delete_collection("security_patterns")
    print("Deleted existing security_patterns collection")
except:
    print("No existing collection to delete")

# Create fresh collection for security patterns
security_collection = chroma_client.create_collection(
    name="security_patterns",
    metadata={"description": "Security vulnerability patterns for code review - OWASP Top 10 2021"}
)

# Security patterns extracted from official OWASP documentation
# Source: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
# Source: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
# Source: https://owasp.org/Top10/A03_2021-Injection/
# Source: https://owasp.org/Top10/A04_2021-Insecure_Design/
# Source: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
# Source: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
# Source: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
# Source: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
# Source: https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
# Source: https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/

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
    },

    # From A02: Cryptographic Failures
    {
        "id": "weak_crypto_algorithm",
        "pattern_name": "Use of Weak Cryptographic Algorithms",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "cwe": "CWE-327",
        "description": "Use of broken or risky cryptographic algorithms like MD5, SHA1, DES, or weak key sizes. Data transmitted in clear text using protocols like HTTP, FTP, SMTP.",
        "vulnerable_example": "Using MD5 or SHA1 for password hashing, or DES for encryption. Transmitting sensitive data over HTTP instead of HTTPS.",
        "detection": "Look for usage of deprecated hash functions (MD5, SHA1) or weak encryption (DES, RC4). Check for http:// URLs handling sensitive data.",
        "prevention": "Use strong algorithms: SHA-256 or higher for hashing, AES-256 for encryption. Always use TLS 1.2+ for data in transit. Use bcrypt/scrypt for password hashing.",
        "severity": "high"
    },
    {
        "id": "missing_encryption",
        "pattern_name": "Missing Encryption of Sensitive Data",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "cwe": "CWE-311",
        "description": "Sensitive data is transmitted or stored without encryption. Includes clear text transmission of passwords, credit cards, health records, PII, or other sensitive information.",
        "vulnerable_example": "Storing passwords in plain text, transmitting authentication credentials over HTTP, storing credit card numbers unencrypted.",
        "detection": "Check if sensitive data (passwords, tokens, PII) is stored or transmitted without encryption. Look for missing TLS/SSL, unencrypted database fields.",
        "prevention": "Encrypt all sensitive data at rest and in transit. Use TLS for transmission. Encrypt database fields containing sensitive data. Never store passwords in plain text.",
        "severity": "critical"
    },
    {
        "id": "improper_cert_validation",
        "pattern_name": "Improper Certificate Validation",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "cwe": "CWE-295",
        "description": "Disabling or improperly implementing SSL/TLS certificate validation allows man-in-the-middle attacks. Setting verify=False or accepting all certificates bypasses security.",
        "vulnerable_example": "requests.get(url, verify=False) or accepting self-signed certificates without validation. Disabling hostname verification.",
        "detection": "Look for verify=False, SSL_VERIFY_NONE, or custom cert validators that always return true. Check for disabled hostname verification.",
        "prevention": "Always validate certificates. Use verify=True (default). For internal CAs, provide proper CA bundle. Never disable cert validation in production.",
        "severity": "high"
    },
    {
        "id": "hardcoded_credentials",
        "pattern_name": "Hardcoded Cryptographic Keys or Passwords",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "cwe": "CWE-798",
        "description": "Cryptographic keys, passwords, or API tokens hardcoded in source code. Exposed in version control and accessible to anyone with code access.",
        "vulnerable_example": "API_KEY = 'sk_live_abc123xyz', password = 'admin123', or hardcoded encryption keys in source code.",
        "detection": "Look for hardcoded strings that look like passwords, API keys, tokens, or encryption keys. Check for patterns like password=, api_key=, token=.",
        "prevention": "Use environment variables or secret management systems. Never commit credentials to version control. Use .env files in .gitignore.",
        "severity": "critical"
    },
    {
        "id": "weak_key_generation",
        "pattern_name": "Weak Cryptographic Key Generation",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "cwe": "CWE-326",
        "description": "Using insufficient key sizes or weak random number generation for cryptographic operations. Keys that are too short or predictable can be brute-forced.",
        "vulnerable_example": "Using RSA keys < 2048 bits, random.random() for cryptographic purposes, or weak session token generation.",
        "detection": "Check key sizes (RSA < 2048, AES < 128). Look for random() instead of secrets module. Check for predictable token generation.",
        "prevention": "Use recommended key sizes: RSA ≥ 2048 bits, AES ≥ 128 bits. Use secrets module or os.urandom() for cryptographic randomness.",
        "severity": "high"
    },
    {
        "id": "sensitive_data_exposure",
        "pattern_name": "Sensitive Information Exposure",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "cwe": "CWE-200",
        "description": "Exposure of sensitive information through error messages, logs, URLs, cookies, headers, or responses. Includes leaking credentials, session tokens, or internal implementation details.",
        "vulnerable_example": "Authorization headers sent in cross-origin redirects, session cookies exposed to third parties, credentials in URLs or logs.",
        "detection": "Check if sensitive headers (Authorization, Cookie) are stripped on redirects. Look for sensitive data in error messages or logs.",
        "prevention": "Strip sensitive headers on cross-origin redirects. Mark cookies as Secure and HttpOnly. Sanitize logs. Use POST for credentials, not GET.",
        "severity": "high"
    },

    # From A04: Insecure Design
    {
        "id": "missing_rate_limiting",
        "pattern_name": "Missing Rate Limiting or DoS Protection",
        "owasp_category": "A04:2021-Insecure Design",
        "cwe": "CWE-400",
        "description": "Uncontrolled resource consumption from missing rate limits, allowing denial of service. Processing extremely large inputs, recursive operations, or computationally expensive operations without limits.",
        "vulnerable_example": "Accepting arbitrarily large strings for processing (e.g., recursive regex, string operations), no rate limiting on API endpoints.",
        "detection": "Look for recursive operations, large input processing, or expensive computations without size/complexity limits. Check for missing rate limiting.",
        "prevention": "Implement rate limiting on API endpoints. Validate and limit input sizes. Set timeouts for operations. Use iterative instead of recursive algorithms where possible.",
        "severity": "medium"
    },
    {
        "id": "improper_input_validation",
        "pattern_name": "Improper Input Validation",
        "owasp_category": "A04:2021-Insecure Design",
        "cwe": "CWE-20",
        "description": "Insufficient or missing validation of user input allows malformed data to cause errors, bypass security checks, or enable other attacks. Trusting client-side validation.",
        "vulnerable_example": "Accepting file uploads without extension/type validation, skipping size checks, or allowing bypass of validation when uploading multiple files.",
        "detection": "Check if user input is validated for type, format, length, and range. Look for client-side-only validation or validation that can be bypassed.",
        "prevention": "Validate all user input on server-side. Use allowlists over denylists. Validate file types, sizes, and content. Don't trust client-side validation.",
        "severity": "high"
    },
    {
        "id": "null_pointer_dereference",
        "pattern_name": "NULL Pointer Dereference",
        "owasp_category": "A04:2021-Insecure Design",
        "cwe": "CWE-476",
        "description": "Dereferencing a NULL or uninitialized pointer causing crashes or denial of service. Accessing object properties or methods without checking if object exists.",
        "vulnerable_example": "Accessing p7.d.sign.cert without checking if p7.d.sign is NULL, leading to segfault.",
        "detection": "Look for pointer/object access without NULL checks, especially in C/C++ bindings or low-level code. Check for missing existence validation.",
        "prevention": "Always validate pointers/objects are not NULL before dereferencing. Check return values from functions that can return NULL. Use safe navigation operators where available.",
        "severity": "medium"
    },

    # From A05: Security Misconfiguration
    {
        "id": "default_credentials",
        "pattern_name": "Default or Weak Credentials",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cwe": "CWE-1188",
        "description": "Using default passwords, default admin accounts, or allowing weak passwords. Unchanged default credentials from installation.",
        "vulnerable_example": "Default admin/admin credentials, or allowing passwords like 'password123'. No password complexity requirements.",
        "detection": "Check for default usernames (admin, root) with weak passwords. Look for missing password strength validation.",
        "prevention": "Force password change on first login. Implement strong password policies. Disable or remove default accounts.",
        "severity": "high"
    },
    {
        "id": "unnecessary_features",
        "pattern_name": "Unnecessary Features Enabled",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cwe": "CWE-1188",
        "description": "Unnecessary features, services, ports, accounts, or privileges enabled. Debug mode enabled in production.",
        "vulnerable_example": "DEBUG=True in production Django settings, unnecessary admin interfaces exposed, development endpoints in production.",
        "detection": "Check for debug mode enabled, unused services running, development/test endpoints accessible in production.",
        "prevention": "Disable debug mode in production. Remove unused features and endpoints. Follow principle of least privilege. Use minimal platform configurations.",
        "severity": "medium"
    },
    {
        "id": "verbose_errors",
        "pattern_name": "Verbose Error Messages",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cwe": "CWE-209",
        "description": "Detailed error messages or stack traces exposed to users, revealing sensitive information about the application's internals, database structure, or file paths.",
        "vulnerable_example": "Showing full stack traces, database error messages, or file paths in production error pages.",
        "detection": "Check if production error handling shows detailed technical information to end users. Look for exposed stack traces.",
        "prevention": "Use generic error messages for users. Log detailed errors server-side only. Disable debug mode in production.",
        "severity": "low"
    },
    {
        "id": "missing_security_headers",
        "pattern_name": "Missing Security Headers",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cwe": "CWE-1021",
        "description": "Missing or misconfigured HTTP security headers like CSP, HSTS, X-Frame-Options, X-Content-Type-Options. Makes application vulnerable to various attacks.",
        "vulnerable_example": "No Content-Security-Policy header allowing XSS, missing HSTS allowing protocol downgrade attacks, missing X-Frame-Options allowing clickjacking.",
        "detection": "Check response headers for missing security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection.",
        "prevention": "Implement security headers: CSP to prevent XSS, HSTS for HTTPS enforcement, X-Frame-Options for clickjacking protection.",
        "severity": "medium"
    },

    # From A06: Vulnerable and Outdated Components
    {
        "id": "outdated_dependencies",
        "pattern_name": "Outdated or Vulnerable Dependencies",
        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-1104",
        "description": "Using libraries, frameworks, or components with known vulnerabilities. Not updating dependencies regularly or not tracking versions. Running unsupported versions.",
        "vulnerable_example": "Using Django 2.x with known CVEs, running EOL Python 2.7, using libraries listed in security advisories without patches.",
        "detection": "Check dependency versions against CVE databases. Look for old version numbers in requirements.txt, package.json. Scan for known vulnerable packages.",
        "prevention": "Regularly update dependencies. Monitor security advisories. Use automated dependency scanning tools (Dependabot, Snyk). Remove unused dependencies.",
        "severity": "high"
    },
    {
        "id": "missing_dependency_scanning",
        "pattern_name": "Missing Vulnerability Scanning",
        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-1395",
        "description": "Not scanning for vulnerabilities in dependencies. No continuous monitoring for new CVEs. Missing SCA (Software Composition Analysis) in CI/CD.",
        "vulnerable_example": "No automated scanning in build pipeline, manual dependency management without vulnerability checks, no awareness of CVEs in used libraries.",
        "detection": "Check if project uses tools like npm audit, pip-audit, Snyk, or OWASP Dependency-Check. Look for vulnerability scanning in CI/CD.",
        "prevention": "Integrate vulnerability scanning in CI/CD. Use tools like npm audit, pip-audit, Snyk, GitHub Dependabot. Subscribe to security advisories.",
        "severity": "medium"
    },
    {
        "id": "unused_dependencies",
        "pattern_name": "Unused or Unnecessary Dependencies",
        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-1104",
        "description": "Including unnecessary dependencies increases attack surface. Unused features or libraries that aren't needed. Transitive dependencies with vulnerabilities.",
        "vulnerable_example": "Including full jQuery for one function, unused Flask extensions in requirements.txt, development dependencies in production builds.",
        "detection": "Audit dependencies for actual usage. Check if all imported libraries are necessary. Look for overlapping functionality from multiple libraries.",
        "prevention": "Remove unused dependencies. Use tree-shaking and minification. Separate dev and production dependencies. Audit transitive dependencies.",
        "severity": "low"
    },
    {
        "id": "no_version_pinning",
        "pattern_name": "Unpinned Dependency Versions",
        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-1126",
        "description": "Not pinning dependency versions allows uncontrolled updates. Using wildcard versions (*, >=) without upper bounds can introduce breaking changes or vulnerabilities.",
        "vulnerable_example": "requirements.txt with flask>=2.0 instead of flask==2.0.3, package.json with ^lodash without lock file, allowing any new version.",
        "detection": "Check for wildcard or unbounded version specifiers. Look for missing lock files (package-lock.json, poetry.lock, Pipfile.lock).",
        "prevention": "Pin exact versions or use lock files. Review updates before applying. Use version ranges cautiously with upper bounds.",
        "severity": "medium"
    },

    # From A07: Identification and Authentication Failures
    {
        "id": "session_fixation",
        "pattern_name": "Session Fixation",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cwe": "CWE-384",
        "description": "Application does not generate new session identifier upon authentication, allowing attacker to fix a user's session ID. Session not properly invalidated on logout.",
        "vulnerable_example": "Reusing same session ID before and after login. Session cookies not invalidated on logout or timeout.",
        "detection": "Check if session ID changes after login. Verify session invalidation on logout. Test if old session tokens remain valid after logout.",
        "prevention": "Generate new session ID on authentication. Invalidate sessions on logout. Implement session timeouts. Rotate session IDs periodically.",
        "severity": "high"
    },
    {
        "id": "weak_password_recovery",
        "pattern_name": "Weak Password Recovery",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cwe": "CWE-640",
        "description": "Weak password recovery mechanisms using knowledge-based answers, insecure email links, or predictable tokens.",
        "vulnerable_example": "Password reset tokens that don't expire, predictable tokens, or reset links without proper validation.",
        "detection": "Test if password reset tokens are predictable, don't expire, or can be reused. Check for timing attacks on token validation.",
        "prevention": "Use cryptographically strong random tokens. Implement token expiration. Rate-limit password reset requests. Use one-time tokens.",
        "severity": "high"
    },
    {
        "id": "credential_stuffing",
        "pattern_name": "Credential Stuffing Protection Missing",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cwe": "CWE-307",
        "description": "Missing protection against automated credential stuffing attacks. No rate limiting or CAPTCHA on authentication endpoints.",
        "vulnerable_example": "Login endpoint without rate limiting allowing thousands of authentication attempts from same IP.",
        "detection": "Check for rate limiting on login/authentication endpoints. Look for missing account lockout or CAPTCHA after failed attempts.",
        "prevention": "Implement rate limiting on authentication. Use multi-factor authentication. Implement account lockout after repeated failures. Use CAPTCHA for suspicious activity.",
        "severity": "medium"
    },
    {
        "id": "missing_mfa",
        "pattern_name": "Missing Multi-Factor Authentication",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cwe": "CWE-308",
        "description": "Sensitive operations or privileged accounts without multi-factor authentication. Single factor (password only) for critical functions.",
        "vulnerable_example": "Admin accounts or financial transactions protected only by passwords without 2FA/MFA.",
        "detection": "Check if privileged accounts or sensitive operations lack MFA requirement. Test if critical functions can be accessed with password only.",
        "prevention": "Implement MFA for all privileged accounts. Require additional verification for sensitive operations. Support TOTP, SMS, or hardware tokens.",
        "severity": "medium"
    },

    # From A08: Software and Data Integrity Failures
    {
        "id": "insecure_deserialization",
        "pattern_name": "Insecure Deserialization",
        "owasp_category": "A08:2021-Software and Data Integrity Failures",
        "cwe": "CWE-502",
        "description": "Deserializing untrusted data without validation enables remote code execution. Using pickle, yaml.load, or eval on untrusted input.",
        "vulnerable_example": "pickle.loads(user_data), yaml.load(untrusted_yaml), or yaml.full_load() on untrusted YAML files allowing arbitrary code execution.",
        "detection": "Look for pickle.loads(), yaml.load(), yaml.full_load() on user-controlled data. Check for deserialization of untrusted JSON/XML into objects.",
        "prevention": "Avoid deserialization of untrusted data. Use yaml.safe_load() instead of yaml.load(). Use JSON instead of pickle when possible. Implement integrity checks.",
        "severity": "critical"
    },
    {
        "id": "code_injection_eval",
        "pattern_name": "Code Injection via eval/exec",
        "owasp_category": "A08:2021-Software and Data Integrity Failures",
        "cwe": "CWE-94",
        "description": "Using eval(), exec(), or similar functions with user-controlled input enables arbitrary code execution. Dynamic code evaluation is extremely dangerous.",
        "vulnerable_example": "eval(user_input), exec(user_string), or using compile() with untrusted code. JonesFaithfulTransformation.from_transformation_str() using eval() on user input.",
        "detection": "Look for eval(), exec(), compile(), __import__() with user-controlled input. Check for dynamic code generation from user data.",
        "prevention": "Never use eval/exec with user input. Use safe alternatives like ast.literal_eval() for data structures. Validate and sanitize all dynamic inputs.",
        "severity": "critical"
    },
    {
        "id": "unsigned_code",
        "pattern_name": "Unsigned or Unverified Code",
        "owasp_category": "A08:2021-Software and Data Integrity Failures",
        "cwe": "CWE-345",
        "description": "Code or packages installed without integrity verification. Missing signature validation for updates or dependencies. Auto-updates without verification.",
        "vulnerable_example": "Installing packages without checksum verification, downloading and executing code over HTTP without signature checks.",
        "detection": "Check if software updates verify signatures. Look for package installations without integrity checks (missing --verify-hashes).",
        "prevention": "Verify digital signatures for all updates. Use package lock files. Enable supply chain security features. Use HTTPS for package downloads.",
        "severity": "high"
    },
    {
        "id": "ci_cd_security",
        "pattern_name": "Insecure CI/CD Pipeline",
        "owasp_category": "A08:2021-Software and Data Integrity Failures",
        "cwe": "CWE-1395",
        "description": "Insufficient security in CI/CD pipeline allowing unauthorized code changes. Secrets in pipeline configurations. Lack of separation between development and production.",
        "vulnerable_example": "Secrets hardcoded in CI/CD configs, insufficient access controls on pipeline, automatic deployments without review.",
        "detection": "Check if CI/CD pipelines have proper access controls, secret management, and audit logging. Look for hardcoded credentials in pipeline configs.",
        "prevention": "Use secret management for CI/CD credentials. Implement least privilege access. Require code review before deployment. Use separate environments.",
        "severity": "high"
    },

    # From A09: Security Logging and Monitoring Failures
    {
        "id": "insufficient_logging",
        "pattern_name": "Insufficient Security Logging",
        "owasp_category": "A09:2021-Security Logging and Monitoring Failures",
        "cwe": "CWE-778",
        "description": "Missing or insufficient logging of security events. Failed logins, access control failures, or input validation errors not logged. Makes incident response and forensics difficult.",
        "vulnerable_example": "No logging of authentication failures, privilege escalation attempts, or suspicious activities. Missing audit trails.",
        "detection": "Check if security-relevant events are logged: authentication, authorization failures, input validation errors, suspicious patterns.",
        "prevention": "Log all authentication events, access control failures, and input validation failures. Include timestamp, user, action, and outcome in logs.",
        "severity": "medium"
    },
    {
        "id": "log_injection",
        "pattern_name": "Log Injection",
        "owasp_category": "A09:2021-Security Logging and Monitoring Failures",
        "cwe": "CWE-117",
        "description": "Logging unsanitized user input allows log injection attacks. Attackers can inject fake log entries or manipulate log files.",
        "vulnerable_example": "logger.info(f'User {user_input} logged in') allows injection of newlines and fake log entries.",
        "detection": "Check if user input is sanitized before logging. Look for string formatting or concatenation with user data in log statements.",
        "prevention": "Sanitize user input before logging. Encode special characters (newlines, tabs). Use structured logging (JSON) instead of string concatenation.",
        "severity": "low"
    },
    {
        "id": "missing_monitoring",
        "pattern_name": "Missing Security Monitoring",
        "owasp_category": "A09:2021-Security Logging and Monitoring Failures",
        "cwe": "CWE-223",
        "description": "No active monitoring or alerting for suspicious activities. Logs not reviewed or analyzed. Missing real-time detection of attacks.",
        "vulnerable_example": "No alerting on repeated failed logins, unusual access patterns, or security violations. No SIEM integration.",
        "detection": "Check if logs are actively monitored. Look for missing alerting mechanisms or security event correlation.",
        "prevention": "Implement real-time monitoring and alerting. Use SIEM for log aggregation. Set up alerts for suspicious patterns. Review logs regularly.",
        "severity": "low"
    },

    # From A10: Server-Side Request Forgery (SSRF)
    {
        "id": "ssrf",
        "pattern_name": "Server-Side Request Forgery (SSRF)",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "cwe": "CWE-918",
        "description": "Application fetches remote resources based on user-supplied URLs without validation. Allows attackers to access internal systems, cloud metadata, or bypass firewalls.",
        "vulnerable_example": "requests.get(user_provided_url) without URL validation, allowing access to internal IPs (169.254.169.254, localhost) or internal services.",
        "detection": "Look for HTTP requests with user-controlled URLs. Check if URLs are validated against allowlist. Test if internal IPs/hostnames are blocked.",
        "prevention": "Validate URLs against allowlist of domains. Block requests to internal IPs, localhost, and cloud metadata endpoints. Use separate network segments.",
        "severity": "high"
    },
    {
        "id": "url_redirect_open",
        "pattern_name": "Open Redirect via SSRF",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "cwe": "CWE-601",
        "description": "Unvalidated redirects using user-supplied URLs enable phishing attacks or SSRF. Application redirects to arbitrary URLs without validation.",
        "vulnerable_example": "redirect(request.GET['url']) without validation allows redirects to malicious sites or internal resources.",
        "detection": "Look for redirect functions using user input without validation. Check if URL schemes and domains are restricted.",
        "prevention": "Validate redirect URLs against allowlist. Use indirect references (IDs) instead of full URLs. Strip or validate URL schemes.",
        "severity": "medium"
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
print("Testing retrieval with sample queries:")
print("="*60)

# Test query 1: SQL injection
test_query_1 = "SELECT * FROM users WHERE username='" + "user_input" + "'"
results_1 = security_collection.query(query_texts=[test_query_1], n_results=2)

print(f"\nQuery 1: {test_query_1}")
print(f"Top 2 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results_1['documents'][0], results_1['metadatas'][0]), 1):
    print(f"\n{i}. {metadata['id']} ({metadata['owasp_category']})")
    print(f"   Severity: {metadata['severity']}")

# Test query 2: Insecure deserialization
test_query_2 = "yaml.full_load(user_yaml_data)"
results_2 = security_collection.query(query_texts=[test_query_2], n_results=2)

print(f"\n\nQuery 2: {test_query_2}")
print(f"Top 2 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results_2['documents'][0], results_2['metadatas'][0]), 1):
    print(f"\n{i}. {metadata['id']} ({metadata['owasp_category']})")
    print(f"   Severity: {metadata['severity']}")

# Test query 3: Certificate validation
test_query_3 = "requests.get(url, verify=False)"
results_3 = security_collection.query(query_texts=[test_query_3], n_results=2)

print(f"\n\nQuery 3: {test_query_3}")
print(f"Top 2 matching patterns:")
for i, (doc, metadata) in enumerate(zip(results_3['documents'][0], results_3['metadatas'][0]), 1):
    print(f"\n{i}. {metadata['id']} ({metadata['owasp_category']})")
    print(f"   Severity: {metadata['severity']}")