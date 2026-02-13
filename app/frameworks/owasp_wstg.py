"""OWASP Web Security Testing Guide v4.2 methodology data."""

WSTG_CATEGORIES = [
    {
        "id": "WSTG-INFO",
        "name": "Information Gathering",
        "description": "Identify application entry points, technologies, and architecture to understand the attack surface.",
        "test_cases": [
            {"id": "WSTG-INFO-01", "name": "Conduct Search Engine Discovery Reconnaissance", "tools": ["theharvester", "dig", "whois"], "description": "Use search engines and public sources to discover information about the target."},
            {"id": "WSTG-INFO-02", "name": "Fingerprint Web Server", "tools": ["whatweb", "nmap", "curl"], "description": "Determine the type and version of web server software."},
            {"id": "WSTG-INFO-03", "name": "Review Webserver Metafiles for Information Leakage", "tools": ["curl", "dirb"], "description": "Check robots.txt, sitemap.xml, and other metafiles for sensitive paths."},
            {"id": "WSTG-INFO-04", "name": "Enumerate Applications on Webserver", "tools": ["nmap", "dirb", "gobuster"], "description": "Discover applications hosted on the web server."},
            {"id": "WSTG-INFO-05", "name": "Review Webpage Content for Information Leakage", "tools": ["curl", "whatweb"], "description": "Analyze page source for comments, metadata, and information leaks."},
            {"id": "WSTG-INFO-06", "name": "Identify Application Entry Points", "tools": ["burpsuite", "zaproxy"], "description": "Map all application entry points including forms, APIs, and parameters."},
            {"id": "WSTG-INFO-07", "name": "Map Execution Paths Through Application", "tools": ["burpsuite", "zaproxy"], "description": "Understand application logic flow and execution paths."},
            {"id": "WSTG-INFO-08", "name": "Fingerprint Web Application Framework", "tools": ["whatweb", "wappalyzer"], "description": "Identify the web application framework in use."},
            {"id": "WSTG-INFO-09", "name": "Fingerprint Web Application", "tools": ["whatweb", "nikto"], "description": "Identify the specific web application and version."},
            {"id": "WSTG-INFO-10", "name": "Map Application Architecture", "tools": ["nmap", "whatweb"], "description": "Understand the application architecture including load balancers, firewalls, etc."},
        ]
    },
    {
        "id": "WSTG-CONF",
        "name": "Configuration and Deployment Management Testing",
        "description": "Test the infrastructure and deployment configuration for security weaknesses.",
        "test_cases": [
            {"id": "WSTG-CONF-01", "name": "Test Network Infrastructure Configuration", "tools": ["nmap", "masscan"], "description": "Examine network infrastructure for misconfigurations."},
            {"id": "WSTG-CONF-02", "name": "Test Application Platform Configuration", "tools": ["nikto", "whatweb"], "description": "Test web server and application platform configuration."},
            {"id": "WSTG-CONF-03", "name": "Test File Extensions Handling", "tools": ["dirb", "gobuster", "ffuf"], "description": "Test how the server handles different file extensions."},
            {"id": "WSTG-CONF-04", "name": "Review Old Backup and Unreferenced Files", "tools": ["dirb", "gobuster", "ffuf"], "description": "Search for backup files and unreferenced content."},
            {"id": "WSTG-CONF-05", "name": "Enumerate Infrastructure and Application Admin Interfaces", "tools": ["dirb", "nikto", "gobuster"], "description": "Discover administrative interfaces."},
            {"id": "WSTG-CONF-06", "name": "Test HTTP Methods", "tools": ["curl", "nmap"], "description": "Test which HTTP methods are allowed and their security implications."},
            {"id": "WSTG-CONF-07", "name": "Test HTTP Strict Transport Security", "tools": ["sslscan", "curl"], "description": "Verify HSTS header is properly configured."},
            {"id": "WSTG-CONF-08", "name": "Test RIA Cross Domain Policy", "tools": ["curl"], "description": "Check cross-domain policy files for overly permissive access."},
            {"id": "WSTG-CONF-09", "name": "Test File Permission", "tools": ["nmap"], "description": "Verify file permissions are appropriately restrictive."},
            {"id": "WSTG-CONF-10", "name": "Test for Subdomain Takeover", "tools": ["subfinder", "amass", "dig"], "description": "Check for subdomain takeover vulnerabilities."},
            {"id": "WSTG-CONF-11", "name": "Test Cloud Storage", "tools": ["curl"], "description": "Check for misconfigured cloud storage buckets."},
        ]
    },
    {
        "id": "WSTG-IDNT",
        "name": "Identity Management Testing",
        "description": "Test identity management functions including registration, provisioning, and role definitions.",
        "test_cases": [
            {"id": "WSTG-IDNT-01", "name": "Test Role Definitions", "tools": ["burpsuite", "zaproxy"], "description": "Verify proper role definitions and access control."},
            {"id": "WSTG-IDNT-02", "name": "Test User Registration Process", "tools": ["burpsuite", "curl"], "description": "Test the user registration process for weaknesses."},
            {"id": "WSTG-IDNT-03", "name": "Test Account Provisioning Process", "tools": ["burpsuite"], "description": "Test administrative account provisioning processes."},
            {"id": "WSTG-IDNT-04", "name": "Test Account Enumeration and Guessable User Account", "tools": ["hydra", "burpsuite"], "description": "Test for user account enumeration vulnerabilities."},
            {"id": "WSTG-IDNT-05", "name": "Test Weak or Unenforced Username Policy", "tools": ["burpsuite", "curl"], "description": "Test username policies for weaknesses."},
        ]
    },
    {
        "id": "WSTG-ATHN",
        "name": "Authentication Testing",
        "description": "Test authentication mechanisms for weaknesses that could allow unauthorized access.",
        "test_cases": [
            {"id": "WSTG-ATHN-01", "name": "Test for Credentials Transported over Encrypted Channel", "tools": ["sslscan", "testssl", "curl"], "description": "Verify credentials are transmitted over HTTPS."},
            {"id": "WSTG-ATHN-02", "name": "Test for Default Credentials", "tools": ["hydra", "nikto"], "description": "Test for default or common credentials."},
            {"id": "WSTG-ATHN-03", "name": "Test for Weak Lock Out Mechanism", "tools": ["hydra", "burpsuite"], "description": "Test account lockout mechanism effectiveness."},
            {"id": "WSTG-ATHN-04", "name": "Test for Bypassing Authentication Schema", "tools": ["burpsuite", "sqlmap"], "description": "Test for authentication bypass vulnerabilities."},
            {"id": "WSTG-ATHN-05", "name": "Test for Vulnerable Remember Password", "tools": ["burpsuite", "curl"], "description": "Test remember password functionality for security issues."},
            {"id": "WSTG-ATHN-06", "name": "Test for Browser Cache Weaknesses", "tools": ["curl", "burpsuite"], "description": "Check for sensitive data in browser cache."},
            {"id": "WSTG-ATHN-07", "name": "Test for Weak Password Policy", "tools": ["burpsuite", "curl"], "description": "Verify password policy enforcement."},
            {"id": "WSTG-ATHN-08", "name": "Test for Weak Security Question/Answer", "tools": ["burpsuite"], "description": "Test security questions for weaknesses."},
            {"id": "WSTG-ATHN-09", "name": "Test for Weak Password Change/Reset", "tools": ["burpsuite", "curl"], "description": "Test password change and reset mechanisms."},
            {"id": "WSTG-ATHN-10", "name": "Test for Weaker Authentication in Alternative Channel", "tools": ["burpsuite", "curl"], "description": "Test alternative authentication channels for weaknesses."},
        ]
    },
    {
        "id": "WSTG-ATHZ",
        "name": "Authorization Testing",
        "description": "Test that authorization controls are properly implemented and cannot be bypassed.",
        "test_cases": [
            {"id": "WSTG-ATHZ-01", "name": "Test Directory Traversal File Include", "tools": ["burpsuite", "curl", "dirb"], "description": "Test for directory traversal and file inclusion vulnerabilities."},
            {"id": "WSTG-ATHZ-02", "name": "Test for Bypassing Authorization Schema", "tools": ["burpsuite", "curl"], "description": "Test for authorization bypass vulnerabilities."},
            {"id": "WSTG-ATHZ-03", "name": "Test for Privilege Escalation", "tools": ["burpsuite", "curl"], "description": "Test for vertical and horizontal privilege escalation."},
            {"id": "WSTG-ATHZ-04", "name": "Test for Insecure Direct Object References", "tools": ["burpsuite", "curl"], "description": "Test for IDOR vulnerabilities."},
        ]
    },
    {
        "id": "WSTG-SESS",
        "name": "Session Management Testing",
        "description": "Test session management mechanisms for weaknesses that could compromise user sessions.",
        "test_cases": [
            {"id": "WSTG-SESS-01", "name": "Test for Session Management Schema", "tools": ["burpsuite", "curl"], "description": "Analyze the session management implementation."},
            {"id": "WSTG-SESS-02", "name": "Test for Cookies Attributes", "tools": ["curl", "burpsuite"], "description": "Verify cookie security attributes (Secure, HttpOnly, SameSite)."},
            {"id": "WSTG-SESS-03", "name": "Test for Session Fixation", "tools": ["burpsuite", "curl"], "description": "Test for session fixation vulnerabilities."},
            {"id": "WSTG-SESS-04", "name": "Test for Exposed Session Variables", "tools": ["burpsuite", "curl"], "description": "Check for session variables exposed in URLs or logs."},
            {"id": "WSTG-SESS-05", "name": "Test for Cross Site Request Forgery", "tools": ["burpsuite", "xsser"], "description": "Test for CSRF vulnerabilities."},
            {"id": "WSTG-SESS-06", "name": "Test for Logout Functionality", "tools": ["burpsuite", "curl"], "description": "Verify proper session termination on logout."},
            {"id": "WSTG-SESS-07", "name": "Test Session Timeout", "tools": ["burpsuite", "curl"], "description": "Test session timeout enforcement."},
            {"id": "WSTG-SESS-08", "name": "Test for Session Puzzling", "tools": ["burpsuite"], "description": "Test for session variable overloading vulnerabilities."},
            {"id": "WSTG-SESS-09", "name": "Test for Session Hijacking", "tools": ["burpsuite", "wireshark"], "description": "Test for session hijacking vulnerabilities."},
        ]
    },
    {
        "id": "WSTG-INPV",
        "name": "Input Validation Testing",
        "description": "Test that all input is properly validated, filtered, and sanitized.",
        "test_cases": [
            {"id": "WSTG-INPV-01", "name": "Test for Reflected Cross Site Scripting", "tools": ["xsser", "burpsuite", "zaproxy"], "description": "Test for reflected XSS vulnerabilities."},
            {"id": "WSTG-INPV-02", "name": "Test for Stored Cross Site Scripting", "tools": ["xsser", "burpsuite"], "description": "Test for stored XSS vulnerabilities."},
            {"id": "WSTG-INPV-03", "name": "Test for HTTP Verb Tampering", "tools": ["curl", "burpsuite"], "description": "Test for HTTP verb tampering vulnerabilities."},
            {"id": "WSTG-INPV-04", "name": "Test for HTTP Parameter Pollution", "tools": ["burpsuite", "curl"], "description": "Test for HTTP parameter pollution vulnerabilities."},
            {"id": "WSTG-INPV-05", "name": "Test for SQL Injection", "tools": ["sqlmap", "burpsuite"], "description": "Test for SQL injection vulnerabilities."},
            {"id": "WSTG-INPV-06", "name": "Test for LDAP Injection", "tools": ["burpsuite", "curl"], "description": "Test for LDAP injection vulnerabilities."},
            {"id": "WSTG-INPV-07", "name": "Test for XML Injection", "tools": ["burpsuite", "curl"], "description": "Test for XML injection including XXE."},
            {"id": "WSTG-INPV-08", "name": "Test for SSI Injection", "tools": ["burpsuite", "curl"], "description": "Test for Server-Side Include injection."},
            {"id": "WSTG-INPV-09", "name": "Test for XPath Injection", "tools": ["burpsuite", "curl"], "description": "Test for XPath injection vulnerabilities."},
            {"id": "WSTG-INPV-10", "name": "Test for IMAP SMTP Injection", "tools": ["burpsuite"], "description": "Test for mail injection vulnerabilities."},
            {"id": "WSTG-INPV-11", "name": "Test for Code Injection", "tools": ["commix", "burpsuite"], "description": "Test for server-side code injection."},
            {"id": "WSTG-INPV-12", "name": "Test for Command Injection", "tools": ["commix", "burpsuite"], "description": "Test for OS command injection vulnerabilities."},
            {"id": "WSTG-INPV-13", "name": "Test for Format String Injection", "tools": ["burpsuite"], "description": "Test for format string injection vulnerabilities."},
            {"id": "WSTG-INPV-14", "name": "Test for Incubated Vulnerability", "tools": ["burpsuite"], "description": "Test for incubated/time-delayed vulnerabilities."},
            {"id": "WSTG-INPV-15", "name": "Test for HTTP Splitting Smuggling", "tools": ["burpsuite", "curl"], "description": "Test for HTTP request splitting/smuggling."},
            {"id": "WSTG-INPV-16", "name": "Test for HTTP Incoming Requests", "tools": ["burpsuite"], "description": "Test for HTTP incoming request vulnerabilities."},
            {"id": "WSTG-INPV-17", "name": "Test for Host Header Injection", "tools": ["curl", "burpsuite"], "description": "Test for host header injection vulnerabilities."},
            {"id": "WSTG-INPV-18", "name": "Test for Server-Side Template Injection", "tools": ["burpsuite", "curl"], "description": "Test for SSTI vulnerabilities."},
            {"id": "WSTG-INPV-19", "name": "Test for Server-Side Request Forgery", "tools": ["burpsuite", "curl"], "description": "Test for SSRF vulnerabilities."},
        ]
    },
    {
        "id": "WSTG-ERRH",
        "name": "Error Handling Testing",
        "description": "Test that errors are handled properly without leaking sensitive information.",
        "test_cases": [
            {"id": "WSTG-ERRH-01", "name": "Test for Improper Error Handling", "tools": ["nikto", "burpsuite", "curl"], "description": "Test for information leakage through error messages."},
            {"id": "WSTG-ERRH-02", "name": "Test for Stack Traces", "tools": ["curl", "burpsuite"], "description": "Test for stack trace disclosure in error responses."},
        ]
    },
    {
        "id": "WSTG-CRYP",
        "name": "Cryptography Testing",
        "description": "Test cryptographic implementations for weaknesses.",
        "test_cases": [
            {"id": "WSTG-CRYP-01", "name": "Test for Weak Transport Layer Security", "tools": ["sslscan", "testssl", "nmap"], "description": "Test TLS configuration for weak ciphers and protocols."},
            {"id": "WSTG-CRYP-02", "name": "Test for Padding Oracle", "tools": ["burpsuite"], "description": "Test for padding oracle vulnerabilities."},
            {"id": "WSTG-CRYP-03", "name": "Test for Sensitive Information Sent via Unencrypted Channels", "tools": ["wireshark", "tcpdump", "curl"], "description": "Verify sensitive data is transmitted encrypted."},
            {"id": "WSTG-CRYP-04", "name": "Test for Weak Encryption", "tools": ["sslscan", "testssl"], "description": "Test for weak cryptographic algorithms."},
        ]
    },
    {
        "id": "WSTG-BUSL",
        "name": "Business Logic Testing",
        "description": "Test business logic for flaws that could be exploited.",
        "test_cases": [
            {"id": "WSTG-BUSL-01", "name": "Test Business Logic Data Validation", "tools": ["burpsuite", "curl"], "description": "Test business logic data validation."},
            {"id": "WSTG-BUSL-02", "name": "Test Ability to Forge Requests", "tools": ["burpsuite", "curl"], "description": "Test for request forgery in business logic."},
            {"id": "WSTG-BUSL-03", "name": "Test Integrity Checks", "tools": ["burpsuite"], "description": "Test data integrity verification mechanisms."},
            {"id": "WSTG-BUSL-04", "name": "Test for Process Timing", "tools": ["burpsuite", "curl"], "description": "Test for race conditions in business logic."},
            {"id": "WSTG-BUSL-05", "name": "Test Number of Times a Function Can Be Used", "tools": ["burpsuite"], "description": "Test usage limits and rate limiting."},
            {"id": "WSTG-BUSL-06", "name": "Test for Circumvention of Work Flows", "tools": ["burpsuite"], "description": "Test for workflow bypass vulnerabilities."},
            {"id": "WSTG-BUSL-07", "name": "Test Defenses Against Application Misuse", "tools": ["burpsuite", "hydra"], "description": "Test application abuse prevention controls."},
            {"id": "WSTG-BUSL-08", "name": "Test Upload of Unexpected File Types", "tools": ["burpsuite", "curl"], "description": "Test file upload for unrestricted types."},
            {"id": "WSTG-BUSL-09", "name": "Test Upload of Malicious Files", "tools": ["burpsuite", "curl"], "description": "Test file upload for malicious file handling."},
        ]
    },
    {
        "id": "WSTG-CLNT",
        "name": "Client-Side Testing",
        "description": "Test client-side code and interactions for vulnerabilities.",
        "test_cases": [
            {"id": "WSTG-CLNT-01", "name": "Test for DOM-Based Cross Site Scripting", "tools": ["burpsuite", "zaproxy"], "description": "Test for DOM-based XSS vulnerabilities."},
            {"id": "WSTG-CLNT-02", "name": "Test for JavaScript Execution", "tools": ["burpsuite"], "description": "Test for JavaScript execution vulnerabilities."},
            {"id": "WSTG-CLNT-03", "name": "Test for HTML Injection", "tools": ["burpsuite", "curl"], "description": "Test for HTML injection vulnerabilities."},
            {"id": "WSTG-CLNT-04", "name": "Test for Client-Side URL Redirect", "tools": ["burpsuite", "curl"], "description": "Test for open redirect vulnerabilities."},
            {"id": "WSTG-CLNT-05", "name": "Test for CSS Injection", "tools": ["burpsuite"], "description": "Test for CSS injection vulnerabilities."},
            {"id": "WSTG-CLNT-06", "name": "Test for Client-Side Resource Manipulation", "tools": ["burpsuite"], "description": "Test for client-side resource manipulation."},
            {"id": "WSTG-CLNT-07", "name": "Test Cross Origin Resource Sharing", "tools": ["curl", "burpsuite"], "description": "Test CORS configuration for security issues."},
            {"id": "WSTG-CLNT-08", "name": "Test for Cross Site Flashing", "tools": ["burpsuite"], "description": "Test for Flash-based cross-site vulnerabilities."},
            {"id": "WSTG-CLNT-09", "name": "Test for Clickjacking", "tools": ["curl", "burpsuite"], "description": "Test for clickjacking vulnerabilities."},
            {"id": "WSTG-CLNT-10", "name": "Test WebSockets", "tools": ["burpsuite"], "description": "Test WebSocket implementations for security issues."},
            {"id": "WSTG-CLNT-11", "name": "Test Web Messaging", "tools": ["burpsuite"], "description": "Test postMessage API for security issues."},
            {"id": "WSTG-CLNT-12", "name": "Test Browser Storage", "tools": ["burpsuite"], "description": "Test local/session storage for sensitive data exposure."},
            {"id": "WSTG-CLNT-13", "name": "Test for Cross Site Script Inclusion", "tools": ["burpsuite"], "description": "Test for XSSI vulnerabilities."},
        ]
    },
]


def get_all_categories():
    return [{"id": c["id"], "name": c["name"], "description": c["description"],
             "test_count": len(c["test_cases"])} for c in WSTG_CATEGORIES]


def get_category(cat_id: str):
    for c in WSTG_CATEGORIES:
        if c["id"] == cat_id:
            return c
    return None


def get_test_case(test_id: str):
    for c in WSTG_CATEGORIES:
        for tc in c["test_cases"]:
            if tc["id"] == test_id:
                return {**tc, "category": c["id"], "category_name": c["name"]}
    return None


def get_all_test_cases():
    cases = []
    for c in WSTG_CATEGORIES:
        for tc in c["test_cases"]:
            cases.append({**tc, "category": c["id"], "category_name": c["name"]})
    return cases
