"""CWE -> flaw class -> analyst phrasings (written for this benchmark)."""
from __future__ import annotations

FLAW_CLASSES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # class: (CWE IDs, phrasings)
    "xss": (("CWE-79", "CWE-80"), ("XSS", "cross-site scripting", "stored or reflected XSS")),
    "sqli": (("CWE-89",), ("SQLi", "SQL injection")),
    "os_command": (("CWE-78",), ("OS command injection", "shell command injection")),
    "command": (("CWE-77",), ("command injection",)),
    "code_injection": (("CWE-94", "CWE-95"), ("code injection", "RCE via code injection")),
    "path_traversal": (("CWE-22", "CWE-23", "CWE-35", "CWE-36"), ("path traversal", "directory traversal", "dot-dot-slash file read")),
    "oob_write": (("CWE-787",), ("out-of-bounds write", "OOB write")),
    "oob_read": (("CWE-125",), ("out-of-bounds read", "OOB read")),
    "buffer_overflow": (("CWE-119", "CWE-120", "CWE-121", "CWE-122"), ("buffer overflow", "memory corruption bug")),
    "use_after_free": (("CWE-416",), ("use-after-free", "UAF")),
    "double_free": (("CWE-415",), ("double free",)),
    "null_deref": (("CWE-476",), ("NULL pointer dereference", "null deref crash")),
    "integer_overflow": (("CWE-190", "CWE-191"), ("integer overflow", "integer wraparound")),
    "deserialization": (("CWE-502",), ("insecure deserialization", "unsafe deserialisation")),
    "csrf": (("CWE-352",), ("CSRF", "cross-site request forgery")),
    "ssrf": (("CWE-918",), ("SSRF", "server-side request forgery")),
    "xxe": (("CWE-611", "CWE-776"), ("XXE", "XML external entity injection")),
    "file_upload": (("CWE-434",), ("unrestricted file upload", "arbitrary file upload")),
    "auth_bypass": (("CWE-287", "CWE-288", "CWE-290", "CWE-306", "CWE-1390"), ("authentication bypass", "missing authentication")),
    "authorization": (("CWE-862", "CWE-863", "CWE-285", "CWE-284", "CWE-639"), ("broken access control", "missing authorization check", "IDOR")),
    "info_disclosure": (("CWE-200", "CWE-209", "CWE-532", "CWE-497", "CWE-538"), ("information disclosure", "sensitive data leak")),
    "dos": (("CWE-400", "CWE-770", "CWE-835", "CWE-674", "CWE-1333"), ("denial of service", "DoS", "resource exhaustion")),
    "open_redirect": (("CWE-601",), ("open redirect",)),
    "privilege": (("CWE-269", "CWE-250", "CWE-266", "CWE-274"), ("privilege escalation", "improper privilege management")),
    "hardcoded_credentials": (("CWE-798", "CWE-259", "CWE-321"), ("hard-coded credentials", "hardcoded password")),
    "race": (("CWE-362", "CWE-367"), ("race condition", "TOCTOU race")),
    "prototype_pollution": (("CWE-1321",), ("prototype pollution",)),
    "format_string": (("CWE-134",), ("format string bug",)),
    "weak_crypto": (("CWE-327", "CWE-326", "CWE-328"), ("weak cryptography", "broken crypto algorithm")),
    "certificate_validation": (("CWE-295", "CWE-297"), ("TLS certificate validation flaw", "improper certificate validation")),
    "template_injection": (("CWE-1336",), ("server-side template injection", "SSTI")),
    "type_confusion": (("CWE-843",), ("type confusion",)),
    "clickjacking": (("CWE-1021",), ("clickjacking",)),
    "session_fixation": (("CWE-384",), ("session fixation",)),
    "search_path": (("CWE-427", "CWE-426"), ("DLL hijacking", "uncontrolled search path")),
    "link_following": (("CWE-59",), ("symlink following", "link following attack")),
    "uninitialized": (("CWE-908", "CWE-457"), ("use of uninitialized memory",)),
    "csv_injection": (("CWE-1236",), ("CSV formula injection",)),
    "ldap_injection": (("CWE-90",), ("LDAP injection",)),
    "xpath_injection": (("CWE-643",), ("XPath injection",)),
    "crlf": (("CWE-93", "CWE-113"), ("CRLF injection", "HTTP response splitting")),
}

CWE_TO_CLASS = {cwe: cls for cls, (cwes, _) in FLAW_CLASSES.items() for cwe in cwes}


def classes_of(cwes: list[str]) -> list[str]:
    return sorted({CWE_TO_CLASS[c] for c in cwes if c in CWE_TO_CLASS})


def phrases(cls: str) -> tuple[str, ...]:
    return FLAW_CLASSES[cls][1]
