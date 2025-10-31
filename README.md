# Kerberos Key Generator

A Python script to generate Kerberos keys (AES256-CTS-HMAC-SHA1-96 and AES128-CTS-HMAC-SHA1-96) from a plaintext password, username, and realm.

## 📋 Project Overview

This tool addresses the need for generating Kerberos hashes for testing, security assessments, and Active Directory environments. It leverages the Impacket library to create proper Kerberos keys using the standard Active Directory salt format (uppercase realm + username).

### 🔧 Core Features

- Generate AES256-CTS-HMAC-SHA1-96 Kerberos hashes
- Generate AES128-CTS-HMAC-SHA1-96 Kerberos hashes
- Generate LM and NT hashes (NTLM)
- Generate optional DES-CBC-MD5 keys
- Create NTDS-style hash lines for Active Directory
- Uses standard Active Directory salt format
- Command-line interface with intuitive parameters
- Error handling and debugging information
- Compatible with various Impacket versions

## 🚀 Prerequisites

### Required Programming Language
- **Python 3.6+** (tested with Python 3.6 and later versions)

### Dependencies
- **Impacket** - Python library for network protocol handling
  ```bash
  pip install impacket
  ```

### System Specifications
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 512MB RAM
- **Storage**: Minimal disk space requirements

## 📦 Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/stoykovstoyk/kerberos-key-generator.git
cd kerberos-key-generator
```

### Step 2: Set Up Environment
```bash
# Create a virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install impacket
```

### Step 4: Make Script Executable (Linux/macOS)
```bash
chmod +x generate.py
```

## 💻 Usage

### Basic Command Syntax
```bash
python generate.py -u <username> -r <realm> -p <password>
```

### Parameter Explanations
| Parameter | Short | Required | Description | Example |
|-----------|-------|----------|-------------|---------|
| `--username` | `-u` | Yes | Username for Kerberos key generation | `administrator` |
| `--realm` | `-r` | Yes | Realm/domain name (uppercase recommended) | `DOMAIN.BG` |
| `--password` | `-p` | Yes | Plaintext password | `P@ssw0rd123` |

## 🚀 Advanced Usage - gen_all_hashes.py

The `gen_all_hashes.py` script provides extended functionality for generating comprehensive hash sets including Kerberos, NTLM, and NTDS-style outputs.

### Basic Command Syntax
```bash
python gen_all_hashes.py -u <username> -r <realm> -p <password>
```

### Advanced Command Syntax
```bash
python gen_all_hashes.py --account "domain.bg\\alabala" --realm DOMAIN.BG --password "YourPassword123!" --rid 14496 --include-des
```

```bash
python gen_all_hashes.py --account "domain.bg\\alabala" --realm DOMAIN.BG --password "YourPassword123!" --rid 14496 --include-des --empty-lm

```

```bash
python gen_all_hashes.py --username alabala --realm DOMAIN.BG --password "YourPassword123!"
```


### Parameter Explanations
| Parameter | Short | Required | Description | Example |
|-----------|-------|----------|-------------|---------|
| `--account` | | No | Account in domain\\user or user@domain format | `DOMAIN.BG\\administrator` |
| `--username` | `-u` | Yes | Username (used if --account not provided) | `administrator` |
| `--realm` | `-r` | No | Realm/domain name (can be inferred from --account) | `DOMAIN.BG` |
| `--password` | `-p` | Yes | Plaintext password | `P@ssw0rd123` |
| `--rid` | | No | User RID for NTDS line (default: 14496) | `14496` |
| `--include-des` | | No | Also generate DES-CBC-MD5 key | |

### Usage Examples

#### Example 1: Basic NTLM + Kerberos Generation
```bash
python gen_all_hashes.py -u administrator -r DOMAIN.BG -p "P@ssw0rd123"
```

**Expected Output:**
```
[*] Username (user only) : administrator
[*] Realm                : DOMAIN.BG
[*] Salt used for AES    : DOMAIN.BGadministrator
[*] Password             : P@ssw0rd123

aes256-cts-hmac-sha1-96   : 1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890
aes128-cts-hmac-sha1-96   : 1a2b3c4d5e6f7890abcdef1234567890abcdef1234

[+] LM/NT hashes:
lm (hex)     : aad3b435b51404eeaad3b435b51404ee
nt (hex)     : 8846f7eaee8fb117ad06bdd830b7586c

[+] NTDS-style hash line:
administrator:14496:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

#### Example 2: Full Account Format with RID
```bash
python gen_all_hashes.py --account "DOMAIN.BG\\administrator" --password "P@ssw0rd123" --rid 1000
```

**Expected Output:**
```
[*] Username (user only) : administrator
[*] Realm                : DOMAIN.BG
[*] Salt used for AES    : DOMAIN.BGadministrator
[*] Password             : P@ssw0rd123

aes256-cts-hmac-sha1-96   : 1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890
aes128-cts-hmac-sha1-96   : 1a2b3c4d5e6f7890abcdef1234567890abcdef1234

[+] LM/NT hashes:
lm (hex)     : aad3b435b51404eeaad3b435b51404ee
nt (hex)     : 8846f7eaee8fb117ad06bdd830b7586c

[+] NTDS-style hash line:
DOMAIN.BG\\administrator:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

#### Example 3: Including DES Key
```bash
python gen_all_hashes.py -u testuser -r EXAMPLE.COM -p "MySecurePassword!" --include-des
```

**Expected Output:**
```
[*] Username (user only) : testuser
[*] Realm                : EXAMPLE.COM
[*] Salt used for AES    : EXAMPLE.COMtestuser
[*] Password             : MySecurePassword!

aes256-cts-hmac-sha1-96   : f1e2d3c4b5a6978901234567890abcdef1234567890abcdef1234567890abcdef
aes128-cts-hmac-sha1-96   : f1e2d3c4b5a6978901234567890abcdef1234
des-cbc-md5               : 1a2b3c4d5e6f7890abcdef1234567890abcdef12

[+] LM/NT hashes:
lm (hex)     : aad3b435b51404eeaad3b435b51404ee
nt (hex)     : 25d55ad283aa400af464c76d713c07ad

[+] NTDS-style hash line:
testuser:14496:aad3b435b51404eeaad3b435b51404ee:25d55ad283aa400af464c76d713c07ad:::
```

### Key Differences Between Scripts

| Feature | `generate.py` | `gen_all_hashes.py` |
|---------|---------------|-------------------|
| **Primary Purpose** | Kerberos key generation | Comprehensive hash generation |
| **Hash Types** | AES256, AES128 Kerberos | AES256, AES128, DES (optional), LM, NT |
| **Output Format** | Simple hash list | Detailed output + NTDS-style line |
| **Account Input** | Username only | Domain\\user, user@domain, or username |
| **RID Support** | No | Yes (customizable) |
| **Use Case** | Basic Kerberos testing | Full hash extraction for AD environments |

### Usage Examples

#### Example 1: Basic Usage
```bash
python generate.py -u administrator -r DOMAIN.BG -p "P@ssw0rd123"
```

**Expected Output:**
```
[*] Username : administrator
[*] Realm    : DOMAIN.BG
[*] Salt     : DOMAIN.BGadministrator
[*] Password : P@ssw0rd123

aes256-cts-hmac-sha1-96   : 1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890
aes128-cts-hmac-sha1-96   : 1a2b3c4d5e6f7890abcdef1234567890abcdef1234
```

#### Example 2: Using Different Credentials
```bash
python generate.py -u testuser -r EXAMPLE.COM -p "MySecurePassword!2023"
```

**Expected Output:**
```
[*] Username : testuser
[*] Realm    : EXAMPLE.COM
[*] Salt     : EXAMPLE.COMtestuser
[*] Password : MySecurePassword!2023

aes256-cts-hmac-sha1-96   : f1e2d3c4b5a6978901234567890abcdef1234567890abcdef1234567890abcdef
aes128-cts-hmac-sha1-96   : f1e2d3c4b5a6978901234567890abcdef1234
```

## 🔍 Troubleshooting

### Common Errors and Solutions

#### Error: "Impacket is required. Install with: pip install impacket"
**Cause:** Impacket library is not installed
**Solution:**
```bash
pip install impacket
```

#### Error: "Enctype [name] not found in _enctype_table"
**Cause:** Impacket version compatibility issue
**Solution:**
1. Update Impacket to the latest version:
   ```bash
   pip install --upgrade impacket
   ```
2. Check available enctypes using the debug output
3. Consider using a different Impacket version if issues persist

#### Error: "No module named 'impacket'"
**Cause:** Python environment issue or incorrect pip installation
**Solution:**
1. Ensure you're using the correct Python environment
2. Reinstall Impacket:
   ```bash
   pip uninstall impacket
   pip install impacket
   ```

#### Error: Permission denied (Linux/macOS)
**Cause:** Script lacks execute permissions
**Solution:**
```bash
chmod +x generate.py
```

### Debug Mode
If you encounter issues with enctypes, the script provides debug information about available encryption types in the `_enctype_table`.

## 📁 Project Structure

```
kerberos-key-generator/
├── generate.py              # Basic Kerberos key generation script
├── gen_all_hashes.py        # Comprehensive hash generation script (Kerberos + NTLM + NTDS)
├── README.md               # Comprehensive documentation
├── requirements.txt        # Python dependencies (optional)
└── LICENSE                 # License file (if applicable)
```

### File Descriptions

| File | Description |
|------|-------------|
| `generate.py` | Basic script for generating Kerberos keys (AES256, AES128) with simple interface |
| `gen_all_hashes.py` | Advanced script for generating comprehensive hash sets including Kerberos, NTLM, and NTDS-style outputs |
| `README.md` | Comprehensive documentation with usage instructions and troubleshooting |
| `requirements.txt` | Optional file listing Python dependencies (can be created with `pip freeze > requirements.txt`) |

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### Reporting Issues
1. Check if the issue has already been reported in the Issuerm section
2. Create a new issue with:
   - Clear and descriptive title
   - Detailed description of the problem
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - System information (OS, Python version, Impacket version)
   - Error messages and stack traces (if applicable)

### Submitting Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Ensure the code follows the existing style
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Standards
- Follow PEP 8 Python coding standards
- Add appropriate comments and docstrings
- Test your changes thoroughly
- Update documentation if needed
- Ensure backward compatibility where possible

## 📄 License

This project is licensed under the MIT License LICENSE.


**Disclaimer:** This tool is intended for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems.