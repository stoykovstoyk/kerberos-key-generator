# Kerberos Key Generator

A Python script to generate Kerberos keys (AES256-CTS-HMAC-SHA1-96 and AES128-CTS-HMAC-SHA1-96) from a plaintext password, username, and realm.

## 📋 Project Overview

This tool addresses the need for generating Kerberos hashes for testing, security assessments, and Active Directory environments. It leverages the Impacket library to create proper Kerberos keys using the standard Active Directory salt format (uppercase realm + username).

### 🔧 Core Features

- Generate AES256-CTS-HMAC-SHA1-96 Kerberos hashes
- Generate AES128-CTS-HMAC-SHA1-96 Kerberos hashes  
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
├── generate.py              # Main script for Kerberos key generation
├── README.md               # Comprehensive documentation
├── requirements.txt        # Python dependencies (optional)
└── LICENSE                 # License file (if applicable)
```

### File Descriptions

| File | Description |
|------|-------------|
| `generate.py` | Main script containing the Kerberos key generation logic and command-line interface |
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