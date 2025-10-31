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

## 📄 process_input.py - Batch Hash Generation Script

The `process_input.py` script provides batch processing capabilities for generating NT hashes from user account and RID pairs stored in an input file. This script is designed for processing large numbers of accounts efficiently and generating standardized output in CSV format.

### 🎯 Script Purpose

The `process_input.py` script serves as a batch processor that:
- Reads user account and RID pairs from an input text file
- Generates NT hashes for each account using the `gen_all_hashes` function
- Outputs results in standardized CSV format
- Handles various account formats (username, domain\user, user@domain)
- Provides robust error handling and validation

### 🔧 Core Functionality

- **Batch Processing**: Processes multiple accounts from a single input file
- **NT Hash Generation**: Generates NT (NTLM) hashes for each account
- **Multiple Account Formats**: Supports different account naming conventions:
  - Simple username: `administrator`
  - Domain\user format: `DOMAIN\administrator`
  - User@domain format: `administrator@DOMAIN.COM`
- **CSV Output**: Generates structured output in comma-separated values format
- **Input Validation**: Skips invalid lines, empty lines, and malformed entries
- **Error Handling**: Provides detailed error messages and continues processing

### 📁 Input File Format Requirements

The input file must be a plain text file with the following specifications:

#### File Structure
- **Format**: Comma-separated values (CSV)
- **Encoding**: UTF-8
- **Line Endings**: Cross-platform compatible (\n or \r\n)

#### Row Format
Each valid row must contain exactly two comma-separated fields:
```
useraccount,rid
```

#### Field Specifications

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `useraccount` | String | Yes | User account name in various formats | `administrator`, `DOMAIN\user`, `user@DOMAIN.COM` |
| `rid` | Integer | Yes | User Relative Identifier (RID) | `1000`, `1001`, `14496` |

#### Input File Examples

**Basic Example:**
```txt
# Sample input file for hash generation
# Format: useraccount,rid
# Lines starting with # are treated as comments and will be skipped
# Empty lines will also be skipped

administrator,1000
testuser,1001
domain\user1,1002
user2@EXAMPLE.COM,1003
anotheruser,1004
```

**Advanced Example:**
```txt
# Active Directory user accounts with RIDs
# Domain accounts
DOMAIN\administrator,512
DOMAIN\krbtgt,502
DOMAIN\guest,501
DOMAIN\testuser,1001
DOMAIN\serviceacct,1102

# UPN format accounts
admin@DOMAIN.COM,512
service@DOMAIN.COM,1102
user@DOMAIN.COM,1003

# Simple username format (domain will be inferred or empty)
backup,1103
sqlservice,1104
webapp,1105
```

#### Input Validation Rules

1. **Empty Lines**: Automatically skipped
2. **Comment Lines**: Lines starting with `#` are treated as comments and skipped
3. **Field Count**: Lines with fewer than 2 fields are skipped with warning
4. **RID Validation**: Non-integer RID values cause line to be skipped with warning
5. **Account Format**: Any string format is accepted for useraccount field

### 📤 Output File Specifications

The output file is generated in CSV format with the following structure:

#### Output Format
```
useraccount,nt_hash
```

#### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `useraccount` | String | Original user account name from input (unchanged) |
| `nt_hash` | String | Generated NT hash in hexadecimal format |

#### Output File Example

```csv
administrator,"8846f7eaee8fb117ad06bdd830b7586c"
testuser,"25d55ad283aa400af464c76d713c07ad"
domain\user1,"e99a18c428cb38d5f260853678922e03"
user2@EXAMPLE.COM,"5d41402abc4b2a76b9719d911017c592"
anotheruser,"acbd18db4cc2f85cedef654fccc4a4d8"
```

#### Output Characteristics

- **Encoding**: UTF-8
- **Format**: CSV (comma-separated values)
- **Quoting**: User accounts containing special characters are automatically quoted
- **Hash Format**: NT hashes are returned as 32-character hexadecimal strings
- **Error Handling**: Failed generations return error messages instead of hashes

### 💻 Command-Line Usage

#### Basic Syntax
```bash
python3 process_input.py --password <password> [options]
```

#### Required Parameters

| Parameter | Short | Required | Description | Example |
|-----------|-------|----------|-------------|---------|
| `--password` | | Yes | Password to generate hashes for | `P@ssw0rd123` |

#### Optional Parameters

| Parameter | Short | Default | Description | Example |
|-----------|-------|---------|-------------|---------|
| `--input` | | `input.txt` | Path to input file | `users.txt` |
| `--output` | | `output.txt` | Path to output file | `hashes.csv` |

#### Usage Examples

**Basic Usage:**
```bash
python3 process_input.py --password "MySecretPassword123"
```

**Custom Input/Output Files:**
```bash
python3 process_input.py --password "P@ssw0rd!" --input accounts.txt --output results.csv
```

**Processing Large Files:**
```bash
python3 process_input.py --password "SecurePass123" --input large_userlist.txt --output nt_hashes.csv
```

**Command with Full Paths:**
```bash
python3 process_input.py --password "TempPass456" --input /path/to/users.txt --output /path/to/hashes.csv
```

#### Security Considerations

- **Password Display**: The password is shown as asterisks in the output for security
- **File Permissions**: Ensure input/output files have appropriate permissions
- **Environment**: Run in secure environment when processing sensitive data

### 🔧 Dependency Requirements

The `process_input.py` script requires the same dependencies as the main `gen_all_hashes.py` script:

#### Core Dependencies
- **Python**: 3.6 or higher
- **Impacket**: >= 0.9.22 (for cryptographic operations)

#### Installation
```bash
# Install required dependencies
pip install impacket>=0.9.22

# Or install from requirements.txt
pip install -r requirements.txt
```

#### Optional Dependencies
- **pycryptodome**: >= 3.15.0 (enhanced crypto operations)

### ⚠️ Error Handling Behavior

The script implements comprehensive error handling with the following behaviors:

#### Input File Errors
- **File Not Found**: Script exits with error message
- **Permission Issues**: Script exits with appropriate error
- **Encoding Issues**: UTF-8 encoding enforced with fallback handling

#### Processing Errors
- **Invalid RID Values**: Line skipped with warning, processing continues
- **Malformed Lines**: Lines with insufficient fields skipped with warning
- **Hash Generation Failures**: Error message returned instead of hash
- **Import Errors**: Script exits if `gen_all_hashes.py` cannot be imported

#### Output Errors
- **Write Permissions**: Script exits if output file cannot be written
- **Disk Space**: Script exits if disk space is insufficient
- **File Locks**: Script exits if output file is locked by another process

#### Error Message Format
```
Warning: Line 5 does not have at least two fields, skipping: invalid_line
Warning: Invalid RID on line 7: not_a_number, skipping: user,invalid_rid
Error: Could not import gen_all_hashes function: [details]
Error: Input file 'missing.txt' not found.
```

### 🔄 Step-by-Step Workflow

#### Step 1: Prepare Input File
1. Create a text file (e.g., `input.txt`)
2. Add user account and RID pairs in CSV format
3. Include comments starting with `#` for documentation
4. Ensure proper UTF-8 encoding

#### Step 2: Verify Dependencies
1. Check Python version: `python3 --version`
2. Verify impacket installation: `python3 -c "import impacket; print('Impacket OK')"`
3. Install missing dependencies if needed

#### Step 3: Execute Script
1. Run the script with required password parameter
2. Monitor progress output in console
3. Review any warnings or errors

#### Step 4: Review Output
1. Check generated output file
2. Verify hash format and completeness
3. Address any processing errors if present

#### Step 5: Process Results
1. Use output file for further analysis
2. Import into security tools or databases
3. Archive results as needed

### 📋 Complete Workflow Example

#### 1. Create Input File (`users.txt`)
```txt
# Active Directory user accounts for hash generation
DOMAIN\administrator,512
DOMAIN\testuser,1001
admin@DOMAIN.COM,512
backup,1103
sqlservice,1104
```

#### 2. Run Processing Script
```bash
python3 process_input.py --password "P@ssw0rd123!" --input users.txt --output nt_hashes.csv
```

#### 3. Script Execution Output
```
Processing input file: users.txt
Output will be written to: nt_hashes.csv
Using password: **********
--------------------------------------------------
Processing line 1: DOMAIN\administrator, 512
Processing line 2: DOMAIN\testuser, 1001
Processing line 3: admin@DOMAIN.COM, 512
Processing line 4: backup, 1103
Processing line 5: sqlservice, 1104
Processing complete. Results written to nt_hashes.csv
```

#### 4. Generated Output File (`nt_hashes.csv`)
```csv
DOMAIN\administrator,"8846f7eaee8fb117ad06bdd830b7586c"
DOMAIN\testuser,"25d55ad283aa400af464c76d713c07ad"
admin@DOMAIN.COM,"8846f7eaee8fb117ad06bdd830b7586c"
backup,"acbd18db4cc2f85cedef654fccc4a4d8"
sqlservice,"e99a18c428cb38d5f260853678922e03"
```

### 🔍 Troubleshooting

#### Common Issues and Solutions

**Issue: "Impacket is required" Error**
```bash
# Solution: Install impacket
pip install impacket
```

**Issue: "Could not import gen_all_hashes function"**
- Ensure `gen_all_hashes.py` is in the same directory
- Check file permissions
- Verify Python path includes current directory

**Issue: Permission Denied Errors**
- Check file read/write permissions
- Run with appropriate user privileges
- Verify output directory exists

**Issue: Invalid RID Values**
- Ensure RID values are integers only
- Check for extra spaces in input file
- Validate CSV format

**Issue: Empty Output File**
- Verify input file has valid content
- Check password parameter is correct
- Review script execution for error messages

### 🎯 Best Practices

1. **Security**: Use strong passwords and secure file handling
2. **Validation**: Always review input files before processing
3. **Backup**: Keep copies of input files and results
4. **Testing**: Test with small files before large batches
5. **Monitoring**: Monitor script execution for performance issues
6. **Documentation**: Document processing parameters and results

### 📊 Performance Considerations

- **Large Files**: Script processes files line by line for memory efficiency
- **Concurrent Processing**: Each account processed sequentially for accuracy
- **Output Generation**: Results written immediately to avoid memory buildup
- **Error Recovery**: Individual line errors don't stop entire processing

---

**Disclaimer:** This batch processing tool is intended for legitimate security testing, educational purposes, and authorized penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems or processing any user accounts.