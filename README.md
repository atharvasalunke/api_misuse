# Crypto API Misuse Checker
This tool statically analyzes Python code that uses the **PyCryptodome** library and detects potential cryptographic API misuses such as insecure modes, missing IVs, and hardcoded keys/salts. It includes both **intraprocedural** and **interprocedural** analysis capabilities to track issues across function boundaries.

## Problem Statement

The first rule of cryptography is, "Don't roll your own!" This means that programmers looking to add "security" to their application are going to leverage an existing cryptographic library (e.g., OpenSSL). Unfortunately, the most common cryptographic libraries are similar in complexity as rolling your own. Thus, a growing body of research seeks to identify misuses such cryptographic library's Application Programmer Interface (API). Note that a library's API is the set of ways that your software can interact with the library; there are secure and insecure ways to interact with a library. For this project, you will examine how a set of programs uses a cryptographic library's API. Conventionally, this analysis is intraprocedural, but your analysis will look at the opportunity and challenges of interprocedural API usage analysis. Your end goal is to identify API misuses.

## Installation

### Prerequisites

Make sure you have **[Anaconda](https://www.anaconda.com/download)** or **[Miniconda](https://docs.conda.io/en/latest/miniconda.html)** installed.
You can verify the installation using:

```bash 
conda --version
```

### Setup Instructions

1. Create the conda environment from the requirements
    ```bash
    conda create -n crypto-checker --file requirements-conda.txt
    ```

2. Activate the environment
    ```bash
    conda activate crypto-checker
    ```
   
## Usage

To analyze a Python source file or a directory of files:
```bash
python analysis_tool/api_misuse_checker.py <file_or_directory> [<file_or_directory> ...]
```

Example:

To analyze a single file:

```bash
python analysis_tool/api_misuse_checker.py analysis_tool/test_cases/test_ecb.py
```

<div style="text-align: center;">OR</div>

To analyze multiple files in a directory (or subdirectories):

```bash
python analysis_tool/api_misuse_checker.py analysis_tool/test_cases/
```

Output is a JSON object mapping filenames to a list of detected issues with line numbers.

## What It Detects

Currently supports only [PyCryptodome](https://pycryptodome.readthedocs.io/):

* AES usage with insecure MODE_ECB
* AES CBC/CFB mode without IV
* Use of hardcoded keys in AES.new
* PBKDF2 with:
  * None or hardcoded salt
  * Salt passed via variable that’s hardcoded
* Inter-procedural analysis:
  * Tracks arguments like keys/salts across function calls
  * Flags use of hardcoded values even if defined in a different function

## Test Cases

All test files are located in ```analysis_tool/test_cases```.

Each test targets a specific misuse pattern and validates whether the tool correctly detects it.

## Running Tests

Pytest is used for automated testing. The test script test_api_misuse_checker_pytest.py runs a suite of tests to verify detection accuracy.

To run tests:

```bash
pytest test_api_misuse_checker_pytest.py
```

Tests include:
* Detection of ECB mode
* CBC mode with and without IV
* Hardcoded key usage
* PBKDF2 with and without secure salt
* Inter-procedural analysis (e.g., hardcoded key passed across functions)

## Visual Example: Detecting Interprocedural Misuse

### Code Sample

```python
# test_cross_function_aes_misuse.py

def main():
    key = b"thisisbadkey1234"  # Hardcoded key
    encrypt_data(key)

def encrypt_data(k):
    from Crypto.Cipher import AES
    AES.new(k, AES.MODE_ECB)  # Insecure mode
```

### What the Tool Detects 
* key traced to hardcoded value in main()
* Insecure use of AES.MODE_ECB in encrypt_data()

### Sample Output
```json
{
  "test_cross_function_aes_misuse.py": [
    {
      "line": 4,
      "issue": "key traced to hardcoded value in main(), used in encrypt_data() at line 8"
    },
    {
      "line": 8,
      "issue": "Insecure AES.MODE_ECB detected"
    }
  ]
}
```

### How it works
```text
main()
 └── calls → encrypt_data(k)
                 └── AES.new(k, AES.MODE_ECB)

↑ Interprocedural analyzer traces:
  k ← hardcoded value from main()
```

The tool combines AST traversal with a call graph to trace how data (like keys) flows across functions.