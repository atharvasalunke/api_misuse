import subprocess
import json
import os

SCRIPT = 'api_misuse_checker.py'
TEST_DIR = 'test_cases'

def run_checker(target_file):
    result = subprocess.run(
        ['python', SCRIPT, os.path.join(TEST_DIR, target_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    assert result.returncode == 0, f"Error: {result.stderr}"
    return json.loads(result.stdout)

def test_ecb_mode():
    output = run_checker('test_ecb.py')
    issues = output.get(os.path.join(TEST_DIR, 'test_ecb.py'), [])
    assert any('ECB' in issue['issue'] for issue in issues)

def test_cbc_missing_iv():
    output = run_checker('test_cbc_missing_iv.py')
    issues = output.get(os.path.join(TEST_DIR, 'test_cbc_missing_iv.py'), [])
    assert any('Missing IV' in issue['issue'] for issue in issues)

def test_cbc_with_iv():
    output = run_checker('test_cbc_with_iv.py')
    issues = output.get(os.path.join(TEST_DIR, 'test_cbc_with_iv.py'), [])
    assert not issues

def test_hardcoded_key():
    output = run_checker('test_hardcoded_key.py')
    issues = output.get(os.path.join(TEST_DIR, 'test_hardcoded_key.py'), [])
    assert any('Hardcoded key' in issue['issue'] for issue in issues)

def test_pbkdf2_no_salt():
    output = run_checker('test_pbkdf2_no_salt.py')
    issues = output.get(os.path.join(TEST_DIR, 'test_pbkdf2_no_salt.py'), [])
    assert any('None as salt' in issue['issue'] for issue in issues)

def test_pbkdf2_with_salt():
    output = run_checker('test_pbkdf2_with_salt.py')
    issues = output.get(os.path.join(TEST_DIR, 'test_pbkdf2_with_salt.py'), [])
    assert not issues

def test_pbkdf2_hardcoded_salt():
    output = run_checker('test_pbkdf2_hardcoded_salt.py')
    issues = output.get(os.path.join(TEST_DIR, 'test_pbkdf2_hardcoded_salt.py'), [])
    assert any('hardcoded salt' in issue['issue'].lower() for issue in issues)

def test_cross_function_aes_misuse():
    output = run_checker('test_cross_function_aes_misuse.py')
    issues = output.get(os.path.join(TEST_DIR, 'test_cross_function_aes_misuse.py'), [])
    assert any('ECB' in issue['issue'] for issue in issues)
    assert any('traced to hardcoded' in issue['issue'] for issue in issues)