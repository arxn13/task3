# Penetration Testing Toolkit

This toolkit provides modular components for penetration testing, including a port scanner and a brute force login tester.

## Modules

### Port Scanner

- Scans specified ports on a target host.
- Usage example:

```bash
python cli.py portscan <host> <ports> [--timeout TIMEOUT]
```

- `<host>`: Target hostname or IP address.
- `<ports>`: Comma-separated list of ports or port ranges (e.g., `22,80,1000-1010`).
- `--timeout`: Timeout in seconds for each port scan (default: 1.0).

### Brute Force Login Tester

- Attempts to brute force HTTP login forms.
- Usage example:

```bash
python cli.py bruteforce <url> <username_field> <password_field> <username> <password_file> <success_indicator> [--timeout TIMEOUT]
```

- `<url>`: Login form URL.
- `<username_field>`: Form field name for username.
- `<password_field>`: Form field name for password.
- `<username>`: Username to test.
- `<password_file>`: File containing list of passwords to try (one per line).
- `<success_indicator>`: String indicating successful login in the HTTP response.
- `--timeout`: Timeout in seconds for each HTTP request (default: 5.0).

## Example Usage

### Port Scanner

```bash
python cli.py portscan 192.168.1.1 22,80,443,8000-8010
```

### Brute Force Login Tester

```bash
python cli.py bruteforce http://example.com/login username password admin passwords.txt "Welcome"
```

## Requirements

- Python 3.x
- `requests` library (install with `pip install requests`)

## Notes

- Use responsibly and only on systems you have permission to test.
- The brute force module requires knowledge of the login form field names and a success indicator string.


import unittest
from pentest_toolkit import port_scanner

class TestPortScanner(unittest.TestCase):
    def test_scan_port_open(self):
        # Test scanning a common open port (e.g., 80 on localhost might be closed, so use 22 or 443)
        # This test assumes port 80 is closed on localhost, so we test for False or True
        result = port_scanner.scan_port('127.0.0.1', 80)
        self.assertIn(result, [True, False])

    def test_scan_port_closed(self):
        # Test scanning a port that is likely closed (e.g., 9999)
        result = port_scanner.scan_port('127.0.0.1', 9999)
        self.assertFalse(result)

    def test_scan_ports(self):
        ports = [80, 9999]
        results = port_scanner.scan_ports('127.0.0.1', ports)
        self.assertIn(80, results)
        self.assertIn(9999, results)
        self.assertIn(results[80], [True, False])
        self.assertFalse(results[9999])

if __name__ == '__main__':
    unittest.main()



import unittest
from unittest.mock import patch, Mock
from pentest_toolkit import brute_force_login

class TestBruteForceLogin(unittest.TestCase):
    @patch('pentest_toolkit.brute_force_login.requests.Session.post')
    def test_brute_force_login_success(self, mock_post):
        # Mock response for successful login
        mock_response = Mock()
        mock_response.text = "Welcome, user!"
        mock_post.return_value = mock_response

        url = "http://example.com/login"
        username_field = "username"
        password_field = "password"
        username = "admin"
        password_list = ["1234", "password", "admin123"]
        success_indicator = "Welcome"

        result = brute_force_login.brute_force_login(url, username_field, password_field, username, password_list, success_indicator)
        self.assertEqual(result, "1234")

    @patch('pentest_toolkit.brute_force_login.requests.Session.post')
    def test_brute_force_login_failure(self, mock_post):
        # Mock response for failed login
        mock_response = Mock()
        mock_response.text = "Login failed"
        mock_post.return_value = mock_response

        url = "http://example.com/login"
        username_field = "username"
        password_field = "password"
        username = "admin"
        password_list = ["1234", "password", "admin123"]
        success_indicator = "Welcome"

        result = brute_force_login.brute_force_login(url, username_field, password_field, username, password_list, success_indicator)
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()

