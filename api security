import requests
import json

class APISecurityTester:
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.findings = []
    
    def test_rate_limiting(self, endpoint="/api/users"):
        """Send 100 rapid requests and check for 429 status"""
        url = self.base_url + endpoint
        successes = 0
        for i in range(100):
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                successes += 1
        
        if successes == 100:
            self.findings.append("NO RATE LIMITING: All 100 requests succeeded — brute force possible")
        else:
            self.findings.append(f"RATE LIMITING PRESENT: {100 - successes} requests blocked")
    
    def test_idor(self, endpoint_template="/api/users/{id}"):
        """Test Insecure Direct Object Reference by incrementing user IDs"""
        for user_id in range(1, 10):
            url = self.base_url + endpoint_template.format(id=user_id)
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                if 'password' in data or 'ssn' in data:
                    self.findings.append(f"IDOR: Access to user {user_id} data exposed sensitive fields")
    
    def test_sql_injection(self, endpoint="/api/search?q=test"):
        """Test for SQL injection with simple payloads"""
        payloads = ["' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT * FROM passwords--"]
        for payload in payloads:
            url = self.base_url + endpoint.replace("test", payload)
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200 and "syntax error" not in response.text.lower():
                self.findings.append(f"SQLi POSSIBLE: Payload '{payload}' returned 200")
    
    def run_all_tests(self):
        self.test_rate_limiting()
        self.test_idor()
        self.test_sql_injection()
        return self.findings

# Usage
tester = APISecurityTester("https://api.example.com", "your_api_key_here")
results = tester.run_all_tests()
for finding in results:
    print(f"  • {finding}")
