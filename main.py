import sys
import os

from DNSSECChecker.DnssecChecker import DNSSECChecker
from HTTPSChecker.HTTPSChecker import HTTPSChecker
from Scanner.Scanner import scanner
from SecurityHeadersChecker.SecurityHeadersChecker import SecurityHeadersChecker
from SecurityLayerChecker.SecurityLayerChecker import SecurityLayerChecker

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py [csv_file_name]")
        sys.exit(1)

    source_file_csv = sys.argv[1]

    if not os.path.isfile(source_file_csv):
        print(f"Error: File {source_file_csv} not found.")
        sys.exit(1)

    if not source_file_csv.endswith(".csv"):
        print(f"Error: File {source_file_csv} is not a csv file.")
        sys.exit(1)

    engines = {
        SecurityHeadersChecker: {
            'method': 'check_security_headers_https',
            'parameters': {'timeout_limit': 60},
            'result_file_name': 'security_headers_analysis',
            'keys_interface_list': SecurityHeadersChecker.get_owasp_security_headers()
        },
        HTTPSChecker: {
            'method': 'get_https_results',
            'parameters': {'timeout_limit': 160},
            'result_file_name': 'https_analysis',
            'keys_interface_list': HTTPSChecker.get_interface_list()
        },
        DNSSECChecker: {
            'method': 'get_information',
            'parameters': {'timeout_limit': 160},
            'result_file_name': 'dnssec_analysis',
            'keys_interface_list': DNSSECChecker.get_interface_list()
        },
        SecurityLayerChecker: {
            'method': 'check_security_layer',
            'parameters': {'params_request_api': {
                'host': '',
                'publish': 'on',
                'startNew': 'off',
                'fromCache': 'on',
                'all': 'on'
            }},
            'result_file_name': 'security_layer_analysis',
            'keys_interface_list': SecurityLayerChecker.get_interface_list()
        }
    }

    for engine, config in engines.items():
        scanner(file_name=source_file_csv, result_file_name=config['result_file_name'], engine_class=engine,
                method_for_analysis=config['method'], params=config['parameters'],
                keys_interface_list=config['keys_interface_list'])
