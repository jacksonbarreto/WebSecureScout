import csv
import sys
import os

import pandas as pd

from DNSSECChecker.DNSSECChecker import DNSSECChecker
from HTTPSChecker.HTTPSChecker import HTTPSChecker
from Scanner.Scanner import scanner
from Scanner.Scanner2 import Scanner as Scanner2
from Scanner.Scanner2 import ScannerConfig
from SecurityHeadersChecker.SecurityHeadersChecker import SecurityHeadersChecker
from SecurityLayerChecker.SecurityLayerChecker import SecurityLayerChecker

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python main.py [csv_file_name with .csv extension] [url_column_name]")
        sys.exit(1)

    source_file_csv = sys.argv[1]
    url_column_name = sys.argv[2]
    file_without_extension = source_file_csv.split(".csv")[0]

    if not source_file_csv.endswith('.csv'):
        print(f"Error: File {source_file_csv} does not have .csv extension.")
        sys.exit(1)

    if not os.path.isfile(source_file_csv):
        print(f"Error: File {source_file_csv} not found.")
        sys.exit(1)

    with open(file=source_file_csv, mode='r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        headers = next(reader)
        columns = headers

    if url_column_name not in columns:
        print(f"Error: Column {url_column_name} not found in {source_file_csv}.")
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
            'parameters': None,
            'result_file_name': 'dnssec_analysis',
            'keys_interface_list': DNSSECChecker.get_interface_list()
        },
        SecurityLayerChecker: {
            'method': 'check_security_layer_in_list',
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

    params_security_layer = {'params_request_api': {
        'host': '',
        'publish': 'on',
        'startNew': 'off',
        'fromCache': 'on',
        'all': 'on'
    }}
    source_df = pd.read_csv(filepath_or_buffer=f'{source_file_csv}', encoding='utf-8', engine='python')
    configs = [
        ScannerConfig(engine_class=SecurityHeadersChecker, method_for_analysis='check_security_headers_https',
                      keys_interface_list=SecurityHeadersChecker.get_owasp_security_headers(),
                      url_column_name=url_column_name, params={'timeout_limit': 60}),
        ScannerConfig(engine_class=HTTPSChecker, method_for_analysis='get_https_results',
                      keys_interface_list=HTTPSChecker.get_interface_list(), url_column_name=url_column_name,
                      params={'timeout_limit': 160}),
        ScannerConfig(engine_class=DNSSECChecker, method_for_analysis='get_information',
                      keys_interface_list=DNSSECChecker.get_interface_list(), url_column_name=url_column_name),
        ScannerConfig(engine_class=SecurityLayerChecker, method_for_analysis='check_security_layer_in_list',
                      keys_interface_list=SecurityLayerChecker.get_interface_list(), url_column_name=url_column_name,
                      params=params_security_layer)]
    # features: implement log_on as parameter in sis.argv
    for config in configs:
        Scanner2(config, source_df).start_analysis(log_on=True, save_to_file_on=True)

    # for engine, config in engines.items():
      #  scanner(file_name=file_without_extension, result_file_name=config['result_file_name'], engine_class=engine,
       #         method_for_analysis=config['method'], params=config['parameters'], url_column_name=url_column_name,
        #        keys_interface_list=config['keys_interface_list'])
