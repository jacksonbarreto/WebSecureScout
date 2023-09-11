import csv
import sys
import os

import pandas as pd

from AxfrChecker.AxfrChecker import AxfrChecker
from DnssecChecker.DnssecChecker import DnssecChecker
from HttpsChecker.HttpsChecker import HttpsChecker
from Scanner.Scanner import Scanner, ScannerConfig
from SecurityHeadersChecker.SecurityHeadersChecker import SecurityHeadersChecker
from SecurityLayerChecker.SecurityLayerChecker import SecurityLayerChecker

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python main.py [csv_file_name with .csv extension] [url_column_name] [log_flag (optional)]")
        sys.exit(1)

    source_file_csv = sys.argv[1]
    url_column_name = sys.argv[2]
    file_without_extension = source_file_csv.split(".csv")[0]
    log_flag = True

    if len(sys.argv) == 4:
        log_flag = (sys.argv[3].lower() == 'true')

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

    source_df = pd.read_csv(filepath_or_buffer=f'{source_file_csv}', encoding='utf-8', engine='python')
    configs = [
        ScannerConfig(engine_class=SecurityHeadersChecker, method_for_analysis='check_security_headers_https',
                      keys_interface_list=SecurityHeadersChecker.get_owasp_security_headers(),
                      url_column_name=url_column_name, params={'timeout_limit': 180}),
        ScannerConfig(engine_class=HttpsChecker, method_for_analysis='get_https_results',
                      keys_interface_list=HttpsChecker.get_interface_list(), url_column_name=url_column_name,
                      params={'timeout_limit': 180}),
        ScannerConfig(engine_class=DnssecChecker, method_for_analysis='get_information',
                      keys_interface_list=DnssecChecker.get_interface_list(), url_column_name=url_column_name),
        ScannerConfig(engine_class=AxfrChecker, method_for_analysis='get_information',
                      keys_interface_list=AxfrChecker.get_interface_list(), url_column_name=url_column_name),
        ScannerConfig(engine_class=SecurityLayerChecker, method_for_analysis='check_security_layer_in_list',
                      keys_interface_list=SecurityLayerChecker.get_interface_list(), url_column_name=url_column_name)
    ]

    for config in configs:
        Scanner(config, source_df).start_analysis(log_on=log_flag, save_to_file_on=True)
