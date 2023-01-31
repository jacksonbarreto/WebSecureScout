import traceback

import pandas as pd
import concurrent.futures
import os.path
import threading


def scanner(file_name, result_file_name, engine_class, method_for_analysis, keys_interface_list, url_column_name='url',
            params=None, encoding='utf-8'):
    if params is None:
        params = {}

    source_df = pd.read_csv(filepath_or_buffer=f'./{file_name}.csv', encoding=encoding, engine='python')

    errors_dataframe = create_error_dataframe(source_df.columns)

    keys_dataframe_result = list(source_df.columns)
    keys_dataframe_result.extend(keys_interface_list)

    source_df_size = len(source_df)

    result_dataframe = pd.DataFrame(columns=keys_dataframe_result)

    lock_result_dataframe = threading.Lock()
    lock_errors_dataframe = threading.Lock()

    def analyze_row(row, engine, parameters, analysis_method_name, url_column):
        try:
            parameters.update({'website': getattr(row, url_column)})
            engine_instance = engine(**parameters)
            analysis_method = getattr(engine_instance, analysis_method_name)
            analysis_result = analysis_method()
            analysis_result.update({column: getattr(row, column) for column in source_df.columns})
            with lock_result_dataframe:
                add_row_to_dataframe(result_dataframe, analysis_result)
        except Exception as e:
            #APAGAR
            print(e)
            traceback.print_exc()
            empty_row = {column: '' for column in keys_interface_list}
            empty_row.update({column: getattr(row, column) for column in source_df.columns})
            with lock_result_dataframe:
                add_row_to_dataframe(result_dataframe, empty_row)
            with lock_errors_dataframe:
                add_error_row_to_error_dataframe(errors_dataframe, row, str(e))

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(analyze_row, row, engine_class, params, method_for_analysis, url_column_name) for row
                   in
                   source_df.itertuples()]
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            print(f'{engine_class.__name__} - analyzing record {i + 1}/{source_df_size}')

    path_results = 'results/'
    if not os.path.exists(path_results):
        os.makedirs(path_results)
    result_dataframe.to_csv(path_or_buf=f'{path_results}{result_file_name}.csv', encoding=encoding, index=False)
    errors_dataframe.to_csv(path_or_buf=f'{path_results}{result_file_name}_errors.csv', encoding=encoding, index=False)


def add_row_to_dataframe(dataframe, new_row):
    dataframe.loc[len(dataframe)] = new_row
    return dataframe


def add_error_row_to_error_dataframe(dataframe, error_row, error_message):
    error_row = list(error_row)[1:]
    error_row.append(error_message)
    dataframe.loc[len(dataframe)] = error_row
    return dataframe


def create_error_dataframe(columns):
    dataframe = pd.DataFrame(columns=columns)
    dataframe['error'] = ''
    return dataframe
