import os
from concurrent.futures import ThreadPoolExecutor as PoolExecutor
from concurrent.futures import as_completed as future_completed

from pandas import DataFrame, Series
from threading import Lock


class ScannerConfig:
    def __init__(self, engine_class: type, method_for_analysis: str, keys_interface_list: list[str],
                 url_column_name: str = None, params: dict = None) -> None:
        self.__engine_class = engine_class
        self.__method_for_analysis = method_for_analysis
        self.__keys_interface_list = keys_interface_list
        self.__url_column_name = 'url' if url_column_name is None else url_column_name
        self.__params = params if params is not None else {}

    def get_engine_class(self) -> type:
        return self.__engine_class

    def get_method_for_analysis(self) -> str:
        return self.__method_for_analysis

    def get_keys_interface_list(self) -> list[str]:
        return self.__keys_interface_list

    def get_url_column_name(self) -> str:
        return self.__url_column_name

    def get_params(self) -> dict:
        return self.__params


class Scanner:
    def __init__(self, config: ScannerConfig, source_df: DataFrame) -> None:
        self.__config = config
        self.__source_df = source_df
        self.__params_engine = self.__config.get_params()
        self.__errors_dataframe = self.__create_error_dataframe(self.__source_df.columns)
        keys_dataframe_result = list(source_df.columns)
        keys_dataframe_result.extend(self.__config.get_keys_interface_list())
        self.__result_dataframe = DataFrame(columns=keys_dataframe_result)
        self.__lock_result_df = Lock()
        self.__lock_errors_df = Lock()

    @staticmethod
    def __create_error_dataframe(columns: list[str]) -> DataFrame:
        df = DataFrame(columns=columns)
        df['error'] = ''
        return df

    @staticmethod
    def __to_snake_case(camelcase: str) -> str:
        return ''.join(['_' + i.lower() if i.isupper() else i for i in camelcase]).lstrip('_')

    def __analyze_row(self, row: Series) -> str:
        try:
            self.__params_engine.update({'website': getattr(row, self.__config.get_url_column_name())})
            engine = self.__config.get_engine_class()(**self.__params_engine)
            results = getattr(engine, self.__config.get_method_for_analysis())()
            results.update({column: getattr(row, column) for column in self.__source_df.columns})
            with self.__lock_result_df:
                self.__result_dataframe.loc[len(self.__result_dataframe)] = results
            return f'Record {row.Index} - {getattr(row, self.__config.get_url_column_name())} - successfully scanned.'
        except Exception as e:
            empty_row = {column: '' for column in self.__config.get_keys_interface_list()}
            empty_row.update({column: getattr(row, column) for column in self.__source_df.columns})
            error_row = {column: getattr(row, column) for column in self.__source_df.columns}
            error_row['error'] = str(e)
            with self.__lock_result_df:
                self.__result_dataframe.loc[len(self.__result_dataframe)] = empty_row
            with self.__lock_errors_df:
                self.__errors_dataframe.loc[len(self.__errors_dataframe)] = error_row
            return f'Record {row.Index} - {getattr(row, self.__config.get_url_column_name())} - ERROR: {str(e)}'

    def start_analysis(self, save_to_file_on: bool = False, log_on: bool = False) -> dict[str, DataFrame]:
        if log_on:
            print(f'Start analysis with {self.__config.get_engine_class().__name__} engine...')
        with PoolExecutor() as executor:
            futures = [executor.submit(self.__analyze_row, row) for row in self.__source_df.itertuples()]
            if log_on:
                for future in future_completed(futures):
                    print(future.result())
        if save_to_file_on:
            self.__save_result()
            if log_on:
                print(f'Results from {self.__config.get_engine_class().__name__} engine saved to file.')
        if log_on:
            print(f'Analysis with {self.__config.get_engine_class().__name__} engine completed.')
        return {
            'results_dataframe': self.__result_dataframe,
            'errors_dataframe': self.__errors_dataframe
        }

    def __save_result(self) -> None:
        path_results = 'results/'
        if not os.path.exists(path_results):
            os.makedirs(path_results)
        result_file_name = f'{path_results}{self.__to_snake_case(self.__config.get_engine_class().__name__)}.csv'
        error_file_name = result_file_name.replace('.csv', '_errors.csv')
        self.__result_dataframe.to_csv(result_file_name, index=False)
        self.__errors_dataframe.to_csv(error_file_name, index=False)
