import argparse
import os
from time import perf_counter
from reports import ReportFactory
from repository import LogRepository



def validate_files(file_paths):
    """Проверяет существование файлов и возвращает список существующих"""
    existing_files = []
    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"Warning: File '{file_path}' does not exist - skipping")
        elif not os.path.isfile(file_path):
            print(f"Warning: '{file_path}' is not a file - skipping")
        else:
            existing_files.append(file_path)
    if not existing_files:
        raise ValueError("No valid log files provided")
    return existing_files


def main():
    """Стартуем"""
    start_time = perf_counter()
    parser = argparse.ArgumentParser(description='Analyze Django logs')
    parser.add_argument('log_files', nargs='+', help='Log files to analyze')
    parser.add_argument('--report', choices=['handlers', 'security'], default='handlers', help='Report type')
    args = parser.parse_args()
    try:
        valid_files = validate_files(args.log_files)
        report_type = ReportFactory.create(args.report)
        repo = LogRepository(report_type)
        # Получаем статистику для всех файлов сразу
        stats = repo.get_stats(valid_files)
        report = report_type.generate(stats)
        print(f"Report type: {args.report}")
        print(report)
        print(f"\nTime: {perf_counter() - start_time:.2f}s")
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    return 0

if __name__ == '__main__':
    main()