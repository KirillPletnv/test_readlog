import re
import tempfile
from typing import Dict
import pytest
from cli_start import main
from reports import HandlersReportType, SecurityReportType, ReportFactory, ReportType
from repository import LogRepository
import sys
import time
import threading
import os

from concurrent.futures import Future
from unittest.mock import MagicMock, patch
from collections import defaultdict

# Тестовые данные
TEST_LOG_CONTENT = """2025-03-28 12:44:46,000 INFO django.request: GET /api/v1/reviews/ 204 OK [192.168.1.59]
2025-03-28 12:21:51,000 INFO django.request: GET /admin/dashboard/ 200 OK [192.168.1.68]
2025-03-28 12:40:47,000 CRITICAL django.core.management: DatabaseError: Deadlock detected
2025-03-28 12:11:57,000 ERROR django.request: Internal Server Error: /admin/dashboard/ [192.168.1.29] - ValueError: Invalid input data
2025-03-28 12:09:06,000 ERROR django.request: Internal Server Error: /api/v1/support/ [192.168.1.84] - DatabaseError: Deadlock detected
2025-03-28 12:07:59,000 ERROR django.request: Internal Server Error: /api/v1/support/ [192.168.1.45] - OSError: No space left on device
2025-03-28 12:01:42,000 WARNING django.security: IntegrityError: duplicate key value violates unique constraint"""


# Ожидаемые результаты
EXPECTED_HANDLERS_RESULT = {
    '/api/v1/reviews/': {'INFO': 1},
    '/admin/dashboard/': {'INFO': 1, 'ERROR': 1},
    '/api/v1/support/': {'ERROR': 2}
}

EXPECTED_SECURITY_RESULT = {
    'IntegrityError': {'WARNING': 1}
}

@pytest.fixture
def temp_log_file():
    """Фикстура для создания временного лог-файла"""
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.log') as f:
        f.write(TEST_LOG_CONTENT)
        f.flush()
        yield f.name
    os.unlink(f.name)


def test_handlers_report_type_analysis():
    """Тест анализа логов для HandlersReportType"""
    analyzer = HandlersReportType()
    result = analyzer.analyze(TEST_LOG_CONTENT)
    assert result == EXPECTED_HANDLERS_RESULT

def test_security_report_type_analysis():
    """Тест анализа логов для SecurityReportType"""
    analyzer = SecurityReportType()
    result = analyzer.analyze(TEST_LOG_CONTENT)
    assert result == EXPECTED_SECURITY_RESULT

def test_report_factory():
    """Тест фабрики отчетов"""
    assert isinstance(ReportFactory.create('handlers'), HandlersReportType)
    assert isinstance(ReportFactory.create('security'), SecurityReportType)
    with pytest.raises(ValueError):
        ReportFactory.create('invalid_type')

def test_log_repository_with_handlers(temp_log_file):
    """Тест LogRepository с HandlersReportType"""
    report_type = HandlersReportType()
    repo = LogRepository(report_type)
    result = repo.get_stats([temp_log_file])
    assert result == EXPECTED_HANDLERS_RESULT

def test_log_repository_with_security(temp_log_file):
    """Тест LogRepository с SecurityReportType"""
    report_type = SecurityReportType()
    repo = LogRepository(report_type)
    result = repo.get_stats([temp_log_file])
    assert result == EXPECTED_SECURITY_RESULT

def test_main_cli_handlers(temp_log_file, capsys):
    """Тест CLI с handlers отчетом"""
    sys.argv = ['my_func_tests.py', temp_log_file, '--report', 'handlers']
    main()
    captured = capsys.readouterr()
    assert '/api/v1/reviews/' in captured.out
    assert '/admin/dashboard/' in captured.out
    assert '/api/v1/support/' in captured.out

def test_main_cli_security(temp_log_file, capsys):
    """Тест CLI с security отчетом"""
    sys.argv = ['my_func_tests.py', temp_log_file, '--report', 'security']
    main()
    captured = capsys.readouterr()
    assert 'IntegrityError' in captured.out


# Тест на пустые логи
def test_handlers_empty_logs():
    analyzer = HandlersReportType()
    result = analyzer.analyze("")
    assert result == {}

# Тест на некорректные строки
def test_handlers_invalid_lines():
    logs = "2025-01-01 00:00:00,000 DEBUG junk data\n" * 3
    analyzer = HandlersReportType()
    result = analyzer.analyze(logs)
    assert result == {}

# Тест форматирования отчёта
def test_handlers_report_formatting():
    stats = {'/test': {'INFO': 1}}
    report = HandlersReportType().generate(stats)
    assert "HANDLER" in report
    assert "/test" in report

# Тест на отсутствие файла
def test_repository_missing_file():
    repo = LogRepository(HandlersReportType())
    with pytest.raises(FileNotFoundError):
        repo.get_stats(["nonexistent.log"])

# Тест на обработку нескольких файлов
def test_repository_multiple_files(temp_log_file):
    repo = LogRepository(HandlersReportType())
    result = repo.get_stats([temp_log_file, temp_log_file])  # 2 копии
    assert result['/api/v1/reviews/']['INFO'] == 2  # Данные суммируются

# Тест на отсутствие аргументов
def test_cli_no_args(capsys):
    sys.argv = ['script.py']
    with pytest.raises(SystemExit):
        main()
    captured = capsys.readouterr()
    assert "error: the following arguments are required: log_files" in captured.err

# Тест на неверный тип отчёта
def test_cli_invalid_report_type(capsys):
    sys.argv = ['script.py', 'file.log', '--report', 'invalid']
    with pytest.raises(SystemExit):
        main()
    assert "invalid choice" in capsys.readouterr().err

def test_mixed_log_entries():
    logs = (
        "2025-01-01 00:00:00,000 INFO django.request: GET /test/ 200\n"
        "2025-01-01 00:00:01,000 DEBUG invalid line\n"
        "2025-01-01 00:00:02,000 ERROR django.request: POST /test/ 500"
    )
    analyzer = HandlersReportType()
    result = analyzer.analyze(logs)
    assert "/test/" in result
    assert result["/test/"]["INFO"] == 1
    assert result["/test/"]["ERROR"] == 1

@pytest.mark.parametrize("log_line,expected_count", [
    ("INFO django.request: GET /test/", 1),
    ("ERROR django.request: POST /test/", 1),
    ("ERROR django.request: Internal Server Error: /test/", 1),
    ("DEBUG invalid line", 0)])

def test_log_variations(log_line, expected_count):
    analyzer = HandlersReportType()
    result = analyzer.analyze(f"2025-01-01 00:00:00,000 {log_line}")
    assert ("/test/" in result) == (expected_count > 0)

def test_edge_case_urls():
    edge_cases = [
        ("/a/", 1),  # Минимально возможный путь
        ("/" + "a/" * 50, 1),  # Максимально длинный путь
        ("/api/v1/", 1),  # Путь с версией API
        ("/api/with-hyphen/", 1),  # Дефисы в пути
        ("/api/with_underscore/", 1)  # Подчеркивания
    ]

    logs = "\n".join(
        f"2025-01-01 00:00:00,000 INFO django.request: GET {url} 200"
        for url, _ in edge_cases)

    analyzer = HandlersReportType()
    result = analyzer.analyze(logs)
    for url, expected_count in edge_cases:
        assert url in result
        assert result[url]["INFO"] == expected_count


def test_performance_large_logs():
    # Генерируем 10 000 строк логов
    logs = "\n".join(
        f"2025-01-01 00:00:00,000 INFO django.request: GET /api/test/{i} 200"
        for i in range(10000)
    )

    analyzer = HandlersReportType()
    start_time = time.time()
    result = analyzer.analyze(logs)
    end_time = time.time()

    assert len(result) == 10000
    assert (end_time - start_time) < 4.0  # Должно обработать за <4 секунды


def test_multiprocessing_handling(tmp_path):
    # Создаем 100 временных лог-файлов
    files = []
    for i in range(100):
        path = tmp_path / f"test_{i}.log"
        with open(path, 'w') as f:
            f.write(f"2025-01-01 00:00:00,000 INFO django.request: GET /api/file_{i}/ 200\n")
        files.append(str(path))

    analyzer = HandlersReportType()
    repo = LogRepository(analyzer)
    result = repo.get_stats(files)

    assert len(result) == 100
    for i in range(100):
        assert f"/api/file_{i}/" in result

def _process_file(file_path: str) -> Dict[str, Dict[str, int]]:
    """Обработка файла в одном процессе"""
    pattern = re.compile(
        r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} '
        r'(?P<level>\w+) django\.request: (?P<method>\w+) (?P<handler>\S+)',
        re.MULTILINE
    )
    stats = defaultdict(lambda: defaultdict(int))
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        for match in pattern.finditer(content):
            handler = match.group('handler')
            level = match.group('level').upper()
            if level in {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}:
                stats[handler][level] += 1
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
    return dict(stats)

def test_file_read_error(mocker):
    mocker.patch(
        'builtins.open',
        side_effect=IOError("Read error")
    )
    result = _process_file("error.log")
    assert result == {}


def test_encoding_error(mocker):
    mocker.patch(
        'builtins.open',
        side_effect=UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'Invalid byte')
    )
    result = _process_file("bad_encoding.log")
    assert result == {}

class TestLogAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return HandlersReportType()

    def test_empty_stats(self, analyzer):
        """Тест пустой статистики"""
        result = analyzer.generate({})
        assert result == "No relevant log entries found.\n"

    def test_single_handler_single_level(self, analyzer):
        """Тест одного обработчика с одним уровнем"""
        stats = {
            "/api/users/": {"INFO": 5}
        }
        result = analyzer.generate(stats)
        assert "HANDLER" in result
        assert "/api/users/" in result
        assert "5" in result  # Проверяем количество INFO
        assert "Total log entries analyzed: 5" in result

    def test_multiple_handlers_multiple_levels(self, analyzer):
        """Тест нескольких обработчиков с разными уровнями"""
        stats = {
            "/api/users/": {"INFO": 3, "ERROR": 2},
            "/api/products/": {"DEBUG": 1, "INFO": 4}
        }
        result = analyzer.generate(stats)

        assert result.index("/api/products/") < result.index("/api/users/")

        # Проверяем подсчеты
        assert "3" in result  # INFO для /api/users/
        assert "2" in result  # ERROR для /api/users/
        assert "1" in result  # DEBUG для /api/products/
        assert "Total log entries analyzed: 10" in result

    def test_missing_levels(self, analyzer):
        """Тест отсутствующих уровней логирования"""
        stats = {
            "/api/test/": {"INFO": 2}  # Нет ERROR, DEBUG и т.д.
        }
        result = analyzer.generate(stats)

        # Проверяем что все уровни есть в заголовке
        for level in analyzer._valid_levels:
            assert level in result

        # Проверяем что отсутствующие уровни отображаются как 0
        assert "0" in result

    def test_all_levels(self, analyzer):
        """Тест всех возможных уровней логирования"""
        stats = {
            "/api/all/": {
                "DEBUG": 1,
                "INFO": 2,
                "WARNING": 3,
                "ERROR": 4,
                "CRITICAL": 5
            }
        }
        result = analyzer.generate(stats)

        # Проверяем что все уровни отображаются
        for level, count in stats["/api/all/"].items():
            assert str(count) in result

        assert "Total log entries analyzed: 15" in result

    def test_handler_names_alignment(self, analyzer):
        """Тест выравнивания имен обработчиков (без проверки точной ширины)"""
        long_handler = "/api/very/long/path/endpoint/"
        stats = {
            long_handler: {"INFO": 1},
            "/": {"ERROR": 1}
        }
        result = analyzer.generate(stats)

        # Проверяем, что оба обработчика присутствуют в выводе
        assert long_handler in result
        assert "/" in result

        # Проверяем, что уровни логирования корректно отображаются
        assert "INFO" in result
        assert "ERROR" in result




class MockFuture(Future):
    """Полноценный мок Future объекта"""
    def __init__(self, result):
        super().__init__()
        self._result = result
        self._state = 'FINISHED'
        self._condition = threading.Condition()

    def result(self):
        return self._result


class MockExecutor:
    """Мок ProcessPoolExecutor"""
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def submit(self, func, *args):
        # Возвращаем корректную структуру данных
        if args and isinstance(args[0], tuple):  # Для чанков
            file_path, offset, size = args[0]
            return MockFuture((
                os.path.basename(file_path),
                {"/api/test/": {"INFO": 1}}
            ))
        else:  # Для целых файлов
            return MockFuture((
                os.path.basename(args[0]),
                {"/api/test/": {"INFO": 1}}
            ))

    def shutdown(self, wait=True):
        pass


class MockLogRepository:
    """Мок LogRepository с правильной структурой данных"""
    def __init__(self, strategy):
        pass
    def get_stats(self, file_paths):
        return {"/api/test/": {"INFO": 1}}


def test_main_handlers_report(capsys, monkeypatch, tmp_path):
    """Тестируем main() с report=handlers"""
    # 1. Подготовка тестового лог-файла
    log_file = tmp_path / "test.log"
    log_file.write_text("2025-01-01 00:00:00,000 INFO django.request: GET /api/test/ 200\n")

    # 2. Мокаем sys.argv
    monkeypatch.setattr(
        "sys.argv",
        ["script.py", str(log_file), "--report", "handlers"]
    )

    # 3. Патчим зависимости
    with patch("reports.ReportFactory.create") as mock_factory, \
            patch("repository.LogRepository", MockLogRepository), \
            patch("repository.ProcessPoolExecutor", MockExecutor):
        # Настраиваем mock для ReportFactory
        mock_report = MagicMock()
        mock_report.generate.return_value = "Mocked handlers report"
        mock_factory.return_value = mock_report

        # 4. Запускаем main()
        main()

        # 5. Проверяем вывод
        captured = capsys.readouterr()
        assert "Report type: handlers" in captured.out
        assert "Mocked handlers report" in captured.out
        assert "Time:" in captured.out


