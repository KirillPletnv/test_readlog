from collections import defaultdict
import re
from typing import Dict, List
from abc import ABC, abstractmethod
import sys

class ReportType(ABC):
    """Абстрактный базовый класс для всех типов отчетов"""
    @abstractmethod
    def analyze(self, content: str) -> Dict[str, Dict[str, int]]:
        """Анализирует содержимое лог-файла"""
        pass

    @abstractmethod
    def generate(self, stats: Dict[str, Dict[str, int]]) -> str:
        """Генерирует текстовый отчет на основе статистики"""
        pass


class HandlersReportType(ReportType):
    """Анализ ручек API """

    _valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    def analyze(self, content: str) -> Dict[str, Dict[str, int]]:
        """Анализирует логи Django для подсчета запросов по обработчикам и уровням
                Args: content (str): Содержимое лог-файла или чанка
                Returns: словарь в формате {обработчик: {уровень_логирования: количество}}"""

        #pattern = re.compile(
        #    r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} '
        #    r'(?P<level>\w+) django\.request: '
        #    r'(?:'
        #    r'(?P<method>\w+ )?(?:Internal Server Error: )?'  # Необязательные части
        #    r'(?P<handler>/[a-zA-Z0-9_\/-]+)'  # Основной захват хендлера
        #    r')',
        #    re.MULTILINE
        #)
        pattern = re.compile(
            r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\s+'
            r'(?P<level>\w+)\s+'
            r'django\.request:\s+'
            r'(?:(?P<method>\w+)\s+)?'
            r'(?:Internal\s+Server\s+Error:\s+)?'
            r'(?P<handler>/[a-zA-Z0-9_\-/]+)'
            r'(?:\s+\d+)?' 
            r'(?:\s|$)'
        )
        stats = defaultdict(lambda: defaultdict(int))
        for i, line in enumerate(content.split('\n'), 1):
            match = pattern.search(line)

            if match:
                level = match.group('level').upper()
                handler = match.group('handler')
                method = match.group('method')

                if handler and level in {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}:
                    stats[handler][level] += 1
        return dict(stats)

    def generate(self, stats: Dict[str, Dict[str, int]]) -> str:
        """Генерирует табличный отчет по обработчикам
            Args: stats (Dict[str, Dict[str, int]]):
            Статистика в формате {обработчик: {уровень: количество}}
            Returns: str: Отформатированная таблица с результатами"""
        if not stats:
            return "No relevant log entries found.\n"
        # Подготовка данных
        stats = {k: dict(v) for k, v in stats.items()}
        levels = self._valid_levels  # ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        # Рассчитываем ширину колонок
        handler_width = max(max(len(h) for h in stats.keys()), len("HANDLER")) + 2
        column_width = max(len(lvl) for lvl in levels) + 2
        # Создаем заголовок
        header = ("HANDLER".ljust(handler_width) +
                  "".join(level.rjust(column_width) for level in levels))
        lines = [header, "=" * (handler_width + column_width * len(levels))]
        # Считаем итоги
        totals = {level: 0 for level in levels}
        for handler in sorted(stats.keys()):
            counts = stats[handler]
            line = handler.ljust(handler_width)
            for level in levels:
                count = counts.get(level, 0)
                line += str(count).rjust(column_width)
                totals[level] += count
            lines.append(line)

        # Итоговая строка
        lines.append("=" * (handler_width + column_width * len(levels)))
        total_line = "TOTAL".ljust(handler_width) + "".join(
            str(totals[level]).rjust(column_width) for level in levels)
        lines.append(total_line)
        # Общее количество запросов
        total_requests = sum(totals.values())
        return (f"\nTotal log entries analyzed: {total_requests}\n\n" +
                "\n".join(lines) + "\n")


class SecurityReportType(ReportType):
    """Тест возможности добавить альтернативный тип отчета """

    def analyze(self, content: str) -> Dict[str, Dict[str, int]]:
        pattern = re.compile(
            r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} '
            r'(?P<level>\w+) django\.security: (?P<event>\w+)',
            re.MULTILINE
        )
        stats = defaultdict(lambda: defaultdict(int))
        for match in pattern.finditer(content):
            stats[match.group('event')][match.group('level').upper()] += 1
        return dict(stats)

    def generate(self, stats: Dict[str, Dict[str, int]]) -> str:
        sorted_items = sorted(stats.items())
        lines = ["SECURITY EVENT".ljust(25) + "\tCOUNT"]
        for event, levels in sorted_items:
            count = sum(levels.values())
            lines.append(f"{event.ljust(25)}\t{count}")
        return "\n".join(lines)

class ReportFactory:
    """Создает объект отчетов указанного типа
           Args: report_type (str): Тип отчета ("handlers" или "security")
           Returns: ReportType: Объект класса HandlersReportType или SecurityReportType
           Raises: ValueError: Если передан неизвестный тип отчета"""
    @staticmethod
    def create(report_type: str) -> ReportType:
        if not report_type:
            raise ValueError("Report type cannot be empty")
        elif report_type == "handlers":
            return HandlersReportType()
        elif report_type == "security":
            return SecurityReportType()
        raise ValueError(f"Unknown report type: {report_type}")