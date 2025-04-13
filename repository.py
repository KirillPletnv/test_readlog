from concurrent.futures import ProcessPoolExecutor, as_completed
from collections import defaultdict
import tqdm
import os
import multiprocessing
from typing import Dict, List, Generator
from reports import ReportType


class LogRepository:
    """Класс для обработки и анализа лог-файлов с использованием многопроцессорности.
        Attributes:
            strategy (ReportType): Стратегия анализа логов (тип отчета)
            chunk_size (int): Размер чанка для чтения больших файлов (по умолчанию 10MB)"""

    def __init__(self, strategy: ReportType):
        self.strategy = strategy
        self.chunk_size = 1024 * 1024 * 10

    def _process_chunk(self, args: tuple) -> tuple[str, dict]:
        """Обрабатывает чанк файла в worker-процессе.
            Args: args (Tuple[str, int, int]): Кортеж параметров:
                - file_path (str): Путь к файлу
                - offset (int): Смещение в файле
                - size (int): Размер читаемого блока
            Returns:
                Tuple[str, Dict[str, Dict[str, int]]]: Кортеж из:
                - chunk_id (str): Идентификатор чанка
                - stats (Dict): Статистика по чанку в формате {handler: {level: count}}"""

        file_path, offset, size = args
        pid = multiprocessing.current_process().pid
        chunk_id = f"{os.path.basename(file_path)}_part{offset // size}"

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                f.seek(offset)
                chunk = f.read(size)
                result = self.strategy.analyze(chunk)
            return chunk_id, result
        except Exception as e:
            tqdm.tqdm.write(f"Process {pid} error in {chunk_id}: {str(e)}")
            return chunk_id, {}

    def get_stats(self, file_paths: List[str]) -> Dict[str, Dict[str, int]]:
        """Собирает статистику из списка файлов с использованием многопроцессорной обработки.
            Args: file_paths (List[str]): Список путей к лог-файлам
            Returns: Dict[str, Dict[str, int]]:
                Совокупная статистика в формате: {handler: {log_level: count}}
                - Большие файлы автоматически разбиваются на чанки
                - Прогресс обработки отображается через tqdm"""
        combined = defaultdict(lambda: defaultdict(int))
        with ProcessPoolExecutor() as executor:
            futures = []
            for file_path in file_paths:
                file_size = os.path.getsize(file_path)
                if file_size > self.chunk_size * 2:  # Разбиваем только действительно большие файлы
                    # Создаем задачи для каждого чанка
                    for offset in range(0, file_size, self.chunk_size):
                        futures.append(executor.submit(
                            self._process_chunk,
                            (file_path, offset, self.chunk_size)
                        ))
                else:
                    # Маленькие файлы обрабатываем целиком
                    futures.append(executor.submit(
                        self._process_chunk,
                        (file_path, 0, file_size)))
            with tqdm.tqdm(total=len(futures), desc="Processing") as pbar:
                for future in as_completed(futures):
                    chunk_id, stats = future.result()
                    for handler, levels in stats.items():
                        for level, count in levels.items():
                            combined[handler][level] += count
                    pbar.update(1)
                    pbar.set_postfix(file=chunk_id[:20])

        return {handler: dict(levels) for handler, levels in combined.items()}