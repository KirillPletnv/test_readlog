import shutil
import os

def amplify_file_fast(input_path, output_path, target_size_gb=1):
    """Создать большой файл отчета из маленького"""
    shutil.copyfile(input_path, output_path)
    original_size = os.path.getsize(input_path)
    repeats = (target_size_gb * 1024 ** 3) // original_size
    with open(output_path, 'ab') as f_out:
        with open(input_path, 'rb') as f_in:
            content = f_in.read()
        for _ in range(repeats):
            f_out.write(content)
    print(f"Файл создан: {output_path} ({os.path.getsize(output_path) / 1024 ** 3:.2f} ГБ)")


amplify_file_fast('app1.log', 'huge_file.txt', target_size_gb=1)