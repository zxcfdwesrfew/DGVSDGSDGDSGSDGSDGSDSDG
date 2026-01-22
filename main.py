import subprocess
import time

def run_app():
    while True:
        print("Запуск app.py...")

        process = subprocess.Popen(["python", "app.py"])

        process.wait()

        if process.returncode != 0:
            print("app.py завершился с ошибкой. Перезапуск...")
        else:
            print("app.py завершился. Перезапуск...")

        time.sleep(1)

if __name__ == "__main__":
    run_app()