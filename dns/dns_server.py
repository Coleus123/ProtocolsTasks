import socket
import json
import time
import threading
from utils import parse_dns_response, extract_records, build_dns_response
import traceback

CACHE_FILE = 'cache.json'
PORT = 53
UPSTREAM_DNS = '8.8.8.8'
BUFFER_SIZE = 512
cache = {}
cache_lock = threading.Lock()
running = True


def load_cache():
    global cache
    try:
        with open(CACHE_FILE, 'r') as f:
            raw = json.load(f)
            now = time.time()
            with cache_lock:
                for key in list(raw):
                    raw[key] = [r for r in raw[key] if now - r['timestamp'] < r['ttl']]
                    if not raw[key]:
                        del raw[key]
                cache = raw
            print(f"Кэш загружен. Записей: {len(cache)}")
    except FileNotFoundError:
        print("Кэш не найден. Начинаем с пустого кэша.")
        cache = {}
    except json.JSONDecodeError:
        print("Ошибка при загрузке кэша. Возможно, файл поврежден. Начинаем с пустого кэша.")
        cache = {}


def save_cache():
    with cache_lock:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)


def cleanup_cache():
    while running:
        time.sleep(120)
        now = time.time()
        with cache_lock:
            for key in list(cache):
                cache[key] = [r for r in cache[key] if now - r['timestamp'] < r['ttl']]
                if not cache[key]:
                    del cache[key]
        save_cache()
        print(f"Кэш очищен. Активных записей: {len(cache)}")


def handle_request(data, addr, sock):
    try:
        query_name, query_type, tid = parse_dns_response(data)
        key = f"{query_type}:{query_name}"
        now = time.time()
        with cache_lock:
            valid_records = [r for r in cache.get(key, []) if now - r['timestamp'] < r['ttl']]
            if valid_records:
                print(f"Найден в кэше {query_name} (type {query_type})")
                response = build_dns_response(tid, data, valid_records)
                sock.sendto(response, addr)
                return
            else:
                if key in cache:
                    del cache[key]
        print(f"Не найден в кэше {query_name} (type {query_type})")
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.settimeout(5)
        upstream.sendto(data, (UPSTREAM_DNS, 53))
        response, _ = upstream.recvfrom(BUFFER_SIZE)
        sock.sendto(response, addr)
        records = extract_records(response)
        with cache_lock:
            for rec in records:
                k = f"{rec['type']}:{rec['name']}"
                cache.setdefault(k, []).append({
                    'name': rec['name'],
                    'type': rec['type'],
                    'data': rec['data'],
                    'ttl': rec['ttl'],
                    'timestamp': time.time()
                })
    except Exception as e:
        print(f"Ошибка при обработке запроса: {e}.")
        traceback.print_exc()


def monitor_exit_command():
    global running
    while True:
        cmd = input().strip().lower()
        if cmd == 'exit':
            running = False
            print("Остановка сервера...")
            break


def run_dns_server():
    global running
    load_cache()
    threading.Thread(target=cleanup_cache, daemon=True).start()
    threading.Thread(target=monitor_exit_command, daemon=True).start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', PORT))
        print(f"DNS-сервер запущен на порту {PORT}. Введите 'exit' для остановки.")
        while running:
            try:
                sock.settimeout(1)
                data, addr = sock.recvfrom(BUFFER_SIZE)
                threading.Thread(target=handle_request, args=(data, addr, sock)).start()
            except socket.timeout:
                continue
    except Exception as e:
        print(f"Сервер остановлен: {e}")
        traceback.print_exc()
    finally:
        save_cache()
        sock.close()
        print("Сервер успешно остановлен.")


if __name__ == '__main__':
    run_dns_server()