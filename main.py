import base64
import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
import struct
import sys
import zlib
import paramiko
import telebot
from telebot import types
from dotenv import load_dotenv
import threading
import time

# Загрузка переменных из .env
load_dotenv()

# === НАСТРОЙКИ TELEGRAM ===
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_IDS = [int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()]

# === НАСТРОЙКИ SSH ===
SSH_HOST = os.getenv("SSH_HOST", "127.0.0.1")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_USER = os.getenv("SSH_USER", "root")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "id_ed25519")
SSH_PASSWORD = os.getenv("SSH_PASSWORD") or None

# === НАСТРОЙКИ AMNEZIA ===
CONTAINER_NAME = os.getenv("CONTAINER_NAME", "amnezia-awg2")
INTERFACE_NAME = os.getenv("INTERFACE_NAME", "awg0")
SERVER_PUBKEY = os.getenv("SERVER_PUBKEY")
SERVER_ENDPOINT = os.getenv("SERVER_ENDPOINT")
DNS_SERVER = os.getenv("DNS_SERVER", "8.8.8.8")
SUBNET_BASE = os.getenv("SUBNET_BASE", "10.8.1.")

# === НАСТРОЙКИ БАЗЫ ДАННЫХ ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "vpn_users.db")

# === НАСТРОЙКИ ДОНАТА ===
ALPHA_CART = os.getenv("ALPHA_CART")
USDT = os.getenv("USDT")


def validate_config():
    """Проверяет обязательные переменные окружения и падает с понятной ошибкой, если чего-то не хватает."""
    errors = []

    if not BOT_TOKEN:
        errors.append("BOT_TOKEN не задан (токен Telegram-бота)")
    if not ADMIN_IDS:
        errors.append("ADMIN_IDS пуст или не задан (ID админов через запятую)")
    if not SERVER_PUBKEY:
        errors.append("SERVER_PUBKEY не задан (публичный ключ сервера AmneziaWG)")
    if not SERVER_ENDPOINT:
        errors.append("SERVER_ENDPOINT не задан (адрес:порт сервера, напр. 1.2.3.4:8081)")

    # Для подключения к серверу нужен либо SSH-ключ, либо пароль
    if not (SSH_KEY_PATH and os.path.exists(SSH_KEY_PATH)) and not SSH_PASSWORD:
        errors.append(
            f"Нет доступа к серверу по SSH: ключ '{SSH_KEY_PATH}' не найден и SSH_PASSWORD не задан"
        )

    if errors:
        print("❌ Ошибка конфигурации — заполните .env:", file=sys.stderr)
        for e in errors:
            print(f"  • {e}", file=sys.stderr)
        sys.exit(1)


validate_config()

bot = telebot.TeleBot(BOT_TOKEN)
user_states = {}

# Сериализует выдачу ключей: выбор свободного IP и запись в БД должны быть
# атомарны, иначе два одновременных запроса могут получить один и тот же IP.
issue_lock = threading.Lock()

# Разрешённые символы в имени пользователя: буквы (вкл. кириллицу), цифры,
# пробел, точка, дефис, апостроф, подчёркивание. Блокирует shell-метасимволы.
NAME_RE = re.compile(r"^[\w .\-']{1,64}$", re.UNICODE)


def is_valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name))


def stable_synthetic_id(pubkey: str) -> int:
    """Стабильный отрицательный ID для внешних пиров (заведённых мимо бота).

    Встроенный hash() рандомизируется между запусками процесса (PYTHONHASHSEED),
    поэтому используем SHA-256 — один и тот же pubkey всегда даёт один и тот же ID,
    без дублей после перезапуска. Отрицательный, чтобы не пересекаться с реальными
    (положительными) Telegram user_id.
    """
    digest = hashlib.sha256(pubkey.encode("utf-8")).hexdigest()
    return -(int(digest[:12], 16) % 1000000000)


def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


@contextmanager
def db(commit: bool = False):
    """Контекст-менеджер для SQLite: открывает соединение, отдаёт курсор и
    гарантированно закрывает его (в т.ч. при исключении). При commit=True и
    отсутствии исключения коммитит транзакцию.

    Использование:
        with db() as cur:                 # только чтение
            cur.execute(...)
        with db(commit=True) as cur:      # запись
            cur.execute(...)
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn.cursor()
        if commit:
            conn.commit()
    finally:
        conn.close()


def init_db():
    with db(commit=True) as cursor:
        # Создание или миграция таблицы пользователей
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if cursor.fetchone():
            cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'about' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN about TEXT")
            if 'traffic_month' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN traffic_month INTEGER DEFAULT 0")
            if 'traffic_total' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN traffic_total INTEGER DEFAULT 0")
            if 'last_reset_month' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN last_reset_month TEXT DEFAULT 'Никогда'")
            if 'last_reset_total' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN last_reset_total TEXT DEFAULT 'Никогда'")
            if 'last_seen_bytes' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN last_seen_bytes INTEGER DEFAULT 0")
        else:
            cursor.execute("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        name TEXT,
                        phone TEXT,
                        username TEXT,
                        ip TEXT,
                        pubkey TEXT,
                        privkey TEXT,
                        about TEXT,
                        traffic_month INTEGER DEFAULT 0,
                        traffic_total INTEGER DEFAULT 0,
                        last_reset_month TEXT DEFAULT 'Никогда',
                        last_reset_total TEXT DEFAULT 'Никогда',
                        last_seen_bytes INTEGER DEFAULT 0
                    )
                """)

        # Таблица заявок
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pending_requests'")
        if cursor.fetchone():
            cursor.execute("PRAGMA table_info(pending_requests)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'about' not in columns:
                cursor.execute("ALTER TABLE pending_requests ADD COLUMN about TEXT")
        else:
            cursor.execute("""
                CREATE TABLE pending_requests (
                    user_id INTEGER PRIMARY KEY,
                    name TEXT,
                    phone TEXT,
                    username TEXT,
                    is_extra BOOLEAN DEFAULT 0,
                    about TEXT
                )
            """)

        cursor.execute("CREATE TABLE IF NOT EXISTS whitelist (phone TEXT PRIMARY KEY)")

        # Таблица для хранения индивидуальных лимитов
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phone_limits (
                phone TEXT PRIMARY KEY,
                max_keys INTEGER DEFAULT 1
            )
        """)


# === БЭКАП И ВОССТАНОВЛЕНИЕ БД ===

def make_db_snapshot() -> str:
    """Создаёт консистентный снапшот БД (online backup API) во временный файл и
    возвращает путь к нему. Безопасно даже при параллельной записи в базу."""
    fd, tmp_path = tempfile.mkstemp(prefix="vpn_users_backup_", suffix=".db")
    os.close(fd)
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(tmp_path)
    try:
        with dst:
            src.backup(dst)
    finally:
        src.close()
        dst.close()
    return tmp_path


def is_valid_db_file(path: str) -> bool:
    """Проверяет, что файл — валидная SQLite-база с ожидаемой таблицей users
    (защита от восстановления из мусорного/чужого файла)."""
    try:
        conn = sqlite3.connect(path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            return cur.fetchone() is not None
        finally:
            conn.close()
    except Exception:
        return False


# === ФУНКЦИИ БЕЛОГО СПИСКА И ЛИМИТОВ ===

def is_phone_whitelisted(phone: str) -> bool:
    with db() as cursor:
        cursor.execute("SELECT phone FROM whitelist WHERE phone = ?", (phone,))
        return cursor.fetchone() is not None


def add_phone_to_whitelist(phone: str):
    with db(commit=True) as cursor:
        cursor.execute("INSERT OR REPLACE INTO whitelist (phone) VALUES (?)", (phone,))


def remove_phone_from_whitelist(phone: str):
    with db(commit=True) as cursor:
        cursor.execute("DELETE FROM whitelist WHERE phone = ?", (phone,))


def get_all_whitelisted_phones():
    with db() as cursor:
        cursor.execute("SELECT phone FROM whitelist ORDER BY phone")
        return [r[0] for r in cursor.fetchall()]


def get_max_keys(phone: str) -> int:
    with db() as cursor:
        cursor.execute("SELECT max_keys FROM phone_limits WHERE phone = ?", (phone,))
        row = cursor.fetchone()
        return row[0] if row else 1


def set_max_keys(phone: str, limit: int):
    with db(commit=True) as cursor:
        cursor.execute("INSERT OR REPLACE INTO phone_limits (phone, max_keys) VALUES (?, ?)", (phone, limit))


def get_user_key_count(phone: str) -> int:
    with db() as cursor:
        cursor.execute("SELECT COUNT(*) FROM users WHERE phone = ?", (phone,))
        return cursor.fetchone()[0]


# === ВЗАИМОДЕЙСТВИЕ С СЕРВЕРОМ ===

def update_all_traffic():
    """Стягивает трафик из ядра, вычисляет дельту и сохраняет в БД"""
    try:
        output = run_ssh_container_cmd(f"awg show {INTERFACE_NAME} transfer")
    except Exception:
        try:
            output = run_ssh_container_cmd(f"wg show {INTERFACE_NAME} transfer")
        except Exception:
            output = ""

    current_stats = {}
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            # Суммируем полученные и отправленные байты (Rx + Tx)
            current_stats[parts[0]] = int(parts[1]) + int(parts[2])

    with db(commit=True) as cursor:
        cursor.execute("SELECT pubkey, traffic_month, traffic_total, last_seen_bytes FROM users WHERE pubkey IS NOT NULL")
        users = cursor.fetchall()

        for pubkey, t_month, t_total, last_seen in users:
            t_month = t_month or 0
            t_total = t_total or 0
            last_seen = last_seen or 0

            current_bytes = current_stats.get(pubkey, 0)

            # Если трафик увеличился, вычисляем дельту. Если ядро сбросилось (current_bytes < last_seen), дельта = current_bytes
            if current_bytes >= last_seen:
                delta = current_bytes - last_seen
            else:
                delta = current_bytes

            if delta > 0:
                t_month += delta
                t_total += delta
                cursor.execute("""
                    UPDATE users
                    SET traffic_month = ?, traffic_total = ?, last_seen_bytes = ?
                    WHERE pubkey = ?
                """, (t_month, t_total, current_bytes, pubkey))
            elif current_bytes < last_seen:
                # Просто обновляем 'последнее увиденное', если трафик обнулился, а дельты нет
                cursor.execute("UPDATE users SET last_seen_bytes = ? WHERE pubkey = ?", (current_bytes, pubkey))


def _new_ssh_client() -> paramiko.SSHClient:
    """Создаёт и подключает новый SSH-клиент (по ключу или паролю)."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if SSH_KEY_PATH and os.path.exists(SSH_KEY_PATH):
        ssh.connect(hostname=SSH_HOST, port=SSH_PORT, username=SSH_USER, key_filename=SSH_KEY_PATH)
    else:
        ssh.connect(hostname=SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD)
    return ssh


def _exec_container_cmd(ssh: paramiko.SSHClient, cmd: str) -> str:
    """Выполняет команду внутри контейнера Amnezia через уже открытое SSH-соединение.

    Успех определяется по коду возврата команды (exit status), а не по наличию
    текста в stderr: многие утилиты awg/wg пишут предупреждения в stderr при
    успешном завершении, а иногда падают с пустым stdout.
    """
    full_cmd = f"docker exec {CONTAINER_NAME} {cmd}"
    stdin, stdout, stderr = ssh.exec_command(full_cmd)
    # read() дочитывает до EOF (т.е. до завершения команды), после чего
    # recv_exit_status() возвращает код мгновенно, без риска дедлока.
    output = stdout.read().decode("utf-8").strip()
    error = stderr.read().decode("utf-8").strip()
    exit_status = stdout.channel.recv_exit_status()

    if exit_status != 0:
        raise Exception(f"SSH Error (exit {exit_status}): {error or output or 'нет вывода'}")
    return output


class SSHSession:
    """Контекст-менеджер: одно SSH-соединение на серию команд.

    Используй для операций, делающих несколько вызовов подряд (напр.
    restore_users_to_server), чтобы не открывать соединение на каждую команду.
    Экземпляр локален для одного вызова и не шарится между потоками.
    """

    def __init__(self):
        self.ssh = None

    def __enter__(self):
        self.ssh = _new_ssh_client()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.ssh:
            self.ssh.close()
            self.ssh = None
        return False

    def run(self, cmd: str) -> str:
        return _exec_container_cmd(self.ssh, cmd)


def run_ssh_container_cmd(cmd: str) -> str:
    """Разовый вызов: открывает соединение, выполняет команду, закрывает.

    Для серии команд предпочитай SSHSession, чтобы переиспользовать коннект.
    """
    ssh = _new_ssh_client()
    try:
        return _exec_container_cmd(ssh, cmd)
    finally:
        ssh.close()


def format_bytes(size: int) -> str:
    for unit in ["Б", "КБ", "МБ", "ГБ", "ТБ"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} ПБ"


def sync_users_from_server() -> int:
    try:
        with db(commit=True) as cursor:
            cursor.execute("SELECT pubkey FROM users WHERE pubkey IS NOT NULL")
            existing_pubkeys = {row[0] for row in cursor.fetchall()}
            server_peers = {}

            try:
                clients_raw = run_ssh_container_cmd("cat /opt/amnezia/awg/clientsTable")
                if clients_raw:
                    clients_list = json.loads(clients_raw)
                    for client in clients_list:
                        pubkey = client.get("clientId")
                        user_data = client.get("userData", {})
                        allowed_ips = user_data.get("allowed_ips", "")
                        client_name = user_data.get("clientName", "Внешний юзер")
                        ip = allowed_ips.split("/")[0] if "/" in allowed_ips else allowed_ips
                        if pubkey:
                            server_peers[pubkey] = {"name": client_name, "ip": ip}
            except Exception:
                pass

            added_count = 0
            for pubkey, info in server_peers.items():
                if pubkey not in existing_pubkeys:
                    synthetic_id = stable_synthetic_id(pubkey)
                    cursor.execute("""
                        INSERT INTO users (user_id, name, phone, username, ip, pubkey, privkey, about)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (synthetic_id, info["name"], "Внешний (из Amnezia)", "Синхронизация", info["ip"], pubkey, None,
                          "Синхронизировано с сервера"))
                    added_count += 1

            return added_count
    except Exception as e:
        print(f"Ошибка синхронизации: {e}")
        return 0


def remove_peer_from_server(pubkey: str):
    pubkey_clean = pubkey.strip()
    with SSHSession() as ssh:
        try:
            ssh.run(f'awg set {INTERFACE_NAME} peer "{pubkey_clean}" remove')
        except Exception:
            try:
                ssh.run(f'wg set {INTERFACE_NAME} peer "{pubkey_clean}" remove')
            except Exception:
                pass
        try:
            conf_path = f"/opt/amnezia/awg/{INTERFACE_NAME}.conf"
            content = ssh.run(f"cat {conf_path}")
            if "[Peer]" in content:
                blocks = content.split("[Peer]")
                new_blocks = [blocks[0]]
                for block in blocks[1:]:
                    if pubkey_clean not in block:
                        new_blocks.append(block)
                new_conf = "[Peer]".join(new_blocks)
                b64_conf = base64.b64encode(new_conf.encode("utf-8")).decode("utf-8")
                ssh.run(f'sh -c "echo \'{b64_conf}\' | base64 -d > {conf_path}"')
        except Exception as e:
            print(f"Ошибка очистки conf: {e}")
        try:
            clients_raw = ssh.run("cat /opt/amnezia/awg/clientsTable")
            if clients_raw:
                clients_list = json.loads(clients_raw)
                new_clients = [c for c in clients_list if c.get("clientId") != pubkey_clean]
                b64_json = base64.b64encode(json.dumps(new_clients, indent=4, ensure_ascii=False).encode("utf-8")).decode(
                    "utf-8")
                ssh.run(f'sh -c "echo \'{b64_json}\' | base64 -d > /opt/amnezia/awg/clientsTable"')
        except Exception as e:
            print(f"Ошибка очистки clientsTable: {e}")


def get_next_free_ip() -> str:
    used_ips = set()
    with db() as cursor:
        cursor.execute("SELECT ip FROM users")
        for row in cursor.fetchall():
            if row[0]:
                used_ips.add(row[0].strip())

    try:
        show_output = run_ssh_container_cmd(f"awg show {INTERFACE_NAME} allowed-ips")
    except Exception:
        show_output = ""

    for line in show_output.splitlines():
        parts = line.strip().split()
        for part in parts:
            if "/" in part:
                used_ips.add(part.split("/")[0])

    used_last_octets = set()
    for ip in used_ips:
        if ip.startswith(SUBNET_BASE):
            try:
                used_last_octets.add(int(ip.split(".")[-1]))
            except ValueError:
                pass

    for last_octet in range(2, 254):
        if last_octet not in used_last_octets:
            return f"{SUBNET_BASE}{last_octet}"
    raise Exception("Нет свободных IP-адресов!")


def get_server_psk(ssh: "SSHSession" = None) -> str:
    runner = ssh.run if ssh else run_ssh_container_cmd
    try:
        output = runner(f"cat /opt/amnezia/awg/{INTERFACE_NAME}.conf")
        for line in output.splitlines():
            if "PresharedKey" in line and "=" in line:
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def get_awg_obfuscation_params() -> dict:
    """Динамически собирает параметры обфускации с сервера, включая закомментированные ключи I1-I5."""
    standard_keys = {"PrivateKey", "Address", "ListenPort", "PostUp", "PostDown", "SaveConfig", "DNS", "MTU", "Table",
                     "FwMark"}
    params = {}
    try:
        output = run_ssh_container_cmd(f"cat /opt/amnezia/awg/{INTERFACE_NAME}.conf")
        in_interface = False

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Извлекаем параметры даже если они закомментированы (например, # I1 = ...)
            if line.startswith("#"):
                line = line.lstrip("#").strip()

            if line == "[Interface]":
                in_interface = True
                continue
            elif line.startswith("["):
                in_interface = False
                break

            if in_interface and "=" in line:
                key, val = [x.strip() for x in line.split("=", 1)]
                if key not in standard_keys:
                    params[key] = val
    except Exception as e:
        print(f"Ошибка получения параметров обфускации с сервера: {e}")

    return params


def generate_amnezia_vpn_key(config_content: str, server_endpoint: str, dns: str, obf_params: dict, client_privkey: str,
                             client_pubkey: str, client_ip: str, client_psk: str) -> str:
    clean_config = config_content.replace("\r\n", "\n").strip()
    parts = server_endpoint.split(":")
    host_only, port_only = parts[0], parts[1] if len(parts) > 1 else "8081"

    # Формируем внутренний last_config (порт должен быть числом)
    last_config_dict = {
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "client_ip": client_ip,
        "clientId": client_pubkey,
        "client_priv_key": client_privkey,
        "client_pub_key": client_pubkey,
        "config": clean_config,
        "hostName": host_only,
        "port": int(port_only),
        "mtu": "1280",
        "persistent_keep_alive": "25",
        "psk_key": client_psk if client_psk else "",
        "server_pub_key": SERVER_PUBKEY
    }
    last_config_dict.update(obf_params)

    # Формируем awg_block (настройки контейнера)
    awg_block = {
        "last_config": json.dumps(last_config_dict, ensure_ascii=False),
        "port": str(port_only),
        "protocol_version": "3.1",
        "transport_proto": "udp",
        "subnet_address": f"{SUBNET_BASE}0"
    }
    # Добавляем параметры обфускации, БЕЗ генерации пустых I1-I5
    awg_block.update(obf_params)

    # Формируем финальный JSON, в точности повторяющий рабочий
    data = {
        "containers": [
            {
                "awg": awg_block,
                "container": "amnezia-awg2"
            }
        ],
        "defaultContainer": "amnezia-awg2",
        "description": "AmneziaWG Bot",
        "dns1": dns,
        "dns2": "1.1.1.1",
        "format_version": 1,
        "hostName": host_only,
    }

    json_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
    header = struct.pack(">I", len(json_bytes))
    compressed_data = zlib.compress(json_bytes)
    return f"vpn://{base64.urlsafe_b64encode(header + compressed_data).decode('utf-8').rstrip('=')}"


def build_user_config_and_key(client_privkey: str, client_pubkey: str, client_ip: str, client_psk: str):
    obf_params = get_awg_obfuscation_params()

    # Формируем строки обфускации для текстового конфига
    obf_str = ""
    for k, v in obf_params.items():
        obf_str += f"{k} = {v}\n"

    psk_client_line = f"PresharedKey = {client_psk}\n" if client_psk else ""

    config_content = f"""[Interface]
Address = {client_ip}/32
DNS = {DNS_SERVER}
PrivateKey = {client_privkey}
{obf_str.strip()}

[Peer]
PublicKey = {SERVER_PUBKEY}
{psk_client_line}Endpoint = {SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    vpn_key = generate_amnezia_vpn_key(config_content, SERVER_ENDPOINT, DNS_SERVER, obf_params, client_privkey,
                                       client_pubkey, client_ip, client_psk)
    return config_content, vpn_key


def generate_and_apply_keys(client_ip: str, client_name: str):
    # Внутренний скрипт Amnezia для добавления клиента (add_client.sh)
    # Он сам сгенерирует ключи, добавит в конфиг, обновит clientsTable и применит настройки к интерфейсу.
    # Возвращает JSON с данными нового клиента.

    cmd = f"/opt/amnezia/awg/add_client.sh {shlex.quote(client_name)} {shlex.quote(client_ip + '/32')}"
    try:
        output = run_ssh_container_cmd(cmd)

        # Парсим вывод скрипта
        # В зависимости от версии Amnezia, скрипт может возвращать текст, где нам нужно найти ключи,
        # либо JSON с полным конфигом. Пробуем прочитать JSON:
        try:
            client_data = json.loads(output)
            privkey = client_data.get('privkey') or client_data.get('private_key')
            pubkey = client_data.get('pubkey') or client_data.get('public_key')
        except json.JSONDecodeError:
            # Если не JSON, достаем ключи регулярными выражениями или парсингом строк
            privkey_match = re.search(r'PrivateKey\s*=\s*(.+)', output)
            pubkey_match = re.search(r'PublicKey\s*=\s*(.+)', output)

            if privkey_match and pubkey_match:
                privkey = privkey_match.group(1).strip()
                pubkey = pubkey_match.group(1).strip()
            else:
                raise Exception(f"Не удалось извлечь ключи из вывода скрипта: {output}")

        psk = get_server_psk()
        return privkey, pubkey, psk

    except Exception as e:
        print(f"Ошибка при использовании внутреннего скрипта Amnezia: {e}")
        # Запасной вариант (старый метод, но с исправленным добавлением PSK в файл)
        privkey = run_ssh_container_cmd("awg genkey")
        pubkey = run_ssh_container_cmd(f'sh -c "echo {privkey} | awg pubkey"')
        psk = get_server_psk()

        if psk:
            run_ssh_container_cmd(
                f'sh -c "echo {psk} > /tmp/psk.key && awg set {INTERFACE_NAME} peer \\"{pubkey}\\" preshared-key /tmp/psk.key allowed-ips {client_ip}/32 && rm /tmp/psk.key"'
            )
            conf_peer_block = f"\n[Peer]\nPublicKey = {pubkey}\nPresharedKey = {psk}\nAllowedIPs = {client_ip}/32\n"
        else:
            run_ssh_container_cmd(f'awg set {INTERFACE_NAME} peer "{pubkey}" allowed-ips {client_ip}/32')
            conf_peer_block = f"\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {client_ip}/32\n"

        run_ssh_container_cmd(f'sh -c "printf \'{conf_peer_block}\' >> /opt/amnezia/awg/{INTERFACE_NAME}.conf"')
        return privkey, pubkey, psk


def issue_vpn_key_to_user(user_id: int, name: str, phone: str, username: str = "", about: str = ""):
    add_phone_to_whitelist(phone)

    if not about:
        with db() as cursor:
            cursor.execute("SELECT about FROM pending_requests WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            if row and row[0]:
                about = row[0]

    # Под локом: выбор IP, генерация ключей и запись в БД должны быть атомарны,
    # иначе два одновременных запроса могут получить один и тот же IP.
    with issue_lock:
        client_ip = get_next_free_ip()
        client_privkey, client_pubkey, client_psk = generate_and_apply_keys(client_ip, name)

        with db(commit=True) as cursor:
            cursor.execute(
                "INSERT INTO users (user_id, name, phone, username, ip, pubkey, privkey, about) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, name, phone, username, client_ip, client_pubkey, client_privkey, about),
            )
            cursor.execute("DELETE FROM pending_requests WHERE user_id = ?", (user_id,))

    config_content, vpn_key = build_user_config_and_key(client_privkey, client_pubkey, client_ip, client_psk)
    response_text = (
        f"🎉 <b>Доступ разрешен!</b>\n\n"
        f"👤 <b>Имя:</b> {name}\n"
        f"📞 <b>Номер:</b> <code>{phone}</code>\n"
        f"🌐 <b>Ваш IP:</b> <code>{client_ip}</code>\n\n"
        f"📋 <b>Ваш ключ AmneziaWG (нажмите, чтобы скопировать):</b>\n"
        f"<code>{vpn_key}</code>"
    )
    bot.send_message(user_id, response_text, parse_mode="HTML")
    filename = f"{name.replace(' ', '_')}_Amnezia.conf"
    bot.send_document(chat_id=user_id, document=(filename, config_content.encode("utf-8")))


def restore_users_to_server() -> tuple:
    """Берет пользователей из БД и прописывает их в ядро AWG, конфиг и clientsTable"""
    with db() as cursor:
        cursor.execute("SELECT pubkey, ip, name FROM users WHERE pubkey IS NOT NULL AND ip IS NOT NULL")
        users = cursor.fetchall()

    if not users:
        return 0, 0

    # Все команды ниже выполняются через одно SSH-соединение вместо
    # нового коннекта на каждый вызов (десятки рукопожатий → одно).
    with SSHSession() as ssh:
        # 1. Читаем текущий clientsTable
        try:
            clients_raw = ssh.run("cat /opt/amnezia/awg/clientsTable")
            clients_list = json.loads(clients_raw) if clients_raw else []
        except Exception:
            clients_list = []

        existing_pubkeys_in_json = {c.get("clientId") for c in clients_list}

        # 2. Читаем текущий конфиг awg0.conf
        try:
            conf_content = ssh.run(f"cat /opt/amnezia/awg/{INTERFACE_NAME}.conf")
        except Exception:
            conf_content = ""

        psk = get_server_psk(ssh)
        if psk:
            ssh.run(f'sh -c "echo {psk} > /tmp/psk.key"')

        restored_peers = 0
        conf_append_block = ""

        # 3. Восстанавливаем каждого пользователя
        for pubkey, ip, name in users:
            pubkey_clean = pubkey.strip()
            ip_clean = ip.strip()

            # А. Добавляем пира в активный интерфейс "на лету" (чтобы заработало без перезагрузки)
            try:
                if psk:
                    ssh.run(
                        f'awg set {INTERFACE_NAME} peer "{pubkey_clean}" preshared-key /tmp/psk.key allowed-ips {ip_clean}/32')
                else:
                    ssh.run(f'awg set {INTERFACE_NAME} peer "{pubkey_clean}" allowed-ips {ip_clean}/32')
                restored_peers += 1
            except Exception as e:
                print(f"Ошибка awg set для {pubkey_clean}: {e}")

            # Б. Добавляем в файл conf (для выживания при следующих перезагрузках)
            if pubkey_clean not in conf_content and pubkey_clean not in conf_append_block:
                psk_str = f"PresharedKey = {psk}\n" if psk else ""
                conf_append_block += f"\n[Peer]\nPublicKey = {pubkey_clean}\n{psk_str}AllowedIPs = {ip_clean}/32\n"

            # В. Добавляем в clientsTable (для корректной работы Amnezia)
            if pubkey_clean not in existing_pubkeys_in_json:
                clients_list.append({
                    "clientId": pubkey_clean,
                    "userData": {
                        "allowed_ips": f"{ip_clean}/32",
                        "clientName": name,
                        "creationDate": datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
                        "dataReceived": "0.00 B",
                        "dataSent": "0.00 B",
                        "latestHandshake": ""
                    }
                })
                existing_pubkeys_in_json.add(pubkey_clean)

        if psk:
            ssh.run("rm /tmp/psk.key")

        # 4. Сохраняем дополненный конфиг
        if conf_append_block:
            b64_append = base64.b64encode(conf_append_block.encode("utf-8")).decode("utf-8")
            ssh.run(f'sh -c "echo \'{b64_append}\' | base64 -d >> /opt/amnezia/awg/{INTERFACE_NAME}.conf"')

        # 5. Сохраняем обновленный clientsTable
        try:
            b64_json = base64.b64encode(json.dumps(clients_list, indent=4, ensure_ascii=False).encode("utf-8")).decode(
                "utf-8")
            ssh.run(f'sh -c "echo \'{b64_json}\' | base64 -d > /opt/amnezia/awg/clientsTable"')
        except Exception as e:
            print(f"Ошибка записи clientsTable: {e}")

    return len(users), restored_peers


# === КЛАВИАТУРЫ ===

def get_admin_inline_keyboard():
    keyboard = types.InlineKeyboardMarkup(row_width=1)
    keyboard.add(
        types.InlineKeyboardButton("📋 Белый список номеров", callback_data="admin_wl_menu"),
        types.InlineKeyboardButton("👥 Управление пользователями", callback_data="admin_users_list"),
        types.InlineKeyboardButton("📊 Просмотреть трафик", callback_data="admin_traffic"),
        types.InlineKeyboardButton("🔄 Синхр. БД -> Сервер", callback_data="admin_sync_to_server"),
        types.InlineKeyboardButton("💾 Скачать бэкап БД", callback_data="admin_backup"),
        types.InlineKeyboardButton("♻️ Восстановить из бэкапа", callback_data="admin_restore"),
        types.InlineKeyboardButton("⬅️ Скрыть панель", callback_data="admin_back_to_main"),
    )
    return keyboard


# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И НАЧАЛО РАБОТЫ ===

def send_welcome_message(chat_id, first_name):
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("🚀 Получить доступ к VPN", callback_data="start_reg_flow"))
    welcome_text = (
        f"👋 Здравствуйте, <b>{first_name}</b>!\n\n"
        f"Этот бот предоставляет приватный доступ к VPN-серверу AmneziaWG.\n"
        f"Для получения конфигурации нажмите кнопку ниже:"
    )
    bot.send_message(chat_id, welcome_text, parse_mode="HTML", reply_markup=keyboard)


def send_donation_prompt(chat_id):
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("💳 Показать куда переводить", callback_data="show_donate_info"))
    text = (
        "🍲 <b>Сервера тоже хотят кушать!</b>\n\n"
        "Поддержка работы VPN требует постоянных расходов. "
        "Если вам нравится сервис, вы можете закинуть немного денег им на корм 🐶"
    )
    bot.send_message(chat_id, text, parse_mode="HTML", reply_markup=kb)


@bot.message_handler(commands=["start"])
def start_cmd(message):
    user_states.pop(message.from_user.id, None)
    bot.clear_step_handler_by_chat_id(message.chat.id)
    send_welcome_message(message.chat.id, message.from_user.first_name)


@bot.message_handler(commands=["cancel"])
def cancel_cmd(message):
    user_states.pop(message.from_user.id, None)
    bot.clear_step_handler_by_chat_id(message.chat.id)
    bot.send_message(message.chat.id, "🚫 Действие отменено.", reply_markup=types.ReplyKeyboardRemove())
    send_welcome_message(message.chat.id, message.from_user.first_name)


@bot.message_handler(commands=["register"])
def register_cmd(message):
    user_states.pop(message.from_user.id, None)
    bot.clear_step_handler_by_chat_id(message.chat.id)
    msg = bot.send_message(message.chat.id, "👤 Пожалуйста, введите ваше <b>Имя</b>:", parse_mode="HTML",
                           reply_markup=types.ReplyKeyboardRemove())
    bot.register_next_step_handler(msg, process_name)


@bot.callback_query_handler(func=lambda call: call.data == "start_reg_flow")
def cb_start_registration(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "👤 Пожалуйста, введите ваше <b>Имя</b>:", parse_mode="HTML")
    bot.register_next_step_handler(msg, process_name)


@bot.callback_query_handler(func=lambda call: call.data == "show_donate_info")
def cb_show_donate_info(call):
    bot.answer_callback_query(call.id)
    donate_info = (
        "💳 <b>Реквизиты для поддержки серверов:</b>\n\n"
        f"• <b>Банковская карта / СБП:</b> <code>{ALPHA_CART}</code>\n"
        f"• <b>USDT (ERC20):</b> <code>{USDT}</code>\n\n"
        "Огромное спасибо за поддержку! ❤️"
    )
    bot.send_message(call.message.chat.id, donate_info, parse_mode="HTML")


def process_name(message):
    if message.text and message.text.strip().lower() in ["/cancel", "cancel", "отмена"]:
        cancel_cmd(message)
        return

    name = message.text.strip() if message.text else ""
    if not name or name.startswith("/"):
        msg = bot.send_message(message.chat.id, "⚠️ Пожалуйста, введите имя текстом:")
        bot.register_next_step_handler(msg, process_name)
        return
    if not is_valid_name(name):
        msg = bot.send_message(
            message.chat.id,
            "⚠️ Имя может содержать только буквы, цифры, пробел, точку, дефис и апостроф "
            "(до 64 символов). Пожалуйста, введите имя ещё раз:",
        )
        bot.register_next_step_handler(msg, process_name)
        return

    user_states[message.from_user.id] = {"name": name}
    msg = bot.send_message(
        message.chat.id,
        "📝 Расскажите немного о себе (от кого вы и откуда узнали об этом канале):",
        parse_mode="HTML"
    )
    bot.register_next_step_handler(msg, process_about)


def process_about(message):
    if message.text and message.text.strip().lower() in ["/cancel", "cancel", "отмена"]:
        cancel_cmd(message)
        return

    about_text = message.text.strip() if message.text else ""
    user_id = message.from_user.id
    if user_id not in user_states:
        bot.send_message(message.chat.id, "Пожалуйста, нажмите /start для начала регистрации.")
        return

    user_states[user_id]["about"] = about_text

    keyboard = types.ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
    keyboard.add(types.KeyboardButton(text="📱 Отправить мой номер телефона", request_contact=True))
    bot.send_message(
        message.chat.id,
        "Спасибо! Теперь нажмите кнопку ниже, чтобы отправить номер телефона для авторизации:",
        parse_mode="HTML", reply_markup=keyboard,
    )


@bot.message_handler(content_types=["contact"])
def process_contact(message):
    user_id = message.from_user.id
    if user_id not in user_states:
        bot.send_message(message.chat.id, "Пожалуйста, нажмите /start для начала регистрации.")
        return
    if message.contact.user_id != user_id:
        bot.send_message(message.chat.id, "⚠️ Пожалуйста, отправьте именно СВОЙ контакт.")
        return

    phone = message.contact.phone_number
    if not phone.startswith("+"):
        phone = f"+{phone}"

    user_data = user_states.pop(user_id)
    name = user_data.get("name", "Без имени")
    about = user_data.get("about", "Не указано")
    username = f"@{message.from_user.username}" if message.from_user.username else "Нет юзернейма"

    current_keys = get_user_key_count(phone)
    max_keys = get_max_keys(phone)
    is_extra = current_keys >= max_keys

    if is_phone_whitelisted(phone) and not is_extra:
        bot.send_message(message.chat.id, "✅ Ваш номер найден в белом списке! Выпускаем ключ...",
                         reply_markup=types.ReplyKeyboardRemove())
        issue_vpn_key_to_user(user_id, name, phone, username, about)
        send_donation_prompt(message.chat.id)
        return

    with db(commit=True) as cursor:
        cursor.execute(
            "INSERT OR REPLACE INTO pending_requests (user_id, name, phone, username, is_extra, about) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, name, phone, username, is_extra, about),
        )

    bot.send_message(
        message.chat.id,
        "⏳ <b>Ваша заявка отправлена на согласование администратору.</b>\n\n"
        "Как только администратор подтвердит доступ, вы автоматически получите свой VPN-ключ.",
        parse_mode="HTML", reply_markup=types.ReplyKeyboardRemove(),
    )

    send_donation_prompt(message.chat.id)

    kb_admin = types.InlineKeyboardMarkup(row_width=2)
    kb_admin.add(
        types.InlineKeyboardButton("✅ Одобрить", callback_data=f"approve_{user_id}"),
        types.InlineKeyboardButton("❌ Отклонить", callback_data=f"reject_{user_id}"),
    )

    extra_alert = f"⚠️ <b>ЗАПРОС НА ДОП. КЛЮЧ</b> (Уже есть: {current_keys}/{max_keys})\n\n" if is_extra else ""
    admin_msg = (
        f"📥 <b>Новая заявка на VPN!</b>\n"
        f"{extra_alert}"
        f"👤 <b>Имя:</b> {name}\n"
        f"📱 <b>Телефон:</b> <code>{phone}</code>\n"
        f"💬 <b>Профиль:</b> {username}\n"
        f"ℹ️ <b>О себе:</b> {about}\n"
        f"🆔 <b>ID:</b> <code>{user_id}</code>"
    )

    for admin_id in ADMIN_IDS:
        try:
            bot.send_message(admin_id, admin_msg, parse_mode="HTML", reply_markup=kb_admin)
        except Exception as e:
            print(f"Ошибка отправки админу {admin_id}: {e}")


# === АДМИН-ПАНЕЛЬ ===

@bot.message_handler(commands=["admin"])
def admin_panel_handler(message):
    if not is_admin(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ У вас нет прав для доступа к админ-панели.")
        return
    sync_users_from_server()
    bot.send_message(
        message.chat.id, "⚙️ <b>Панель администратора VPN:</b>\nВыберите необходимое действие:",
        parse_mode="HTML", reply_markup=get_admin_inline_keyboard(),
    )


@bot.callback_query_handler(func=lambda call: call.data.startswith("admin_"))
def admin_callback_handler(call):
    if not is_admin(call.from_user.id):
        return

    action = call.data
    if action == "admin_back_to_main":
        bot.answer_callback_query(call.id)
        bot.delete_message(call.message.chat.id, call.message.message_id)

    elif action == "admin_back_to_panel":
        bot.answer_callback_query(call.id)
        bot.edit_message_text(
            "⚙️ <b>Панель администратора VPN:</b>\nВыберите необходимое действие:",
            chat_id=call.message.chat.id, message_id=call.message.message_id,
            parse_mode="HTML", reply_markup=get_admin_inline_keyboard(),
        )

    elif action == "admin_sync_to_server":
        bot.answer_callback_query(call.id, "Синхронизация запущена... Это займет несколько секунд.")
        try:
            total_users, success = restore_users_to_server()
            bot.send_message(
                call.message.chat.id,
                f"✅ <b>Синхронизация завершена!</b>\n\nПользователей в БД: <b>{total_users}</b>\nУспешно добавлено в ядро сервера: <b>{success}</b>\n\n<i>Теперь пользователи могут подключаться.</i>",
                parse_mode="HTML"
            )
        except Exception as e:
            bot.send_message(call.message.chat.id, f"❌ Ошибка синхронизации: {e}")

    elif action == "admin_backup":
        bot.answer_callback_query(call.id, "Готовлю бэкап...")
        try:
            snapshot = make_db_snapshot()
            try:
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                with open(snapshot, "rb") as f:
                    data = f.read()
            finally:
                os.remove(snapshot)
            # Отправляем бэкап всем админам
            for admin_id in ADMIN_IDS:
                try:
                    bot.send_document(
                        admin_id, (f"vpn_users_{ts}.db", data),
                        caption=f"💾 Бэкап БД от {ts}",
                    )
                except Exception as e:
                    print(f"Ошибка отправки бэкапа админу {admin_id}: {e}")
        except Exception as e:
            bot.send_message(call.message.chat.id, f"❌ Ошибка создания бэкапа: {e}")

    elif action == "admin_restore":
        bot.answer_callback_query(call.id)
        msg = bot.send_message(
            call.message.chat.id,
            "♻️ <b>Восстановление из бэкапа.</b>\n\n"
            "Пришлите файл бэкапа <b>документом</b> (.db, тот, что присылал «Скачать бэкап БД»).\n\n"
            "⚠️ Текущая база будет <b>полностью заменена</b> (прежняя сохранится в страховочную копию).\n"
            "Для отмены — /cancel.",
            parse_mode="HTML",
        )
        bot.register_next_step_handler(msg, process_restore_upload)

    elif action == "admin_wl_menu":
        bot.answer_callback_query(call.id)
        kb = types.InlineKeyboardMarkup(row_width=1)
        kb.add(
            types.InlineKeyboardButton("📜 Список номеров в базе", callback_data="admin_wl_view"),
            types.InlineKeyboardButton("➕ Добавить номер", callback_data="admin_wl_add"),
            types.InlineKeyboardButton("⬅️ Назад в Админ-панель", callback_data="admin_back_to_panel"),
        )
        bot.edit_message_text(
            "📋 <b>Управление Белым списком номеров:</b>",
            chat_id=call.message.chat.id, message_id=call.message.message_id,
            parse_mode="HTML", reply_markup=kb,
        )

    elif action == "admin_wl_view" or action.startswith("admin_wl_del_"):
        if action.startswith("admin_wl_del_"):
            phone_to_del = action.replace("admin_wl_del_", "")
            remove_phone_from_whitelist(phone_to_del)
            bot.answer_callback_query(call.id, f"Удален: {phone_to_del}", show_alert=True)
        else:
            bot.answer_callback_query(call.id)

        phones = get_all_whitelisted_phones()
        kb = types.InlineKeyboardMarkup(row_width=1)
        if not phones:
            kb.add(types.InlineKeyboardButton("⬅️ Назад", callback_data="admin_wl_menu"))
            bot.edit_message_text("📭 <b>Белый список пуст.</b>", chat_id=call.message.chat.id,
                                  message_id=call.message.message_id, parse_mode="HTML", reply_markup=kb)
            return

        with db() as cursor:
            for p in phones:
                cursor.execute("SELECT name, username FROM users WHERE phone = ? LIMIT 1", (p,))
                user_row = cursor.fetchone()
                if user_row:
                    name, username = user_row
                    display_uname = username if username else "—"
                else:
                    name = "Вручную добавлен"
                    display_uname = "—"

                btn_text = f"❌ {p} | {name} | Telegram: {display_uname}"
                kb.add(types.InlineKeyboardButton(btn_text, callback_data=f"admin_wl_del_{p}"))

        kb.add(types.InlineKeyboardButton("⬅️ Назад", callback_data="admin_wl_menu"))
        bot.edit_message_text("📜 <b>Номера в белом списке (с именем и Telegram):</b>", chat_id=call.message.chat.id,
                              message_id=call.message.message_id, parse_mode="HTML", reply_markup=kb)

    elif action == "admin_wl_add":
        bot.answer_callback_query(call.id)
        msg = bot.send_message(call.message.chat.id, "📱 Введите номер телефона (например, <code>+79991112233</code>):",
                               parse_mode="HTML")
        bot.register_next_step_handler(msg, process_add_whitelist_phone)

    elif action == "admin_users_list":
        bot.answer_callback_query(call.id)
        with db() as cursor:
            cursor.execute("SELECT user_id, name, phone FROM users GROUP BY user_id ORDER BY name")
            users = cursor.fetchall()

        if not users:
            bot.send_message(call.message.chat.id, "📭 Нет пользователей!")
            return

        keyboard = types.InlineKeyboardMarkup(row_width=1)
        for uid, name, phone in users:
            keyboard.add(types.InlineKeyboardButton(f"👤 {name} ({phone})", callback_data=f"adm_u_{uid}"))
        keyboard.add(types.InlineKeyboardButton("⬅️ Назад в Админ-панель", callback_data="admin_back_to_panel"))
        bot.edit_message_text(
            "👥 <b>Выберите пользователя для просмотра:</b>",
            chat_id=call.message.chat.id, message_id=call.message.message_id,
            parse_mode="HTML", reply_markup=keyboard,
        )


    elif action == "admin_traffic":
        bot.answer_callback_query(call.id, "Загрузка трафика...")
        update_all_traffic()  # Обязательно обновляем перед показом
        with db() as cursor:
            # Добавлено поле last_reset_total в выборку
            cursor.execute(
                "SELECT user_id, name, ip, pubkey, phone, traffic_month, traffic_total, last_reset_month, last_reset_total FROM users ORDER BY name")
            users = cursor.fetchall()
        if not users:
            bot.send_message(call.message.chat.id, "📭 В базе нет пользователей.")
            return
        total_month = 0
        total_all = 0
        body = ""
        for uid, name, ip, pubkey, phone, t_month, t_total, lr_month, lr_total in users:
            t_month = t_month or 0
            t_total = t_total or 0
            lr_month = lr_month or "Никогда"
            lr_total = lr_total or "Никогда"
            total_month += t_month
            total_all += t_total
            body += f"👤 <b>{name}</b> ({ip})\n"
            body += f"├ За месяц: <b>{format_bytes(t_month)}</b> <i>(сброс: {lr_month})</i>\n"
            body += f"└ Общий: <b>{format_bytes(t_total)}</b> <i>(сброс: {lr_total})</i>\n\n"

        report = (
            "📊 <b>Статистика трафика:</b>\n\n"
            f"🌐 <b>Всего по всем ({len(users)} ключей):</b>\n"
            f"├ За месяц: <b>{format_bytes(total_month)}</b>\n"
            f"└ За всё время: <b>{format_bytes(total_all)}</b>\n\n"
            "➖➖➖➖➖➖➖➖➖➖\n\n"
        )
        report += body
        keyboard = types.InlineKeyboardMarkup(row_width=1)
        keyboard.add(types.InlineKeyboardButton("🔄 Сбросить 'За месяц' у всех", callback_data="admin_reset_all_month"))
        keyboard.add(types.InlineKeyboardButton("🔄 Сбросить 'Общий' у всех", callback_data="admin_reset_all_total"))
        keyboard.add(types.InlineKeyboardButton("⬅️ Назад", callback_data="admin_back_to_panel"))
        bot.edit_message_text(report, chat_id=call.message.chat.id, message_id=call.message.message_id,
                              parse_mode="HTML", reply_markup=keyboard)

    elif action == "admin_reset_all_month":
        now_str = datetime.datetime.now().strftime("%Y-%m-%d")
        with db(commit=True) as cursor:
            cursor.execute("UPDATE users SET traffic_month = 0, last_reset_month = ?", (now_str,))
        bot.answer_callback_query(call.id, "Трафик за месяц сброшен у всех!", show_alert=True)
        call.data = "admin_traffic"
        admin_callback_handler(call)

    elif action == "admin_reset_all_total":
        now_str = datetime.datetime.now().strftime("%Y-%m-%d")
        with db(commit=True) as cursor:
            cursor.execute("UPDATE users SET traffic_total = 0, last_reset_total = ?", (now_str,))
        bot.answer_callback_query(call.id, "Общий трафик сброшен у всех!", show_alert=True)
        call.data = "admin_traffic"
        admin_callback_handler(call)


def process_add_whitelist_phone(message):
    phone = message.text.strip() if message.text else ""
    if not phone.startswith("+"):
        phone = f"+{phone}"
    clean_digits = "".join(filter(str.isdigit, phone))
    if len(clean_digits) < 10:
        bot.send_message(message.chat.id, "⚠️ Некорректный номер. Попробуйте еще раз в панели.")
        return
    add_phone_to_whitelist(phone)
    bot.send_message(message.chat.id, f"✅ Номер <code>{phone}</code> добавлен в белый список!", parse_mode="HTML")


def process_restore_upload(message):
    """Принимает от админа файл бэкапа (.db), валидирует и заменяет текущую БД."""
    if not is_admin(message.from_user.id):
        return
    if message.text and message.text.strip().lower() in ["/cancel", "cancel", "отмена"]:
        bot.send_message(message.chat.id, "🚫 Восстановление отменено.")
        return
    if not message.document:
        msg = bot.send_message(
            message.chat.id,
            "⚠️ Это не файл. Пришлите бэкап <b>документом</b> (.db) или /cancel.",
            parse_mode="HTML",
        )
        bot.register_next_step_handler(msg, process_restore_upload)
        return

    try:
        file_info = bot.get_file(message.document.file_id)
        data = bot.download_file(file_info.file_path)
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Не удалось скачать файл: {e}")
        return

    # Пишем во временный файл в той же директории, что и БД (для атомарной замены),
    # и валидируем прежде, чем что-либо трогать.
    fd, tmp_path = tempfile.mkstemp(prefix="vpn_restore_", suffix=".db", dir=DATA_DIR)
    os.close(fd)
    try:
        with open(tmp_path, "wb") as f:
            f.write(data)

        if not is_valid_db_file(tmp_path):
            os.remove(tmp_path)
            bot.send_message(
                message.chat.id,
                "❌ Файл не похож на корректную базу бота (нет таблицы <code>users</code>). "
                "База <b>не изменена</b>.",
                parse_mode="HTML",
            )
            return

        # Страховочная копия текущей БД перед заменой
        safety = None
        if os.path.exists(DB_PATH):
            safety = f"{DB_PATH}.bak_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(DB_PATH, safety)

        # Заменяем под локом выдачи, чтобы не пересечься с активной записью ключей.
        # os.replace атомарен в пределах одной ФС (tmp создан в DATA_DIR).
        with issue_lock:
            os.replace(tmp_path, DB_PATH)
        init_db()  # домигрируем схему, если бэкап был из более старой версии

        safety_note = (
            f"\nСтраховочная копия прежней БД: <code>{os.path.basename(safety)}</code>"
            if safety else ""
        )
        bot.send_message(
            message.chat.id,
            "✅ <b>База восстановлена из бэкапа.</b>" + safety_note +
            "\n\nНажмите «🔄 Синхр. БД → Сервер» в /admin, чтобы прописать пользователей в AmneziaWG.",
            parse_mode="HTML",
        )
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        bot.send_message(message.chat.id, f"❌ Ошибка восстановления: {e}")


@bot.callback_query_handler(
    func=lambda call: call.data.startswith("adm_u_") or call.data.startswith("adm_exp_") or call.data.startswith(
        "adm_del_") or call.data.startswith("adm_lim_") or call.data.startswith("adm_rst_m_") or call.data.startswith(
        "adm_rst_t_"))
def admin_user_actions_handler(call):
    if not is_admin(call.from_user.id):
        return

    action = call.data

    if action.startswith("adm_u_"):
        bot.answer_callback_query(call.id)
        target_uid = int(action.replace("adm_u_", ""))

        update_all_traffic()  # Считаем свежий трафик перед открытием

        with db() as cursor:
            cursor.execute(
                "SELECT id, name, phone, username, ip, about, traffic_month, traffic_total, last_reset_month, last_reset_total FROM users WHERE user_id = ?",
                (target_uid,))
            user_keys = cursor.fetchall()

        if not user_keys:
            bot.send_message(call.message.chat.id, "Пользователь не найден.")
            return

        name = user_keys[0][1]
        phone = user_keys[0][2]
        username = user_keys[0][3]
        about = user_keys[0][5] if len(user_keys[0]) > 5 and user_keys[0][5] else "Не указано"

        t_month_sum = sum((r[6] or 0) for r in user_keys)
        t_total_sum = sum((r[7] or 0) for r in user_keys)
        lr_month = user_keys[0][8] or "Никогда"
        lr_total = user_keys[0][9] or "Никогда"

        current_keys = get_user_key_count(phone)
        max_keys = get_max_keys(phone)

        text = (
            f"👤 <b>Профиль пользователя:</b>\n"
            f"📝 <b>Имя:</b> {name}\n"
            f"📞 <b>Телефон:</b> <code>{phone}</code>\n"
            f"💬 <b>Telegram:</b> {username}\n"
            f"ℹ️ <b>О себе:</b> {about}\n"
            f"🆔 <b>ID:</b> <code>{target_uid}</code>\n"
            f"🔑 <b>Лимит ключей на номер:</b> {max_keys} (выпущено {current_keys})\n\n"
            f"📊 <b>Трафик:</b>\n"
            f"├ За месяц: <b>{format_bytes(t_month_sum)}</b> <i>(с {lr_month})</i>\n"
            f"└ Общий: <b>{format_bytes(t_total_sum)}</b> <i>(с {lr_total})</i>\n\n"
            f"🌐 <b>Подключенные IP (Ключи):</b>\n"
        )

        keyboard = types.InlineKeyboardMarkup(row_width=1)
        keyboard.add(
            types.InlineKeyboardButton("🔄 Сбросить трафик 'за месяц'", callback_data=f"adm_rst_m_{target_uid}"),
            types.InlineKeyboardButton("🔄 Сбросить 'общий' трафик", callback_data=f"adm_rst_t_{target_uid}"),
            types.InlineKeyboardButton("⚙️ Изменить лимит ключей", callback_data=f"adm_lim_{target_uid}")
        )

        for idx, (db_id, _, _, _, ip, _, _, _, _, _) in enumerate(user_keys, 1):
            text += f"{idx}. <code>{ip}</code>\n"
            keyboard.add(
                types.InlineKeyboardButton(f"📥 Выгрузить ключ {ip}", callback_data=f"adm_exp_{db_id}"),
                types.InlineKeyboardButton(f"❌ Удалить ключ {ip}", callback_data=f"adm_del_{db_id}")
            )

        keyboard.add(types.InlineKeyboardButton("⬅️ Назад к списку", callback_data="admin_users_list"))

        bot.edit_message_text(text, chat_id=call.message.chat.id, message_id=call.message.message_id, parse_mode="HTML",
                              reply_markup=keyboard)

    elif action.startswith("adm_lim_"):
        bot.answer_callback_query(call.id)
        target_uid = int(action.replace("adm_lim_", ""))

        with db() as cursor:
            cursor.execute("SELECT phone FROM users WHERE user_id = ?", (target_uid,))
            phone = cursor.fetchone()[0]

        msg = bot.send_message(
            call.message.chat.id,
            f"Введите новое максимальное количество ключей для номера <code>{phone}</code>:",
            parse_mode="HTML"
        )
        bot.register_next_step_handler(msg, process_change_limit, phone)

    elif action.startswith("adm_exp_"):
        bot.answer_callback_query(call.id, "Подготовка ключа...")
        row_id = int(action.replace("adm_exp_", ""))

        with db() as cursor:
            cursor.execute("SELECT name, phone, ip, privkey, pubkey, user_id FROM users WHERE id = ?", (row_id,))
            row = cursor.fetchone()

        if not row:
            bot.send_message(call.message.chat.id, "❌ Ключ не найден!")
            return

        name, phone, ip, privkey, pubkey, uid = row
        keyboard = types.InlineKeyboardMarkup().add(
            types.InlineKeyboardButton("⬅️ Назад в профиль", callback_data=f"adm_u_{uid}"))

        if not privkey:
            bot.send_message(call.message.chat.id, "⚠️ Нет сохраненного приватного ключа.", reply_markup=keyboard)
            return

        psk = get_server_psk()
        config_content, vpn_key = build_user_config_and_key(privkey, pubkey, ip, psk)

        text = f"🔑 <b>Ключ подключения:</b>\n📞 <code>{phone}</code> | 🌐 <code>{ip}</code>\n\n<code>{vpn_key}</code>"
        bot.send_message(call.message.chat.id, text, parse_mode="HTML", reply_markup=keyboard)
        filename = f"{name.replace(' ', '_')}_{ip}_Amnezia.conf"
        bot.send_document(chat_id=call.message.chat.id, document=(filename, config_content.encode("utf-8")))

    elif action.startswith("adm_del_"):
        bot.answer_callback_query(call.id, "Удаление ключа...")
        row_id = int(action.replace("adm_del_", ""))

        with db(commit=True) as cursor:
            cursor.execute("SELECT name, pubkey, ip, user_id FROM users WHERE id = ?", (row_id,))
            row = cursor.fetchone()

            if row:
                name, pubkey, ip, uid = row
                if pubkey:
                    remove_peer_from_server(pubkey)
                cursor.execute("DELETE FROM users WHERE id = ?", (row_id,))

                keyboard = types.InlineKeyboardMarkup().add(
                    types.InlineKeyboardButton("⬅️ Вернуться в профиль", callback_data=f"adm_u_{uid}"))
                bot.edit_message_text(
                    f"✅ Ключ <b>{ip}</b> пользователя <b>{name}</b> удален!",
                    chat_id=call.message.chat.id, message_id=call.message.message_id,
                    parse_mode="HTML", reply_markup=keyboard,
                )
            else:
                bot.send_message(call.message.chat.id, "❌ Ключ не найден!")
    elif action.startswith("adm_rst_m_"):
        target_uid = int(action.replace("adm_rst_m_", ""))
        now_str = datetime.datetime.now().strftime("%Y-%m-%d")
        with db(commit=True) as cursor:
            cursor.execute("UPDATE users SET traffic_month = 0, last_reset_month = ? WHERE user_id = ?",
                           (now_str, target_uid))
        bot.answer_callback_query(call.id, "Трафик за месяц сброшен!", show_alert=True)
        call.data = f"adm_u_{target_uid}"
        admin_user_actions_handler(call)

    elif action.startswith("adm_rst_t_"):
        target_uid = int(action.replace("adm_rst_t_", ""))
        now_str = datetime.datetime.now().strftime("%Y-%m-%d")
        with db(commit=True) as cursor:
            cursor.execute("UPDATE users SET traffic_total = 0, last_reset_total = ? WHERE user_id = ?",
                           (now_str, target_uid))
        bot.answer_callback_query(call.id, "Общий трафик сброшен!", show_alert=True)
        call.data = f"adm_u_{target_uid}"
        admin_user_actions_handler(call)


def process_change_limit(message, phone):
    try:
        new_limit = int(message.text.strip())
        set_max_keys(phone, new_limit)
        bot.send_message(message.chat.id,
                         f"✅ Лимит для номера <code>{phone}</code> успешно изменен на <b>{new_limit}</b>.",
                         parse_mode="HTML")
    except ValueError:
        bot.send_message(message.chat.id, "❌ Ошибка. Нужно ввести число.")


@bot.callback_query_handler(func=lambda call: call.data.startswith(("approve_", "reject_")))
def admin_approval_decision(call):
    if not is_admin(call.from_user.id):
        return

    action, target_uid = call.data.split("_")
    target_uid = int(target_uid)

    with db() as cursor:
        cursor.execute("SELECT name, phone, username, is_extra, about FROM pending_requests WHERE user_id = ?",
                       (target_uid,))
        req = cursor.fetchone()

    if not req:
        bot.answer_callback_query(call.id, "⚠️ Заявка не найдена.")
        return

    name, phone, username, is_extra, about = req

    if action == "approve":
        bot.answer_callback_query(call.id, "Выдача доступа...")
        try:
            issue_vpn_key_to_user(target_uid, name, phone, username, about)
            bot.edit_message_text(
                f"✅ <b>ЗАЯВКА ОДОБРЕНА</b>\n\n👤 <b>Имя:</b> {name}\n📱 <b>Телефон:</b> <code>{phone}</code>",
                chat_id=call.message.chat.id, message_id=call.message.message_id, parse_mode="HTML",
            )
        except Exception as e:
            bot.send_message(call.message.chat.id, f"❌ Ошибка создания ключа: {e}")

    elif action == "reject":
        bot.answer_callback_query(call.id, "Отклонено")
        with db(commit=True) as cursor:
            cursor.execute("DELETE FROM pending_requests WHERE user_id = ?", (target_uid,))

        bot.edit_message_text(
            f"❌ <b>ЗАЯВКА ОТКЛОНЕНА</b>\n\n👤 <b>Имя:</b> {name}\n📱 <b>Телефон:</b> <code>{phone}</code>",
            chat_id=call.message.chat.id, message_id=call.message.message_id, parse_mode="HTML",
        )
        try:
            bot.send_message(target_uid, "❌ Ваша заявка на получение VPN была отклонена.")
        except Exception:
            pass


if __name__ == "__main__":
    init_db()
    print("Автоматическое восстановление пользователей на сервер...")
    try:
        restore_users_to_server()
        print("Пользователи успешно синхронизированы.")
    except Exception as e:
        print(f"Сбой автосинхронизации: {e}")


    # Запускаем фоновый поток, который каждые 5 минут синхронизирует трафик
    def traffic_saver_thread():
        while True:
            time.sleep(300)  # Раз в 5 минут
            try:
                update_all_traffic()
            except Exception as e:
                print(f"Ошибка фонового обновления трафика: {e}")


    threading.Thread(target=traffic_saver_thread, daemon=True).start()

    bot.remove_webhook()
    print("Бот со всеми обновлениями запущен...")
    bot.infinity_polling()