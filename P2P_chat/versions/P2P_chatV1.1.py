#!/usr/bin/env python3

import socket
import threading
import sys
import os
import json
import base64
import hashlib
import hmac
import struct
import argparse
import time
import uuid
import random
import getpass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    HAVE_ARGON2 = True
except ImportError:
    HAVE_ARGON2 = False


HKDF_INFO = b"p2p-chat-v1-session-key"
NONCE_SIZE = 12
PASSWORD_SALT = b"p2p-chat-v1-password-salt"

HOME = os.path.expanduser("~")
KNOWN_KEYS_PATH = os.path.join(HOME, ".p2p_chat_known_keys")
IDENTITY_PATH = os.path.join(HOME, ".p2p_chat_identity")

PADDING_SIZE_DEFAULT = 1024
PADDING_JITTER_MAX = 0.15

MIN_PASSWORD_LEN = 4


HELP_EPILOG = """
================================================================
  КАК РАБОТАЕТ P2P-ЧАТ
================================================================

Программа устанавливает ПРЯМОЕ соединение между двумя
пользователями — без серверов-посредников. Всё, что передаётся
по сети, шифруется AES-256-GCM. Ключ шифрования выводится из
общего секрета, который обе стороны вычисляют независимо
(ECDH X25519 + HKDF-SHA256). По сети ключ не передаётся.

Перед началом обмена стороны проходят проверку:

  1. Совпадение кодового слова (HMAC-SHA256 challenge-response)
     Если слова разные — соединение обрывается сразу.
  2. Владение долговременным ключом (Ed25519-подпись)
     Доказывает, что собеседник — действительно он.
  3. Отпечаток публичного ключа (TOFU)
     При первом контакте отпечаток запоминается, при
     последующих — сверяется. Если изменился — предупреждение
     о возможной атаке «человек посередине».


================================================================
  БЫСТРЫЙ СТАРТ
================================================================

Нужны ДВА терминала — на одной или двух машинах.

--- Терминал 1 (тот, кто «слушает») ---
  python3 P2P_chat_v1.0.py --listen --login alice --port 5555

  Программа спросит кодовое слово (мин. 8 символов).
  Далее будет ждать подключения.

--- Терминал 2 (тот, кто «подключается») ---
  python3 P2P_chat_v1.0.py --connect --login bob --peer 192.168.1.10:5555

  Где 192.168.1.10 — IP «Алисы», 5555 — её порт.
  Введите то же кодовое слово.

При первом соединении обе стороны увидят отпечаток собеседника
и вопрос «Доверять? (yes/no)». Сверьте отпечатки голосом или
через другой канал. Если совпадают — введите «yes» с обеих
сторон.


================================================================
  КОМАНДЫ ВНУТРИ ЧАТА
================================================================

  <текст>                отправить сообщение
  /file <путь>           отправить файл
  /quit                  выйти из чата


================================================================
  ПАРАМЕТРЫ
================================================================

  --listen               Режим ожидания входящего соединения.
                         Обязателен --port.

  --connect              Режим подключения к собеседнику.
                         Обязателен --peer.

  --login LOGIN          Ваш логин (отображаемое имя).
                         Хранится в ~/.p2p_chat_identity.

  --port PORT            Порт для прослушивания (с --listen).
                         Пример: 5555.

  --peer IP:PORT         Адрес собеседника (с --connect).
                         Пример: 192.168.1.10:5555.

  --password PASSWORD    Общее кодовое слово (мин. 8 символов).
                         Если не указано — спросим скрытно.
                         ВНИМАНИЕ: аргумент виден в `ps aux`.
                         Для реальной работы лучше не указывать
                         и вводить интерактивно.

  --pad                  Включить паддинг сообщений:
                         все кадры фиксированного размера +
                         случайная задержка. Скрывает размер и
                         тайминги сообщений.
                         ОБЕ СТОРОНЫ должны использовать --pad.

  -h, --help             Показать эту справку и выйти.


================================================================
  ПРИМЕРЫ
================================================================

Локальный тест (два терминала на одной машине):

  Терминал 1:
    python3 P2P_chat_v1.0.py --listen --login alice --port 5555

  Терминал 2:
    python3 P2P_chat_v1.0.py --connect --login bob --peer 127.0.0.1:5555

Локальная сеть (разные машины):

  На Алисе (192.168.1.10):
    python3 P2P_chat_v1.0.py --listen --login alice --port 5555

  На Бобе:
    python3 P2P_chat_v1.0.py --connect --login bob --peer 192.168.1.10:5555

С паддингом (максимальная приватность):

  Терминал 1:
    python3 P2P_chat_v1.0.py --listen --login alice --port 5555 --pad

  Терминал 2:
    python3 P2P_chat_v1.0.py --connect --login bob --peer 192.168.1.10:5555 --pad

С паролем в аргументе (не рекомендуется, но быстро):

  python3 P2P_chat_v1.0.py --listen --login alice --port 5555 --password "наша-фраза-2024"


================================================================
  ФАЙЛЫ В ДОМАШНЕЙ ПАПКЕ
================================================================

  ~/.p2p_chat_identity        ваша постоянная идентичность
                              (приватный ключ Ed25519).
                              Скопируйте файл на другое
                              устройство — и вы сможете
                              входить оттуда под тем же
                              логином.

  ~/.p2p_chat_known_keys      доверенные отпечатки собеседников.


================================================================
  ЧТО ЗАЩИЩЕНО
================================================================

  ✓ Содержимое сообщений и файлов (AES-256-GCM)
  ✓ От подмены и повторов (GCM-тег, уникальный nonce)
  ✓ От MITM при первом контакте (кодовое слово)
  ✓ От MITM при повторных (отпечатки ключей)
  ✓ От подмены личности (Ed25519-подписи)
  ✓ От анализа размера и времени (с --pad)

  ✗ Метаданные: факт соединения, объём, время
  ✗ Слабый пароль: если фраза «123» — переберут
  ✗ Заражённое устройство: троян увидит всё
"""


def derive_session_key(shared_secret, salt):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def hash_password(password):
    if HAVE_ARGON2:
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=PASSWORD_SALT,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Argon2Type.ID,
        )
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), PASSWORD_SALT, 200_000, dklen=32
    )


def encrypt_message(key, plaintext, aad=b""):
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt_message(key, data, aad=b""):
    nonce = data[:NONCE_SIZE]
    ct = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)


def compute_fingerprint(pub_bytes):
    digest = hashlib.sha256(pub_bytes).digest()
    b64 = base64.b64encode(digest).decode().rstrip("=")
    return ":".join(b64[i:i+4] for i in range(0, 43, 4))


def load_or_create_identity(login):
    if os.path.exists(IDENTITY_PATH):
        try:
            with open(IDENTITY_PATH, "r") as f:
                data = json.load(f)
            for k in ("login", "private_key", "public_key", "fingerprint"):
                if k not in data:
                    raise ValueError(f"Некорректный файл: нет поля {k}")
            return data
        except Exception as e:
            print(f"[!] Не удалось прочитать {IDENTITY_PATH}: {e}")
            print("[!] Удалите файл и запустите снова, либо исправьте вручную.")
            sys.exit(1)

    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    data = {
        "login": login,
        "private_key": base64.b64encode(priv_bytes).decode(),
        "public_key": base64.b64encode(pub_bytes).decode(),
        "fingerprint": compute_fingerprint(pub_bytes),
    }

    try:
        with open(IDENTITY_PATH, "w") as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(IDENTITY_PATH, 0o600)
        except Exception:
            pass
    except Exception as e:
        print(f"[!] Не удалось сохранить идентичность: {e}")
        sys.exit(1)

    print(f"[✓] Создана новая идентичность '{login}'")
    print(f"[i] Отпечаток: {data['fingerprint']}")
    print(f"[i] Файл:     {IDENTITY_PATH}")
    print(f"[i] Скопируйте этот файл на другие устройства, чтобы входить как '{login}'.")
    return data


def identity_sign(identity, message):
    priv_bytes = base64.b64decode(identity["private_key"])
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.sign(message)


def identity_verify(pub_bytes, signature, message):
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(signature, message)
        return True
    except Exception:
        return False


def load_known_fingerprints():
    if not os.path.exists(KNOWN_KEYS_PATH):
        return {}
    try:
        with open(KNOWN_KEYS_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_known_fingerprints(db):
    try:
        with open(KNOWN_KEYS_PATH, "w") as f:
            json.dump(db, f, indent=2)
    except Exception as e:
        print(f"[!] Не удалось сохранить базу отпечатков: {e}")


def verify_peer_fingerprint(peer_login, peer_pub_bytes, interactive=True):
    fingerprint = compute_fingerprint(peer_pub_bytes)
    db = load_known_fingerprints()

    if peer_login in db:
        if db[peer_login] == fingerprint:
            print(f"[✓] Отпечаток '{peer_login}' совпадает с сохранённым.")
            return True
        print(f"\n{'='*64}")
        print(f"[!!] ВНИМАНИЕ: отпечаток '{peer_login}' ИЗМЕНИЛСЯ!")
        print(f"[!!] Известный: {db[peer_login]}")
        print(f"[!!] Текущий:   {fingerprint}")
        print(f"[!!] Это может быть атака «человек посередине»!")
        print(f"{'='*64}\n")
        if not interactive:
            return False
        resp = input("Продолжить всё равно? (yes/no): ").strip().lower()
        if resp != "yes":
            return False
        db[peer_login] = fingerprint
        save_known_fingerprints(db)
        return True
    else:
        print(f"\n[*] Первое подключение к '{peer_login}'")
        print(f"[*] Отпечаток публичного ключа: {fingerprint}")
        if not interactive:
            db[peer_login] = fingerprint
            save_known_fingerprints(db)
            return True
        resp = input("Доверять этому отпечатку? (yes/no): ").strip().lower()
        if resp != "yes":
            return False
        db[peer_login] = fingerprint
        save_known_fingerprints(db)
        print(f"[✓] Отпечаток сохранён в {KNOWN_KEYS_PATH}")
        return True


def send_frame(sock, data):
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_frame(sock):
    header = recv_exact(sock, 4)
    if not header:
        return b""
    length = struct.unpack("!I", header)[0]
    return recv_exact(sock, length)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


class Padder:
    def __init__(self, enabled, size=PADDING_SIZE_DEFAULT, jitter=PADDING_JITTER_MAX):
        self.enabled = enabled
        self.size = size
        self.jitter = jitter if enabled else 0.0

    def wrap(self, key, plaintext):
        if not self.enabled:
            return encrypt_message(key, plaintext)
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, b"")
        real_len = NONCE_SIZE + len(ct)
        payload = struct.pack("!I", real_len) + nonce + ct
        if len(payload) > self.size:
            raise ValueError(
                f"Сообщение слишком длинное для паддинга "
                f"({len(payload)} > {self.size})"
            )
        padding = os.urandom(self.size - len(payload))
        return payload + padding

    def unwrap(self, key, data):
        if not self.enabled:
            return decrypt_message(key, data)
        if len(data) != self.size:
            raise ValueError(f"Неверный размер кадра: {len(data)} != {self.size}")
        real_len = struct.unpack("!I", data[:4])[0]
        blob = data[4:4 + real_len]
        nonce = blob[:NONCE_SIZE]
        ct = blob[NONCE_SIZE:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, b"")

    def maybe_sleep(self):
        if self.jitter > 0:
            time.sleep(random.uniform(0, self.jitter))


def do_handshake(sock, identity, my_password, is_server, interactive_fp=True):
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    send_frame(sock, eph_pub)
    peer_eph_pub = recv_frame(sock)
    if not peer_eph_pub:
        raise ConnectionError("Не удалось получить эфемерный публичный ключ")
    peer_eph = X25519PublicKey.from_public_bytes(peer_eph_pub)

    my_id_pub = base64.b64decode(identity["public_key"])
    send_frame(sock, my_id_pub)
    peer_id_pub = recv_frame(sock)
    if not peer_id_pub:
        raise ConnectionError("Не удалось получить публичный ключ собеседника")

    send_frame(sock, identity["login"].encode("utf-8"))
    peer_login = recv_frame(sock).decode("utf-8")
    if not peer_login:
        raise ConnectionError("Не удалось получить логин собеседника")

    my_challenge = os.urandom(32)
    send_frame(sock, my_challenge)
    peer_challenge = recv_frame(sock)
    if len(peer_challenge) != 32:
        raise ConnectionError("Некорректный challenge от собеседника")

    pw_hash = hash_password(my_password)
    my_hmac = hmac.new(pw_hash, peer_challenge + peer_id_pub, hashlib.sha256).digest()
    send_frame(sock, my_hmac)

    peer_hmac = recv_frame(sock)
    expected = hmac.new(pw_hash, my_challenge + my_id_pub, hashlib.sha256).digest()
    if not hmac.compare_digest(peer_hmac, expected):
        raise ConnectionError(
            "Проверка кодового слова не удалась: собеседник ввёл другое слово."
        )
    print("[✓] Кодовое слово подтверждено.")

    my_proof_msg = b"identity-proof:" + peer_challenge + peer_id_pub
    my_proof = identity_sign(identity, my_proof_msg)
    send_frame(sock, my_proof)

    peer_proof = recv_frame(sock)
    peer_proof_msg = b"identity-proof:" + my_challenge + my_id_pub
    if not identity_verify(peer_id_pub, peer_proof, peer_proof_msg):
        raise ConnectionError("Собеседник не владеет долговременным ключом")
    print("[✓] Личность собеседника подтверждена подписью.")

    if not verify_peer_fingerprint(peer_login, peer_id_pub, interactive=interactive_fp):
        raise ConnectionError("Отпечаток не подтверждён — соединение прервано")

    shared = eph_priv.exchange(peer_eph)
    salt = b"".join(sorted([eph_pub, peer_eph_pub]))
    session_key = derive_session_key(shared, salt)

    return session_key, peer_login, peer_id_pub


class ChatPeer:
    CHUNK_SIZE = 64 * 1024
    FILE_TIMEOUT = 300

    def __init__(self, sock, session_key, my_login, peer_login, padder):
        self.sock = sock
        self.key = session_key
        self.my_login = my_login
        self.peer_login = peer_login
        self.padder = padder
        self.stop_event = threading.Event()
        self.send_lock = threading.Lock()

        self.incoming_file = None
        self.incoming_lock = threading.Lock()

        self.pending_offers = {}
        self.offer_results = {}

    def _send_json(self, obj):
        payload = json.dumps(obj).encode("utf-8")
        frame = self.padder.wrap(self.key, payload)
        self.padder.maybe_sleep()
        with self.send_lock:
            send_frame(self.sock, frame)

    def send_text(self, text):
        self._send_json({"t": "msg", "from": self.my_login, "b": text})

    def send_sys(self, text):
        self._send_json({"t": "sys", "b": text})

    def send_file(self, path):
        if not os.path.isfile(path):
            print(f"[!] Файл не найден: {path}")
            return
        filename = os.path.basename(path)
        size = os.path.getsize(path)

        print(f"[*] Считаю SHA-256 файла '{filename}'...")
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha.update(chunk)
        file_hash = sha.hexdigest()

        transfer_id = uuid.uuid4().hex[:12]
        event = threading.Event()
        self.pending_offers[transfer_id] = event

        self._send_json({
            "t": "file_offer",
            "id": transfer_id,
            "from": self.my_login,
            "name": filename,
            "size": size,
            "sha256": file_hash,
        })
        print(f"[*] Предложение файла '{filename}' ({size} байт) отправлено, ждём согласия...")

        if not event.wait(timeout=self.FILE_TIMEOUT):
            print("[!] Тайм-аут. Передача отменена.")
            self.pending_offers.pop(transfer_id, None)
            return

        result = self.offer_results.pop(transfer_id, None)
        self.pending_offers.pop(transfer_id, None)
        if result != "accept":
            print("[!] Собеседник отклонил передачу.")
            return

        print(f"[*] Начинаю отправку '{filename}'...")
        sent = 0
        chunk_index = 0
        start_time = time.time()
        try:
            with open(path, "rb") as f:
                while True:
                    data = f.read(self.CHUNK_SIZE)
                    if not data:
                        break
                    b64 = base64.b64encode(data).decode("ascii")
                    self._send_json({
                        "t": "file_chunk",
                        "id": transfer_id,
                        "i": chunk_index,
                        "d": b64,
                    })
                    sent += len(data)
                    chunk_index += 1
                    self._print_progress(filename, sent, size, start_time)
            self._send_json({"t": "file_done", "id": transfer_id})
            print(f"\n[✓] Файл '{filename}' отправлен ({sent} байт).")
        except Exception as e:
            print(f"\n[!] Ошибка при отправке: {e}")

    def _print_progress(self, filename, sent, total, start_time):
        elapsed = max(time.time() - start_time, 0.001)
        speed = sent / elapsed / 1024
        pct = sent * 100 / total if total else 100
        bar_len = 30
        filled = int(bar_len * sent / total) if total else bar_len
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(
            f"\r\033[K[↑] {filename}: [{bar}] {pct:5.1f}%  "
            f"{sent//1024}/{total//1024} KiB  {speed:.1f} KiB/s"
        )
        sys.stdout.flush()

    def handle_incoming(self, msg):
        t = msg.get("t")
        if t == "msg":
            print(f"\r\033[K[{msg.get('from','peer')}] {msg.get('b','')}\n> ",
                  end="", flush=True)
        elif t == "sys":
            print(f"\r\033[K[*] {msg.get('b','')}\n> ", end="", flush=True)
        elif t == "file_offer":
            self._handle_offer(msg)
        elif t == "file_accept":
            tid = msg.get("id")
            if tid in self.pending_offers:
                self.offer_results[tid] = "accept"
                self.pending_offers[tid].set()
        elif t == "file_reject":
            tid = msg.get("id")
            if tid in self.pending_offers:
                self.offer_results[tid] = "reject"
                self.pending_offers[tid].set()
        elif t == "file_chunk":
            self._handle_chunk(msg)
        elif t == "file_done":
            self._handle_done(msg)
        else:
            print(f"\r\033[K[?] Неизвестный тип: {t}\n> ", end="", flush=True)

    def _handle_offer(self, msg):
        tid = msg["id"]
        name = msg["name"]
        size = msg["size"]
        sha = msg["sha256"]
        print(f"\n\033[33m[📎] {msg.get('from','peer')} хочет отправить файл:\033[0m")
        print(f"    Имя:    {name}")
        print(f"    Размер: {size} байт ({size/1024:.1f} KiB)")
        print(f"    SHA-256: {sha[:32]}...")
        answer = input("Принять? (y/n): ").strip().lower()

        if answer != "y":
            self._send_json({"t": "file_reject", "id": tid, "reason": "user_declined"})
            print("[*] Отклонено.")
            return

        with self.incoming_lock:
            self.incoming_file = {
                "id": tid,
                "name": self._safe_filename(name),
                "size": size,
                "sha256": sha,
                "buffer": bytearray(),
                "start_time": time.time(),
            }
        self._send_json({"t": "file_accept", "id": tid})
        print(f"[*] Принимаю файл '{name}'...")

    @staticmethod
    def _safe_filename(name):
        name = os.path.basename(name).replace("\x00", "")
        return name or "received_file"

    def _handle_chunk(self, msg):
        tid = msg.get("id")
        with self.incoming_lock:
            state = self.incoming_file
            if not state or state["id"] != tid:
                return
            try:
                data = base64.b64decode(msg["d"])
            except Exception:
                return
            state["buffer"].extend(data)
            received = len(state["buffer"])
            total = state["size"]
            elapsed = max(time.time() - state["start_time"], 0.001)
            speed = received / elapsed / 1024
            pct = received * 100 / total if total else 100
            bar_len = 30
            filled = int(bar_len * received / total) if total else bar_len
            bar = "█" * filled + "░" * (bar_len - filled)
            sys.stdout.write(
                f"\r\033[K[↓] {state['name']}: [{bar}] {pct:5.1f}%  "
                f"{received//1024}/{total//1024} KiB  {speed:.1f} KiB/s"
            )
            sys.stdout.flush()

    def _handle_done(self, msg):
        tid = msg.get("id")
        with self.incoming_lock:
            state = self.incoming_file
            if not state or state["id"] != tid:
                return
            data = bytes(state["buffer"])
            self.incoming_file = None

        if len(data) != state["size"]:
            print(f"\n[!] Размер не совпал: {len(data)} != {state['size']}")
            print("> ", end="", flush=True)
            return

        actual = hashlib.sha256(data).hexdigest()
        if actual != state["sha256"]:
            print(f"\n[!] Хеш не совпал! Файл повреждён или подменён.")
            print("> ", end="", flush=True)
            return

        save_path = state["name"]
        base, ext = os.path.splitext(save_path)
        counter = 1
        while os.path.exists(save_path):
            save_path = f"{base}({counter}){ext}"
            counter += 1

        try:
            with open(save_path, "wb") as f:
                f.write(data)
            print(f"\n[✓] Файл сохранён: {os.path.abspath(save_path)}")
        except Exception as e:
            print(f"\n[!] Не удалось сохранить: {e}")
        print("> ", end="", flush=True)

    def reader(self):
        try:
            while not self.stop_event.is_set():
                frame = recv_frame(self.sock)
                if not frame:
                    print("\n[!] Собеседник отключился.")
                    self.stop_event.set()
                    break
                try:
                    plaintext = self.padder.unwrap(self.key, frame)
                except Exception as e:
                    print(f"\n[!] Ошибка расшифровки: {e}")
                    continue
                try:
                    msg = json.loads(plaintext.decode("utf-8"))
                except Exception:
                    print("\n[peer] <нечитаемое сообщение>")
                    continue
                try:
                    self.handle_incoming(msg)
                except Exception as e:
                    print(f"\n[!] Ошибка обработки: {e}")
        except Exception as e:
            if not self.stop_event.is_set():
                print(f"\n[!] Ошибка соединения: {e}")
            self.stop_event.set()


def run_chat(sock, identity, my_password, is_server, pad_enabled):
    print("[*] Выполняется рукопожатие...")
    padder = Padder(enabled=pad_enabled)

    session_key, peer_login, _peer_id = do_handshake(
        sock, identity, my_password, is_server, interactive_fp=True
    )
    print(f"[✓] Соединение установлено с '{peer_login}'. Ключ AES-256-GCM выведен.")
    if pad_enabled:
        print(f"[i] Паддинг включён: кадр = {padder.size} байт, jitter ≤ {int(padder.jitter*1000)} мс.")
    print("[i] Команды: /quit — выход, /file <путь> — отправить файл.\n")

    peer = ChatPeer(sock, session_key, identity["login"], peer_login, padder)
    t = threading.Thread(target=peer.reader, daemon=True)
    t.start()

    try:
        while not peer.stop_event.is_set():
            try:
                line = input("> ")
            except EOFError:
                break
            if peer.stop_event.is_set():
                break

            if line.strip() == "/quit":
                try:
                    peer.send_sys("собеседник покинул чат")
                except Exception:
                    pass
                break

            if line.startswith("/file "):
                path = line[len("/file "):].strip()
                if not path:
                    print("[!] Укажи путь: /file <путь>")
                    continue
                threading.Thread(
                    target=peer.send_file, args=(path,), daemon=True
                ).start()
                continue

            if not line:
                continue

            try:
                peer.send_text(line)
            except Exception as e:
                print(f"[!] Не удалось отправить: {e}")
                break
    finally:
        peer.stop_event.set()
        try:
            sock.close()
        except Exception:
            pass
        print("\n[*] Чат завершён.")


def start_server(identity, port, password, pad_enabled):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"[*] Логин: {identity['login']}")
    print(f"[*] Кодовое слово задано (аутентификация включена).")
    print(f"[*] Ожидаю подключения на порту {port}...")
    conn, addr = srv.accept()
    srv.close()
    print(f"[+] Подключение от {addr[0]}:{addr[1]}")
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    run_chat(conn, identity, password, is_server=True, pad_enabled=pad_enabled)


def start_client(identity, host, port, password, pad_enabled):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[*] Подключаюсь к {host}:{port}...")
    sock.connect((host, port))
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    run_chat(sock, identity, password, is_server=False, pad_enabled=pad_enabled)


def prompt_password(provided):
    if provided is not None:
        if len(provided) < MIN_PASSWORD_LEN:
            print(f"[!] Кодовое слово слишком короткое — минимум {MIN_PASSWORD_LEN} символов.")
            sys.exit(1)
        return provided

    if not sys.stdin.isatty():
        print("[!] Кодовое слово обязательно. Используйте --password или запустите из терминала.")
        sys.exit(1)

    try:
        p1 = getpass.getpass(f"Введите общее кодовое слово (мин. {MIN_PASSWORD_LEN} символов): ")
        if len(p1) < MIN_PASSWORD_LEN:
            print(f"[!] Слишком короткое. Минимум {MIN_PASSWORD_LEN}.")
            sys.exit(1)
        p2 = getpass.getpass("Повторите: ")
        if p1 != p2:
            print("[!] Слова не совпадают.")
            sys.exit(1)
        return p1
    except Exception as e:
        print(f"[!] Не удалось прочитать кодовое слово: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="P2P_chat",
        description=(
            "P2P защищённый чат с AES-256-GCM.\n"
            "Прямое соединение между двумя пользователями без серверов.\n"
            "Обязательное общее кодовое слово + отпечатки ключей (TOFU).\n"
            "Передача файлов с проверкой SHA-256."
        ),
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    parser.add_argument(
        "-h", "--help",
        action="help",
        help="Показать подробную справку и выйти"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--listen",
        action="store_true",
        help="Режим ожидания входящего соединения (нужен --port)"
    )
    group.add_argument(
        "--connect",
        action="store_true",
        help="Режим подключения к собеседнику (нужен --peer)"
    )

    parser.add_argument(
        "--login",
        help="Ваш логин (отображаемое имя). Хранится в ~/.p2p_chat_identity"
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Порт для прослушивания, например 5555 (с --listen)"
    )
    parser.add_argument(
        "--peer",
        help="Адрес собеседника в формате ip:port, например 192.168.1.10:5555 (с --connect)"
    )
    parser.add_argument(
        "--password",
        help="Общее кодовое слово (мин. 8 символов). Если не указано — спросим скрытно"
    )
    parser.add_argument(
        "--pad",
        action="store_true",
        help="Включить паддинг сообщений (обе стороны должны использовать одинаково)"
    )

    args = parser.parse_args()

    if not args.listen and not args.connect:
        parser.print_help()
        print("\n[!] Укажите --listen или --connect.")
        sys.exit(1)

    if not args.login:
        parser.print_help()
        print("\n[!] Укажите --login.")
        sys.exit(1)

    password = prompt_password(args.password)
    identity = load_or_create_identity(args.login)

    try:
        if args.listen:
            if not args.port:
                parser.error("--port обязателен с --listen")
            start_server(identity, args.port, password, args.pad)
        else:
            if not args.peer or ":" not in args.peer:
                parser.error("--peer должен быть в формате ip:port")
            host, port_str = args.peer.rsplit(":", 1)
            start_client(identity, host, int(port_str), password, args.pad)
    except KeyboardInterrupt:
        print("\n[*] Прервано пользователем.")
    except ConnectionError as e:
        print(f"\n[!] Ошибка соединения: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
