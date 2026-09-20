"""Telegram moderation bot. Python 3.11+, standard library only."""
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path

LOG = logging.getLogger("antispam")
DEFAULT = {"mode": "observe", "bot_guard": "observe", "links": False, "phrases": [], "trusted": [],
           "flood": 6, "repeat": 3}
HELP = """Антиспам: команды администратора в группе
/setup — подключить чат (только владелец бота)
/settings — настройки
/bots — список bot-аккаунтов и пойманных спамеров
/botguard observe|ban|off — учитывать / сразу удалять / отключить
/botban ID — удалить и заблокировать конкретного бота
/botunban ID — снять блокировку с бота
/botclean confirm — удалить всех обнаруженных недоверенных ботов
/mode observe|delete|ban|off — наблюдение / удаление сообщений / блокировка авторов / пауза
/links on|off — запрет ссылок (по умолчанию выключен)
/phrase add текст — добавить стоп-фразу
/phrase remove текст — убрать стоп-фразу
/trust add ID или /trust remove ID — белый список пользователей
/stats — статистика за сутки и неделю
/recent — последние 10 срабатываний без текста сообщений
/check — проверить права бота
/del — удалить сообщение, на которое ответили
Для канала отправляйте команды в личку: /stats -1001234567890
Аналогично: /setup ID, /mode ID delete, /phrase ID add текст.
Удаление необратимо. Начните с наблюдения и /recent."""


def normalize(text):
    return " ".join("".join(c for c in unicodedata.normalize("NFKC", text).casefold()
                            if unicodedata.category(c) != "Cf").split())


def reason(message, settings, recent):
    text = normalize(message.get("text") or message.get("caption") or "")
    entities = message.get("entities", []) + message.get("caption_entities", [])
    if settings["links"] and (any(e["type"] in {"url", "text_link"} for e in entities)
                              or re.search(r"(?:https?://|www\.|t\.me/|tg://|\b[\w-]+\.(?:ru|com|net|org)\b)", text)):
        return "ссылка"
    if any(normalize(p) in text for p in settings["phrases"]):
        return "стоп-фраза"
    if len(recent) >= settings["flood"] - 1:
        return "флуд"
    digest = hashlib.sha256(text.encode()).hexdigest() if text else ""
    if digest and sum(row[0] == digest for row in recent) >= settings["repeat"] - 1:
        return "повтор"
    return None


class APIError(Exception):
    def __init__(self, code, retry_after=0, description=""):
        message = f"Telegram API error {code}"
        if description:
            message += f": {description}"
        super().__init__(message)
        self.code, self.retry_after, self.description = code, retry_after, description


class API:
    def __init__(self, token):
        self.url = "https://api.telegram.org/bot" + token + "/"

    def call(self, method, **params):
        req = urllib.request.Request(self.url + method,
                                     data=json.dumps(params).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=45) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read())
            except ValueError:
                raise APIError(exc.code) from None
        if not payload.get("ok"):
            raise APIError(payload.get("error_code", 500),
                           payload.get("parameters", {}).get("retry_after", 0),
                           payload.get("description", ""))
        return payload["result"]


class Bot:
    def __init__(self, api, db, owners):
        self.api, self.db, self.owners = api, db, owners
        self.me = api.call("getMe")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS settings(chat INTEGER PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value INTEGER);
        CREATE TABLE IF NOT EXISTS messages(chat INTEGER, mid INTEGER, actor TEXT,
          ts INTEGER, digest TEXT, PRIMARY KEY(chat,mid));
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, chat INTEGER,
          mid INTEGER, ts INTEGER, reason TEXT, action TEXT);
        CREATE TABLE IF NOT EXISTS known_bots(chat INTEGER, uid INTEGER, username TEXT,
          name TEXT, first_seen INTEGER, last_seen INTEGER, status TEXT,
          PRIMARY KEY(chat,uid));
        CREATE TABLE IF NOT EXISTS offenders(chat INTEGER, uid INTEGER, username TEXT,
          name TEXT, first_seen INTEGER, last_seen INTEGER, strikes INTEGER,
          last_reason TEXT, status TEXT, PRIMARY KEY(chat,uid));
        CREATE INDEX IF NOT EXISTS messages_recent ON messages(chat,actor,ts);
        CREATE INDEX IF NOT EXISTS events_recent ON events(chat,ts);
        """)

    def settings(self, chat):
        row = self.db.execute("SELECT value FROM settings WHERE chat=?", (chat,)).fetchone()
        if not row:
            return None
        merged = json.loads(json.dumps(DEFAULT))
        merged.update(json.loads(row[0]))
        return merged

    def save(self, chat, settings):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (chat, json.dumps(settings)))

    def admin(self, chat, user):
        return self.api.call("getChatMember", chat_id=chat, user_id=user)["status"] in {"creator", "administrator"}

    def say(self, chat, text):
        self.api.call("sendMessage", chat_id=chat, text=text[:4000])

    def event(self, chat, mid, why, action):
        with self.db:
            self.db.execute("INSERT INTO events(chat,mid,ts,reason,action) VALUES (?,?,?,?,?)",
                            (chat, mid, int(time.time()), why, action))

    def delete(self, chat, mid, why):
        try:
            self.api.call("deleteMessage", chat_id=chat, message_id=mid)
        except APIError as exc:
            self.event(chat, mid, why, "ошибка удаления")
            LOG.warning("Delete failed chat=%s message=%s code=%s", chat, mid, exc.code)
            if exc.retry_after:
                time.sleep(min(exc.retry_after, 60))
            return False
        self.event(chat, mid, why, "удалено")
        return True

    def remember_bot(self, chat, user, status="seen"):
        now = int(time.time())
        name = " ".join(" ".join(x for x in (user.get("first_name"), user.get("last_name")) if x).split())
        with self.db:
            self.db.execute("""INSERT INTO known_bots VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(chat,uid) DO UPDATE SET username=excluded.username,
                name=excluded.name,last_seen=excluded.last_seen,status=excluded.status""",
                (chat, user["id"], user.get("username", ""), name, now, now, status))

    def remember_offender(self, chat, user, why, status="обнаружен", add_strike=True):
        now = int(time.time())
        name = " ".join(" ".join(x for x in (user.get("first_name"), user.get("last_name")) if x).split())
        strike = 1 if add_strike else 0
        with self.db:
            self.db.execute("""INSERT INTO offenders VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(chat,uid) DO UPDATE SET username=excluded.username,
                name=excluded.name,last_seen=excluded.last_seen,
                strikes=offenders.strikes+excluded.strikes,last_reason=excluded.last_reason,
                status=excluded.status""",
                (chat, user["id"], user.get("username", ""), name, now, now,
                 strike, why, status))

    def mark_account(self, chat, user, status, why=""):
        if user.get("is_bot"):
            self.remember_bot(chat, user, status)
        else:
            self.remember_offender(chat, user, why, status, add_strike=False)

    def ban_account(self, chat, user, config, why="бот-аккаунт"):
        uid = user["id"]
        if uid == self.me["id"] or uid in config["trusted"]:
            self.mark_account(chat, user, "доверенный", why)
            return "trusted"
        try:
            member = self.api.call("getChatMember", chat_id=chat, user_id=uid)
        except APIError as exc:
            self.mark_account(chat, user, "ошибка проверки", why)
            self.event(chat, 0, why, "ошибка проверки бота")
            LOG.warning("Bot lookup failed chat=%s user=%s code=%s", chat, uid, exc.code)
            return "error"
        if member["status"] in {"creator", "administrator"}:
            self.mark_account(chat, user, "администратор", why)
            return "admin"
        if member["status"] in {"left", "kicked"}:
            self.mark_account(chat, user, "заблокирован" if member["status"] == "kicked" else "вышел", why)
            return "absent"
        try:
            self.api.call("banChatMember", chat_id=chat, user_id=uid, revoke_messages=True)
        except APIError as exc:
            self.mark_account(chat, user, "ошибка удаления", why)
            self.event(chat, 0, why, "ошибка удаления бота")
            LOG.warning("Bot ban failed chat=%s user=%s code=%s", chat, uid, exc.code)
            return "error"
        self.mark_account(chat, user, "заблокирован", why)
        self.event(chat, 0, why, "аккаунт заблокирован")
        return "banned"

    def notice_bot(self, chat, user, config, status="обнаружен"):
        if config["bot_guard"] == "off" or not user.get("is_bot") or user["id"] == self.me["id"]:
            return
        self.remember_bot(chat, user, status)
        if config["bot_guard"] == "ban":
            self.ban_account(chat, user, config)

    def command(self, m):
        parts = m.get("text", "").split()
        if not parts or not parts[0].startswith("/"):
            return False
        name, _, mention = parts[0].partition("@")
        if mention and mention.lower() != self.me["username"].lower():
            return False
        if name not in {"/start", "/help", "/setup", "/settings", "/mode", "/links",
                        "/phrase", "/trust", "/stats", "/recent", "/check", "/del",
                        "/bots", "/botguard", "/botban", "/botunban", "/botclean"}:
            return False
        source, user = m["chat"]["id"], m.get("from", {}).get("id")
        if m.get("sender_chat") or not user:
            return False  # anonymous administrators cannot authenticate commands
        args = parts[1:]
        private = m["chat"]["type"] == "private"
        if name in {"/start", "/help"}:
            if private:
                self.say(source, f"Ваш Telegram ID: {user}\n\n" + HELP)
                return True
            return False
        if private:
            if not args or not re.fullmatch(r"-\d+", args[0]):
                self.say(source, "Укажите ID чата после команды.\n" + HELP)
                return True
            target = int(args.pop(0))
        else:
            target = source
        if not self.admin(target, user):
            return False
        config = self.settings(target)
        if name == "/setup":
            if user not in self.owners:
                self.say(source, "Подключить чат может только владелец из OWNER_IDS.")
                return True
            self.save(target, config or dict(DEFAULT))
            self.say(source, "Чат подключён. /settings — настройки; /check — права бота.")
            return True
        if config is None:
            self.say(source, "Сначала владелец бота должен выполнить /setup.")
            return True
        reply = "Настройки сохранены."
        if name == "/settings":
            reply = (f"Защита от ботов: {config['bot_guard']}\nРежим антиспама: {config['mode']}\nЗапрет ссылок: {config['links']}\n"
                     f"Стоп-фразы: {', '.join(config['phrases']) or 'нет'}\n"
                     f"Белый список: {config['trusted']}\nФлуд: 6 сообщений / 15 сек.\nПовторы: 3 / 15 сек.")
        elif name == "/check":
            rights = self.api.call("getChatMember", chat_id=target, user_id=self.me["id"])
            reply = (f"Статус: {rights['status']}\nПраво удаления сообщений: "
                     f"{rights.get('can_delete_messages', False)}\nПраво блокировки участников: "
                     f"{rights.get('can_restrict_members', False)}")
        elif name == "/bots":
            official = [(uid, username, display, "официальный bot", status, seen)
                        for uid, username, display, status, seen in self.db.execute(
                            "SELECT uid,username,name,status,last_seen FROM known_bots WHERE chat=?", (target,))]
            suspects = [(uid, username, display, f"спам: {why} ({strikes})", status, seen)
                        for uid, username, display, strikes, why, status, seen in self.db.execute(
                            """SELECT uid,username,name,strikes,last_reason,status,last_seen
                            FROM offenders WHERE chat=?""", (target,))]
            rows = sorted(official + suspects, key=lambda row: row[-1], reverse=True)[:100]
            reply = ("Обнаруженные боты и спам-аккаунты (до 100):\n" + "\n".join(
                f"{uid} @{username or '—'} {display or '—'} — {kind}; {status}"
                for uid, username, display, kind, status, _ in rows)) if rows else "Боты и спам-аккаунты пока не обнаружены."
        elif name == "/botguard":
            if len(args) != 1 or args[0] not in {"observe", "ban", "off"}:
                reply = "Допустимые значения: observe, ban, off"
            else:
                config["bot_guard"] = args[0]
                self.save(target, config)
                reply = "Защита от ботов: " + args[0]
        elif name in {"/botban", "/botunban"}:
            if len(args) != 1 or not args[0].isdecimal():
                reply = "Укажите числовой ID бота."
            else:
                uid = int(args[0])
                row = self.db.execute("""SELECT username,name,1 FROM known_bots WHERE chat=? AND uid=?
                    UNION ALL SELECT username,name,0 FROM offenders WHERE chat=? AND uid=? LIMIT 1""",
                    (target, uid, target, uid)).fetchone()
                user_data = {"id": uid, "is_bot": bool(row[2]) if row else False, "username": row[0] if row else "",
                             "first_name": row[1] if row else ""}
                if name == "/botban":
                    result = self.ban_account(target, user_data, config, "удаление администратором")
                    reply = {"banned": "Бот удалён и заблокирован.", "trusted": "Бот находится в белом списке.",
                             "admin": "Нельзя удалить бота-администратора: сначала снимите его права.",
                             "absent": "Бота уже нет в группе.",
                             "error": "Не удалось удалить. Проверьте право блокировки участников."}[result]
                else:
                    self.api.call("unbanChatMember", chat_id=target, user_id=uid, only_if_banned=True)
                    self.mark_account(target, user_data, "разблокирован", "разблокирован администратором")
                    reply = "Бот разблокирован; теперь он сможет вступить снова."
        elif name == "/botclean":
            if args != ["confirm"]:
                count = self.db.execute("""SELECT
                    (SELECT count(*) FROM known_bots WHERE chat=? AND status NOT IN ('заблокирован','вышел','доверенный','администратор'))+
                    (SELECT count(*) FROM offenders WHERE chat=? AND status NOT IN ('заблокирован','вышел','доверенный','администратор'))""",
                    (target, target)).fetchone()[0]
                reply = f"Будет обработано ботов: {count}. Для удаления: /botclean confirm"
            else:
                rows = self.db.execute("""SELECT uid,username,name,1 FROM known_bots WHERE chat=?
                    AND status NOT IN ('заблокирован','вышел','доверенный','администратор')
                    UNION ALL SELECT uid,username,name,0 FROM offenders WHERE chat=?
                    AND status NOT IN ('заблокирован','вышел','доверенный','администратор') LIMIT 50""",
                    (target, target)).fetchall()
                results = {"banned": 0, "trusted": 0, "admin": 0, "absent": 0, "error": 0}
                for uid, username, display, is_bot in rows:
                    outcome = self.ban_account(target, {"id": uid, "is_bot": bool(is_bot), "username": username,
                                                       "first_name": display}, config, "массовая очистка")
                    results[outcome] += 1
                remaining = self.db.execute("""SELECT
                    (SELECT count(*) FROM known_bots WHERE chat=? AND status NOT IN ('заблокирован','вышел','доверенный','администратор'))+
                    (SELECT count(*) FROM offenders WHERE chat=? AND status NOT IN ('заблокирован','вышел','доверенный','администратор'))""",
                    (target, target)).fetchone()[0]
                reply = (f"Очистка: удалено {results['banned']}, уже вышли {results['absent']}, "
                         f"доверенных {results['trusted']}, администраторов {results['admin']}, "
                         f"ошибок {results['error']}. Осталось обработать: {remaining}.")
        elif name in {"/mode", "/links"}:
            valid = {"observe", "delete", "ban", "off"} if name == "/mode" else {"on", "off"}
            if len(args) != 1 or args[0] not in valid:
                reply = "Допустимые значения: " + ", ".join(sorted(valid))
            else:
                config[name[1:]] = args[0] if name == "/mode" else args[0] == "on"
                self.save(target, config)
        elif name in {"/phrase", "/trust"}:
            if len(args) < 2 or args[0] not in {"add", "remove"}:
                reply = "Формат: команда add|remove значение"
            else:
                value = normalize(" ".join(args[1:]))
                if name == "/trust":
                    if not value.isdecimal():
                        self.say(source, "Нужен числовой ID пользователя.")
                        return True
                    value = int(value)
                key = "phrases" if name == "/phrase" else "trusted"
                if args[0] == "add" and value and value not in config[key]:
                    config[key].append(value)
                elif args[0] == "remove" and value in config[key]:
                    config[key].remove(value)
                self.save(target, config)
        elif name == "/stats":
            lines = []
            for days in (1, 7):
                since = int(time.time()) - days * 86400
                count = self.db.execute("SELECT count(*) FROM messages WHERE chat=? AND ts>=?", (target, since)).fetchone()[0]
                rows = self.db.execute("SELECT action,count(*) FROM events WHERE chat=? AND ts>=? GROUP BY action", (target, since)).fetchall()
                lines.append(f"За {days} дн.: проверено сообщений {count}; " + (", ".join(f"{a}: {n}" for a, n in rows) or "срабатываний нет"))
            reply = "\n".join(lines) + "\nПравки могут давать несколько срабатываний на сообщение. Время: UTC."
        elif name == "/recent":
            rows = self.db.execute("SELECT mid,reason,action FROM events WHERE chat=? ORDER BY id DESC LIMIT 10", (target,)).fetchall()
            reply = "\n".join(f"Сообщение {mid}: {why} — {action}" for mid, why, action in rows) or "Срабатываний нет."
        elif name == "/del":
            original = m.get("reply_to_message")
            if private or not original:
                reply = "Отправьте /del ответом на сообщение в группе."
            else:
                reply = "Удалено." if self.delete(target, original["message_id"], "вручную") else "Не удалось удалить. Проверьте права и возраст сообщения."
        self.say(source, reply)
        return True

    def handle(self, update):
        if "chat_member" in update:
            change = update["chat_member"]
            chat = change["chat"]["id"]
            config = self.settings(chat)
            user = change["new_chat_member"]["user"]
            status = change["new_chat_member"]["status"]
            if config and config["bot_guard"] != "off" and user.get("is_bot") and user["id"] != self.me["id"]:
                label = ("заблокирован" if status == "kicked" else "вышел" if status == "left" else
                         "администратор" if status in {"administrator", "creator"} else "обнаружен")
                self.remember_bot(chat, user, label)
                if status in {"member", "restricted"} and config["bot_guard"] == "ban":
                    self.ban_account(chat, user, config)
            return
        m = next((update[k] for k in ("message", "edited_message", "channel_post", "edited_channel_post") if k in update), None)
        if not m:
            return
        chat, mid = m["chat"]["id"], m["message_id"]
        if self.command(m) or m["chat"]["type"] == "private":
            return
        config = self.settings(chat)
        if not config:
            return
        for joined in m.get("new_chat_members", []):
            self.notice_bot(chat, joined, config)
        user = m.get("from", {})
        self.notice_bot(chat, user, config)
        if config["mode"] == "off" or m.get("is_automatic_forward"):
            return
        sender, user = m.get("sender_chat"), m.get("from", {})
        if m["chat"]["type"] != "channel":
            if sender and sender["id"] == chat:
                return
            if not sender and (user.get("id") in config["trusted"] or user.get("id") == self.me["id"] or
                               (user.get("id") and self.admin(chat, user["id"]))):
                return
        actor = f"c:{sender['id']}" if sender else f"u:{user.get('id', 0)}"
        now = int(time.time())
        recent = self.db.execute("SELECT digest FROM messages WHERE chat=? AND actor=? AND ts>=? AND mid!=?",
                                 (chat, actor, now - 15, mid)).fetchall()
        # Channel posts share an identity; do not apply per-person flood rules there.
        why = reason(m, config, recent if m["chat"]["type"] != "channel" else [])
        text = normalize(m.get("text") or m.get("caption") or "")
        digest = hashlib.sha256(text.encode()).hexdigest() if text else ""
        with self.db:
            self.db.execute("INSERT INTO messages VALUES (?,?,?,?,?) ON CONFLICT(chat,mid) DO UPDATE SET digest=excluded.digest",
                            (chat, mid, actor, now, digest))
        if why:
            if not sender and user.get("id") and not user.get("is_bot"):
                self.remember_offender(chat, user, why)
            if config["mode"] == "ban" and not sender and user.get("id"):
                self.ban_account(chat, user, config, why)
                self.delete(chat, mid, why)
            elif config["mode"] == "delete":
                self.delete(chat, mid, why)
            else:
                self.event(chat, mid, why, "наблюдение")

    def run(self):
        row = self.db.execute("SELECT value FROM state WHERE key='offset'").fetchone()
        offset = row[0] if row else 0
        while True:
            try:
                updates = self.api.call("getUpdates", offset=offset, timeout=30,
                                        allowed_updates=["message", "edited_message", "channel_post",
                                                         "edited_channel_post", "chat_member"])
                for update in updates:
                    try:
                        self.handle(update)
                    except APIError as exc:
                        if exc.code == 429 or exc.code >= 500:
                            raise
                        LOG.warning("Update %s could not be processed; API code=%s", update["update_id"], exc.code)
                    offset = update["update_id"] + 1
                    with self.db:
                        self.db.execute("INSERT OR REPLACE INTO state VALUES ('offset',?)", (offset,))
                with self.db:
                    for table in ("messages", "events"):
                        self.db.execute(f"DELETE FROM {table} WHERE ts<?", (int(time.time()) - 30 * 86400,))
            except APIError as exc:
                LOG.warning("API error code=%s", exc.code)
                if exc.code in {401, 409}:
                    raise SystemExit("Проверьте токен, webhook и отсутствие второго экземпляра бота.") from None
                time.sleep(min(max(exc.retry_after, 5), 60))
            except (urllib.error.URLError, TimeoutError, OSError):
                LOG.warning("Network unavailable; retrying")
                time.sleep(5)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if Path(".env").exists():
        for line in Path(".env").read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())
    token = os.environ.get("BOT_TOKEN", "")
    if not re.fullmatch(r"\d+:[A-Za-z0-9_-]+", token):
        raise SystemExit("Укажите BOT_TOKEN в .env (см. .env.example).")
    owners = {int(x.strip()) for x in os.environ.get("OWNER_IDS", "").split(",") if x.strip()}
    path = Path(os.environ.get("DB_PATH", "data/bot.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        Bot(API(token), db, owners).run()


if __name__ == "__main__":
    main()
