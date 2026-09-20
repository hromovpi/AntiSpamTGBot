"""Audit recent channel members through MTProto and optionally ban approved IDs."""
import argparse
import asyncio
import csv
import json
import os
import re
import sys
from collections import Counter
from datetime import date, datetime, time, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from bot import API, APIError

SEARCH_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789абвгдеёжзийклмнопрстуфхцчшщъыьэюяіїєґ"
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def progress_bar(done, pending, found, label="", width=28):
    total = done + pending
    ratio = done / total if total else 1.0
    filled = min(width, round(width * ratio))
    bar = "█" * filled + "░" * (width - filled)
    percent = round(ratio * 100)
    suffix = f" · {label}" if label else ""
    return f"[{bar}] {percent:3d}% · запросов {done}/{total} · найдено {found}{suffix}"


class ProgressDisplay:
    def __init__(self, enabled=True, stream=None):
        self.stream = stream or sys.stdout
        self.enabled = enabled and self.stream.isatty()
        self.visible = False

    def _write(self, text):
        if self.enabled:
            self.stream.write("\r\033[K" + text)
            self.stream.flush()
            self.visible = True

    def sweep(self, done, pending, found, prefix):
        self._write(progress_bar(done, pending, found, f"префикс: {prefix}"))

    def events(self, count, found, event_date=None):
        if count % 10 and count != 1:
            return
        spinner = SPINNER[count % len(SPINNER)]
        when = f" · {event_date:%Y-%m-%d %H:%M:%S}" if event_date else ""
        self._write(f"{spinner} событий прочитано {count} · уникальных аккаунтов {found}{when}")

    def finish_sweep(self, done, found):
        self._write(progress_bar(done, 0, found, "готово"))
        self.close()

    def finish_events(self, count, found):
        self._write(f"✓ событий прочитано {count} · уникальных аккаунтов {found} · готово")
        self.close()

    def close(self):
        if self.enabled and self.visible:
            self.stream.write("\n")
            self.stream.flush()
            self.visible = False


def load_env(path=Path(".env")):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def parse_chat(value):
    return int(value) if re.fullmatch(r"-\d+", value) else value


def start_time(value, timezone_name):
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"Неизвестная таймзона: {timezone_name}") from exc
    selected = datetime.now(zone).date() if value == "today" else date.fromisoformat(value)
    return datetime.combine(selected, time.min, zone).astimezone(timezone.utc), zone


def safe_cell(value):
    value = str(value or "").replace("\r", " ").replace("\n", " ")
    return "'" + value if value.startswith(("=", "+", "-", "@")) else value


def risk(user, burst, is_admin=False):
    reasons = []
    score = 0
    username = user.get("username") or ""
    if user.get("bot"):
        score += 100
        reasons.append("официальный bot-аккаунт")
    if user.get("deleted"):
        score += 4
        reasons.append("удалённый аккаунт")
    if not user.get("photo"):
        score += 1
        reasons.append("нет фото")
    if not username:
        score += 1
        reasons.append("нет username")
    elif sum(ch.isdigit() for ch in username) >= 5:
        score += 1
        reasons.append("много цифр в username")
    if not (user.get("first_name") or user.get("last_name")):
        score += 2
        reasons.append("нет имени")
    if burst >= 50:
        score += 3
        reasons.append(f"массовое вступление: {burst}/мин")
    elif burst >= 10:
        score += 2
        reasons.append(f"массовое вступление: {burst}/мин")
    if is_admin:
        reasons.append("администратор — исключён")
    return score, reasons, score >= 4 and not is_admin


def read_approved(path):
    result = []
    seen = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if not line.isdecimal():
            raise ValueError(f"Строка {number}: ожидается только числовой Telegram ID")
        uid = int(line)
        if uid not in seen:
            seen.add(uid)
            result.append(uid)
    return result


def rotate_session(session):
    source = Path(str(session) + ".session")
    if not source.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = source.with_name(source.name + f".backup-{stamp}")
    source.replace(backup)
    return backup


async def resolve_chat(client, target):
    try:
        return await client.get_entity(target)
    except (ValueError, TypeError):
        if not isinstance(target, int):
            raise
        from telethon import utils
        async for dialog in client.iter_dialogs():
            if utils.get_peer_id(dialog.entity) == target:
                return dialog.entity
        raise ValueError("Канал не найден среди диалогов бота. Проверьте ID и права администратора.")


async def collect(client, channel, since):
    from telethon.tl.types import ChannelParticipantsRecent
    records = {}
    async for entity in client.iter_participants(channel, limit=None, filter=ChannelParticipantsRecent):
        participant = getattr(entity, "participant", None)
        joined = getattr(participant, "date", None)
        if joined is None:
            continue
        joined = joined if joined.tzinfo else joined.replace(tzinfo=timezone.utc)
        if joined < since:
            continue
        records[entity.id] = {
            "id": entity.id, "joined_at": joined, "joins": 1, "source": {"recent_members"},
            "username": getattr(entity, "username", None) or "",
            "first_name": getattr(entity, "first_name", None) or "",
            "last_name": getattr(entity, "last_name", None) or "",
            "bot": bool(getattr(entity, "bot", False)),
            "deleted": bool(getattr(entity, "deleted", False)),
            "photo": getattr(entity, "photo", None) is not None,
        }
    return list(records.values())


def participant_row(entity, since, source):
    participant = getattr(entity, "participant", None)
    joined = getattr(participant, "date", None)
    if joined is None:
        return None
    joined = joined if joined.tzinfo else joined.replace(tzinfo=timezone.utc)
    if joined < since:
        return None
    return {
        "id": entity.id, "joined_at": joined, "joins": 1, "source": {source},
        "username": getattr(entity, "username", None) or "",
        "first_name": getattr(entity, "first_name", None) or "",
        "last_name": getattr(entity, "last_name", None) or "",
        "bot": bool(getattr(entity, "bot", False)),
        "deleted": bool(getattr(entity, "deleted", False)),
        "photo": getattr(entity, "photo", None) is not None,
    }


def merge_record(records, row):
    if row is None:
        return
    previous = records.get(row["id"])
    if previous is None:
        records[row["id"]] = row
    else:
        previous["joined_at"] = min(previous["joined_at"], row["joined_at"])
        previous["source"].update(row["source"])


async def collect_search_sweep(client, channel, since, initial, max_queries=500, progress=None):
    """Best-effort partitioning of Telegram's capped participant search results."""
    records = {row["id"]: row for row in initial}
    queue = list(SEARCH_ALPHABET)
    queries = 0
    saturated = []
    while queue and queries < max_queries:
        prefix = queue.pop(0)
        users = await client.get_participants(channel, limit=None, search=prefix)
        queries += 1
        for entity in users:
            merge_record(records, participant_row(entity, since, f"search:{prefix}"))
        if len(users) >= 200:
            if len(prefix) < 3 and len(queue) + queries + len(SEARCH_ALPHABET) <= max_queries:
                queue.extend(prefix + char for char in SEARCH_ALPHABET)
            else:
                saturated.append(prefix)
        if progress:
            progress.sweep(queries, len(queue), len(records), prefix)
    if progress:
        progress.finish_sweep(queries, len(records))
    return list(records.values()), queries, saturated, len(queue)


async def collect_admin_log(client, channel, since, progress=None):
    """Collect all join events since a date. Telegram permits this only for user accounts."""
    records = {}
    events_read = 0
    async for event in client.iter_admin_log(channel, limit=None, join=True, invite=True):
        event_date = event.date if event.date.tzinfo else event.date.replace(tzinfo=timezone.utc)
        if event_date < since:
            break
        events_read += 1
        participant = getattr(event.action, "participant", None)
        uid = getattr(participant, "user_id", None) or event.user_id
        try:
            entity = await client.get_entity(uid)
        except (ValueError, TypeError):
            entity = None
        row = records.setdefault(uid, {
            "id": uid, "joined_at": event_date, "joins": 0, "source": set(),
            "username": "", "first_name": "", "last_name": "", "bot": False,
            "deleted": False, "photo": False,
        })
        row["joined_at"] = min(row["joined_at"], event_date)
        row["joins"] += 1
        row["source"].add("invite" if event.joined_invite else "public")
        if entity is not None:
            for key in ("username", "first_name", "last_name"):
                row[key] = getattr(entity, key, None) or ""
            row["bot"] = bool(getattr(entity, "bot", False))
            row["deleted"] = bool(getattr(entity, "deleted", False))
            row["photo"] = getattr(entity, "photo", None) is not None
        if progress:
            progress.events(events_read, len(records), event_date)
    if progress:
        progress.finish_events(events_read, len(records))
    return list(records.values())


def write_reports(records, admins, zone, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(zone).strftime("%Y%m%d-%H%M%S")
    csv_path = output_dir / f"joins-{stamp}.csv"
    approval_path = output_dir / f"approved-ids-{stamp}.txt"
    minute_counts = Counter(r["joined_at"].replace(second=0, microsecond=0) for r in records)
    prepared = []
    for row in records:
        burst = minute_counts[row["joined_at"].replace(second=0, microsecond=0)]
        score, reasons, candidate = risk(row, burst, row["id"] in admins)
        prepared.append({**row, "burst": burst, "score": score, "reasons": reasons,
                         "candidate": candidate, "is_admin": row["id"] in admins})
    prepared.sort(key=lambda r: (-r["score"], r["joined_at"]))
    fields = ["id", "joined_at", "username", "first_name", "last_name", "official_bot",
              "deleted", "has_photo", "joins", "joins_same_minute", "risk_score",
              "candidate", "is_admin", "source", "reasons"]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in prepared:
            writer.writerow({
                "id": row["id"], "joined_at": row["joined_at"].astimezone(zone).isoformat(),
                "username": safe_cell(row["username"]), "first_name": safe_cell(row["first_name"]),
                "last_name": safe_cell(row["last_name"]), "official_bot": row["bot"],
                "deleted": row["deleted"], "has_photo": row["photo"], "joins": row["joins"],
                "joins_same_minute": row["burst"], "risk_score": row["score"],
                "candidate": row["candidate"], "is_admin": row["is_admin"],
                "source": "+".join(sorted(row["source"])), "reasons": "; ".join(row["reasons"]),
            })
    with approval_path.open("w", encoding="utf-8") as stream:
        stream.write("# Проверьте CSV. Для одобренных удалений уберите '# ' перед ID.\n")
        stream.write("# Строки с # игнорируются. Один числовой ID на строку.\n")
        for row in prepared:
            if row["candidate"]:
                name = " ".join(x for x in (row["first_name"], row["last_name"]) if x)
                stream.write(f"# {row['id']}  # @{row['username'] or '—'} {name or '—'}; "
                             f"риск {row['score']}: {', '.join(row['reasons'])}\n")
    return csv_path, approval_path, prepared


def ban_approved(api, chat, ids, known_ids, audit_path):
    unknown = [uid for uid in ids if uid not in known_ids]
    if unknown:
        raise ValueError("В approved-файле есть ID не из текущего отчёта: " + ", ".join(map(str, unknown[:10])))
    results = []
    for uid in ids:
        try:
            api.call("banChatMember", chat_id=chat, user_id=uid, revoke_messages=True)
            results.append({"id": uid, "result": "banned"})
        except APIError as exc:
            results.append({"id": uid, "result": "error", "code": exc.code})
    audit_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    return results


async def async_main(args):
    try:
        from telethon import TelegramClient
    except ImportError:
        raise SystemExit("Не установлен Telethon. Выполните: python3 -m pip install -r requirements-scan.txt")
    load_env()
    if args.full_log and args.search_sweep:
        raise SystemExit("Выберите один режим: --full-log или --search-sweep")
    if not 1 <= args.max_search_queries <= 4000:
        raise SystemExit("--max-search-queries должен быть от 1 до 4000")
    token = os.environ.get("BOT_TOKEN", "")
    api_hash = os.environ.get("TELEGRAM_API_HASH", "")
    try:
        api_id = int(os.environ.get("TELEGRAM_API_ID", ""))
    except ValueError:
        raise SystemExit("Укажите числовой TELEGRAM_API_ID в .env") from None
    if not token or not api_hash:
        raise SystemExit("Укажите BOT_TOKEN, TELEGRAM_API_ID и TELEGRAM_API_HASH в .env")
    try:
        since, zone = start_time(args.since, args.timezone or os.environ.get("TIMEZONE", "Europe/Saratov"))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    target = parse_chat(args.chat)
    bot_api = API(token)
    me = bot_api.call("getMe")
    rights = bot_api.call("getChatMember", chat_id=target, user_id=me["id"])
    if rights.get("status") != "creator" and not rights.get("can_restrict_members"):
        raise SystemExit("У бота нет права блокировать участников этого канала.")
    admins = {item["user"]["id"] for item in bot_api.call(
        "getChatAdministrators", chat_id=target, return_bots=True)}
    session_key = "USER_MTProto_SESSION" if args.full_log else "MTProto_SESSION"
    session_default = "data/mtproto_admin" if args.full_log else "data/mtproto_bot"
    session = Path(os.environ.get(session_key, session_default))
    session.parent.mkdir(parents=True, exist_ok=True)
    if args.reset_user_session:
        if not args.full_log:
            raise SystemExit("--reset-user-session используется только вместе с --full-log")
        backup = rotate_session(session)
        print(f"Предыдущая сессия перемещена в {backup}" if backup else "Сохранённой пользовательской сессии не было.")
    client = TelegramClient(str(session), api_id, api_hash, receive_updates=False)
    progress = ProgressDisplay(enabled=not args.no_progress)
    if args.full_log:
        print("Полный режим: войдите личным аккаунтом — администратором канала.")
        print("Код и пароль 2FA вводятся локально в Telethon и не записываются в отчёт.")
        await client.start(phone=lambda: input("Введите номер личного аккаунта в формате +7...: ").strip())
        identity = await client.get_me()
        if identity.bot:
            await client.disconnect()
            raise SystemExit("Выполнен вход bot-аккаунтом. Перезапустите с --full-log --reset-user-session "
                             "и введите номер телефона личного администратора, а не BOT_TOKEN.")
    else:
        await client.start(bot_token=token)
    try:
        channel = await resolve_chat(client, target)
        if args.full_log:
            records = await collect_admin_log(client, channel, since, progress)
            sweep_info = None
        else:
            records = await collect(client, channel, since)
            if args.search_sweep:
                records, queries, saturated, pending = await collect_search_sweep(
                    client, channel, since, records, args.max_search_queries, progress)
                sweep_info = (queries, saturated, pending)
            else:
                sweep_info = None
    finally:
        progress.close()
        await client.disconnect()
    csv_path, approval_path, prepared = write_reports(records, admins, zone, Path(args.output_dir))
    candidates = sum(1 for row in prepared if row["candidate"])
    official = sum(1 for row in prepared if row["bot"])
    print(f"Вступивших с {since.astimezone(zone).isoformat()}: {len(prepared)}")
    print(f"Официальных bot-аккаунтов: {official}; кандидатов для ручной проверки: {candidates}")
    print(f"Отчёт: {csv_path}")
    print(f"Файл подтверждения: {approval_path}")
    if sweep_info:
        queries, saturated, pending = sweep_info
        print(f"Поисковый обход: запросов {queries}; насыщенных префиксов {len(saturated)}; "
              f"необработанных префиксов {pending}.")
        print("Это расширенная выборка, но Telegram не гарантирует, что поиск вернёт каждого участника.")
    elif not args.full_log and len(prepared) >= 200:
        print("ВНИМАНИЕ: получено ровно 200 записей — вероятен лимит недавних участников Telegram.")
        print("Для полного журнала сегодняшних вступлений повторите команду с --full-log.")
    if args.apply:
        if not args.confirm_ban:
            raise SystemExit("Для блокировки одновременно укажите --apply ФАЙЛ и --confirm-ban")
        approved_path = Path(args.apply)
        ids = read_approved(approved_path)
        if not ids:
            raise SystemExit("В файле нет раскомментированных ID; блокировка не запускалась.")
        audit_path = Path(args.output_dir) / f"ban-audit-{datetime.now(zone).strftime('%Y%m%d-%H%M%S')}.json"
        results = ban_approved(bot_api, target, ids, {r["id"] for r in prepared}, audit_path)
        print(f"Заблокировано: {sum(r['result'] == 'banned' for r in results)}; "
              f"ошибок: {sum(r['result'] == 'error' for r in results)}")
        print(f"Журнал блокировки: {audit_path}")


def parser():
    result = argparse.ArgumentParser(description="Проверка недавних подписчиков Telegram-канала")
    result.add_argument("--chat", required=True, help="@username или числовой ID канала")
    result.add_argument("--since", default="today", help="today или дата YYYY-MM-DD")
    result.add_argument("--timezone", help="например Europe/Saratov; по умолчанию TIMEZONE из .env")
    result.add_argument("--output-dir", default="reports")
    result.add_argument("--full-log", action="store_true",
                        help="полный журнал вступлений через личный аккаунт администратора")
    result.add_argument("--search-sweep", action="store_true",
                        help="собрать больше участников серией поисковых запросов без личного аккаунта")
    result.add_argument("--max-search-queries", type=int, default=500,
                        help="максимум запросов поискового обхода (по умолчанию 500)")
    result.add_argument("--no-progress", action="store_true",
                        help="не показывать динамический прогресс в терминале")
    result.add_argument("--reset-user-session", action="store_true",
                        help="переместить ошибочную личную сессию в резервную копию и войти заново")
    result.add_argument("--apply", metavar="APPROVED_IDS", help="файл с подтверждёнными ID")
    result.add_argument("--confirm-ban", action="store_true", help="явно разрешить блокировку ID из --apply")
    return result


if __name__ == "__main__":
    try:
        asyncio.run(async_main(parser().parse_args()))
    except (APIError, OSError) as exc:
        sys.exit(f"Ошибка Telegram или сети: {exc}")
