import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from scan_members import (ban_approved, collect_admin_log, collect_search_sweep,
                          read_approved, progress_bar, risk, rotate_session,
                          start_time, write_reports)


class ScannerTests(unittest.TestCase):
    def test_official_bot_is_candidate_unless_admin(self):
        user = {'bot': True, 'photo': True, 'username': 'helper_bot', 'first_name': 'Helper'}
        self.assertTrue(risk(user, 1)[2])
        self.assertFalse(risk(user, 1, is_admin=True)[2])

    def test_ordinary_account_needs_multiple_signals(self):
        normal = {'bot': False, 'photo': True, 'username': 'person', 'first_name': 'Person'}
        suspicious = {'bot': False, 'photo': False, 'username': '', 'first_name': 'Person'}
        self.assertFalse(risk(normal, 60)[2])
        self.assertTrue(risk(suspicious, 50)[2])

    def test_approved_file_accepts_only_uncommented_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'approved.txt'
            path.write_text('# 111 # candidate\n222 # approved\n222\n', encoding='utf-8')
            self.assertEqual(read_approved(path), [222])

    def test_approved_file_rejects_non_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'approved.txt'
            path.write_text('123\n@somebody\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                read_approved(path)

    def test_report_candidates_are_commented(self):
        zone = ZoneInfo('Europe/Saratov')
        record = {'id': 123, 'joined_at': datetime(2026, 9, 20, 10, tzinfo=zone),
                  'joins': 1, 'source': {'public'}, 'username': 'spam12345',
                  'first_name': '', 'last_name': '', 'bot': True, 'deleted': False,
                  'photo': False}
        with tempfile.TemporaryDirectory() as directory:
            csv_path, approval, rows = write_reports([record], set(), zone, Path(directory))
            self.assertTrue(csv_path.exists())
            self.assertTrue(rows[0]['candidate'])
            self.assertIn('# 123', approval.read_text(encoding='utf-8'))
            self.assertEqual(read_approved(approval), [])

    def test_since_uses_requested_timezone(self):
        since, zone = start_time('2026-09-20', 'Europe/Saratov')
        self.assertEqual(since.astimezone(zone).hour, 0)

    def test_progress_bar_shows_dynamic_queue_and_found_count(self):
        line = progress_bar(25, 75, 321, 'префикс: а', width=10)
        self.assertIn('25%', line)
        self.assertIn('25/100', line)
        self.assertIn('найдено 321', line)
        self.assertIn('префикс: а', line)

    def test_rotate_session_keeps_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / 'admin'
            original = Path(str(session) + '.session')
            original.write_text('bot session', encoding='utf-8')
            backup = rotate_session(session)
            self.assertFalse(original.exists())
            self.assertEqual(backup.read_text(encoding='utf-8'), 'bot session')

    def test_ban_rejects_protected_admin_before_api_calls(self):
        class API:
            def call(self, *args, **kwargs):
                raise AssertionError('API must not be called')

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'защищённые администраторы'):
                ban_approved(API(), -100, [1, 2], {1, 2}, Path(directory) / 'audit.json',
                             protected_ids={2})


class AdminLogTests(unittest.IsolatedAsyncioTestCase):
    async def test_invited_participant_id_is_used_instead_of_inviter(self):
        class Object:
            def __init__(self, **values):
                self.__dict__.update(values)

        joined = datetime(2026, 9, 20, 12, tzinfo=ZoneInfo('UTC'))
        event = Object(date=joined, user_id=999,
                       action=Object(participant=Object(user_id=123)), joined_invite=True)
        user = Object(id=123, username='new_user', first_name='New', last_name='User',
                      bot=False, deleted=False, photo=object())

        class Client:
            async def iter_admin_log(self, *args, **kwargs):
                yield event

            async def get_entity(self, uid):
                self.requested = uid
                return user

        client = Client()
        rows = await collect_admin_log(client, object(), datetime(2026, 9, 20, tzinfo=ZoneInfo('UTC')))
        self.assertEqual(client.requested, 123)
        self.assertEqual(rows[0]['id'], 123)
        self.assertEqual(rows[0]['source'], {'invite'})

    async def test_search_sweep_merges_unique_users(self):
        class Object:
            def __init__(self, **values):
                self.__dict__.update(values)

        joined = datetime(2026, 9, 20, 12, tzinfo=ZoneInfo('UTC'))
        participant = Object(date=joined)
        shared = Object(id=1, participant=participant, username='anna', first_name='Anna',
                        last_name='', bot=False, deleted=False, photo=None)
        second = Object(id=2, participant=participant, username='boris', first_name='Boris',
                        last_name='', bot=False, deleted=False, photo=None)

        class Client:
            async def get_participants(self, channel, limit, search):
                return [shared] if search == 'a' else [shared, second] if search == 'b' else []

        rows, queries, saturated, pending = await collect_search_sweep(
            Client(), object(), datetime(2026, 9, 20, tzinfo=ZoneInfo('UTC')), [], max_queries=2)
        self.assertEqual({row['id'] for row in rows}, {1, 2})
        self.assertEqual(queries, 2)
        self.assertEqual(saturated, [])
        self.assertGreater(pending, 0)


if __name__ == '__main__':
    unittest.main()
