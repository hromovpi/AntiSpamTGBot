import copy
import sqlite3
import unittest
from bot import APIError, Bot, DEFAULT, reason


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.fail_delete = False
        self.members = {}

    def call(self, method, **params):
        self.calls.append((method, params))
        if method == 'getMe':
            return {'id': 99, 'username': 'guard_bot'}
        if method == 'getChatMember':
            status = 'administrator' if params['user_id'] in {1, 99} else self.members.get(params['user_id'], 'member')
            return {'status': status, 'can_delete_messages': True, 'can_restrict_members': True}
        if method == 'deleteMessage' and self.fail_delete:
            raise APIError(403)
        return True


class Tests(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.bot = Bot(self.api, self.db, {1})
        self.config = copy.deepcopy(DEFAULT)
        self.config.update(links=True)
        self.bot.save(-100, self.config)

    def message(self, text='https://spam.example', mid=1, user=2):
        return {'message_id': mid, 'chat': {'id': -100, 'type': 'supergroup'},
                'from': {'id': user}, 'text': text}

    def test_observe_does_not_delete(self):
        self.bot.handle({'message': self.message()})
        self.assertNotIn('deleteMessage', [x[0] for x in self.api.calls])
        self.assertEqual(self.db.execute('SELECT action FROM events').fetchone()[0], 'наблюдение')

    def test_delete_and_fail_statistics(self):
        self.config['mode'] = 'delete'
        self.bot.save(-100, self.config)
        self.bot.handle({'message': self.message()})
        self.api.fail_delete = True
        self.bot.handle({'message': self.message(mid=2)})
        self.assertEqual(self.db.execute('SELECT action FROM events ORDER BY id').fetchall(),
                         [('удалено',), ('ошибка удаления',)])

    def test_admin_and_automatic_forward_exempt(self):
        self.bot.handle({'message': self.message(user=1)})
        self.bot.handle({'message': {**self.message(), 'is_automatic_forward': True}})
        self.assertEqual(self.db.execute('SELECT count(*) FROM events').fetchone()[0], 0)

    def test_member_cannot_disable(self):
        self.bot.handle({'message': self.message('/mode off')})
        self.assertEqual(self.bot.settings(-100)['mode'], 'observe')

    def test_hidden_link_caption(self):
        self.assertEqual(reason({'caption': 'текст', 'caption_entities': [{'type': 'text_link', 'url': 'https://example.com'}]}, self.config, []), 'ссылка')

    def test_edit_checked_but_not_counted_twice(self):
        self.bot.handle({'message': self.message('привет')})
        self.bot.handle({'edited_message': self.message()})
        self.assertEqual(self.db.execute('SELECT count(*) FROM messages').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT reason FROM events').fetchone()[0], 'ссылка')

    def test_repeat_and_flood(self):
        for n in range(3):
            self.bot.handle({'message': self.message('Одинаковый текст', n)})
        self.assertEqual(self.db.execute('SELECT reason FROM events').fetchone()[0], 'повтор')
        for n in range(3, 6):
            self.bot.handle({'message': self.message(f'другой {n}', n)})
        self.assertEqual(self.db.execute('SELECT reason FROM events ORDER BY id DESC').fetchone()[0], 'флуд')

    def test_unconfigured_chat_ignored(self):
        m = self.message()
        m['chat']['id'] = -200
        self.bot.handle({'message': m})
        self.assertEqual(self.db.execute('SELECT count(*) FROM messages').fetchone()[0], 0)

    def test_phrase_normalization(self):
        self.config['phrases'] = ['быстрый доход']
        self.assertEqual(reason({'text': 'БЫСТРЫЙ  до\u200bход'}, self.config, []), 'стоп-фраза')

    def test_channel_posts_filtered(self):
        m = self.message()
        m['chat']['type'] = 'channel'
        m['sender_chat'] = m['chat']
        self.bot.handle({'channel_post': m})
        self.assertEqual(self.db.execute('SELECT reason FROM events').fetchone()[0], 'ссылка')

    def test_trusted_user(self):
        self.config['trusted'] = [2]
        self.bot.save(-100, self.config)
        self.bot.handle({'message': self.message()})
        self.assertEqual(self.db.execute('SELECT count(*) FROM messages').fetchone()[0], 0)

    def test_api_error_keeps_telegram_description(self):
        error = APIError(400, description='Bad Request: chat not found')
        self.assertIn('chat not found', str(error))

    def test_new_bot_is_remembered_in_observe_mode(self):
        new_bot = {'id': 50, 'is_bot': True, 'username': 'helper_bot', 'first_name': 'Helper'}
        self.bot.handle({'chat_member': {'chat': {'id': -100},
                         'new_chat_member': {'status': 'member', 'user': new_bot}}})
        self.assertEqual(self.db.execute('SELECT uid,status FROM known_bots').fetchone(),
                         (50, 'обнаружен'))
        self.assertNotIn('banChatMember', [x[0] for x in self.api.calls])

    def test_new_bot_is_banned_in_ban_mode(self):
        self.config['bot_guard'] = 'ban'
        self.bot.save(-100, self.config)
        new_bot = {'id': 50, 'is_bot': True, 'username': 'spam_bot', 'first_name': 'Spam'}
        self.bot.handle({'chat_member': {'chat': {'id': -100},
                         'new_chat_member': {'status': 'member', 'user': new_bot}}})
        calls = [params for method, params in self.api.calls if method == 'banChatMember']
        self.assertEqual(calls[0]['user_id'], 50)
        self.assertTrue(calls[0]['revoke_messages'])
        self.assertEqual(self.db.execute('SELECT status FROM known_bots').fetchone()[0], 'заблокирован')

    def test_trusted_and_admin_bots_are_not_banned(self):
        self.config['bot_guard'] = 'ban'
        self.config['trusted'] = [50]
        self.bot.save(-100, self.config)
        self.bot.notice_bot(-100, {'id': 50, 'is_bot': True, 'first_name': 'Trusted'}, self.config)
        self.api.members[51] = 'administrator'
        self.bot.notice_bot(-100, {'id': 51, 'is_bot': True, 'first_name': 'Admin'}, self.config)
        self.assertNotIn('banChatMember', [x[0] for x in self.api.calls])

    def test_old_settings_receive_bot_guard_default(self):
        old = copy.deepcopy(DEFAULT)
        old.pop('bot_guard')
        self.db.execute('UPDATE settings SET value=? WHERE chat=-100', (__import__('json').dumps(old),))
        self.assertEqual(self.bot.settings(-100)['bot_guard'], 'observe')

    def test_spam_sender_is_listed_as_offender(self):
        self.bot.handle({'message': self.message()})
        self.assertEqual(self.db.execute(
            'SELECT uid,strikes,last_reason,status FROM offenders').fetchone(),
            (2, 1, 'ссылка', 'обнаружен'))

    def test_ban_mode_blocks_spam_sender_and_deletes_message(self):
        self.config['mode'] = 'ban'
        self.bot.save(-100, self.config)
        self.bot.handle({'message': self.message()})
        methods = [method for method, _ in self.api.calls]
        self.assertIn('banChatMember', methods)
        self.assertIn('deleteMessage', methods)
        self.assertEqual(self.db.execute('SELECT status FROM offenders').fetchone()[0],
                         'заблокирован')


if __name__ == '__main__':
    unittest.main()
