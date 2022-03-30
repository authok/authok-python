import unittest
import mock
from ...management.user_blocks import UserBlocks


class TestUserBlocks(unittest.TestCase):

    def test_init_with_optionals(self):
        t = UserBlocks(domain='domain', token='jwttoken', telemetry=False, timeout=(10, 2))
        self.assertEqual(t.client.options.timeout, (10, 2))
        telemetry_header = t.client.base_headers.get('AuthOK-Client', None)
        self.assertEqual(telemetry_header, None)

    @mock.patch('authok.v3.management.user_blocks.RestClient')
    def test_get_by_identifier(self, mock_rc):
        mock_instance = mock_rc.return_value

        u = UserBlocks(domain='domain', token='jwttoken')

        u.get_by_identifier('some_identifier')

        mock_instance.get.assert_called_with(
            'https://domain/api/v1/user-blocks',
            params={'identifier': 'some_identifier'}
        )

    @mock.patch('authok.v3.management.user_blocks.RestClient')
    def test_unblock_by_identifier(self, mock_rc):
        mock_instance = mock_rc.return_value

        u = UserBlocks(domain='domain', token='jwttoken')

        u.unblock_by_identifier('test@test.com')

        mock_instance.delete.assert_called_with(
            'https://domain/api/v1/user-blocks',
            params={'identifier': 'test@test.com'}
        )

    @mock.patch('authok.v3.management.user_blocks.RestClient')
    def test_get(self, mock_rc):
        mock_instance = mock_rc.return_value

        u = UserBlocks(domain='domain', token='jwttoken')

        u.get('authok|584ad3c228be27504a2c80d5')

        mock_instance.get.assert_called_with(
            'https://domain/api/v1/user-blocks/authok|584ad3c228be27504a2c80d5'
        )

    @mock.patch('authok.v3.management.user_blocks.RestClient')
    def test_unblock(self, mock_rc):
        mock_instance = mock_rc.return_value

        u = UserBlocks(domain='domain', token='jwttoken')

        u.unblock('authok|584ad3c228be27504a2c80d5')

        mock_instance.delete.assert_called_with(
            'https://domain/api/v1/user-blocks/authok|584ad3c228be27504a2c80d5'
        )
