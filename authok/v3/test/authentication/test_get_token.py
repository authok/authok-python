import unittest
import mock
from ...authentication.get_token import GetToken


class TestGetToken(unittest.TestCase):

    @mock.patch('authok.v3.authentication.get_token.GetToken.post')
    def test_authorization_code(self, mock_post):

        g = GetToken('my.domain.com')

        g.authorization_code(client_id='cid',
                             client_secret='clsec',
                             code='cd',
                             grant_type='gt',
                             redirect_uri='idt')

        args, kwargs = mock_post.call_args

        self.assertEqual(args[0], 'https://my.domain.com/oauth/token')
        self.assertEqual(kwargs['data'], {
            'client_id': 'cid',
            'client_secret': 'clsec',
            'code': 'cd',
            'grant_type': 'gt',
            'redirect_uri': 'idt'
        })

    @mock.patch('authok.v3.authentication.get_token.GetToken.post')
    def test_authorization_code_pkce(self, mock_post):

        g = GetToken('my.domain.com')

        g.authorization_code_pkce(client_id='cid',
                                  code_verifier='cdver',
                                  code='cd',
                                  grant_type='gt',
                                  redirect_uri='idt')

        args, kwargs = mock_post.call_args

        self.assertEqual(args[0], 'https://my.domain.com/oauth/token')
        self.assertEqual(kwargs['data'], {
            'client_id': 'cid',
            'code_verifier': 'cdver',
            'code': 'cd',
            'grant_type': 'gt',
            'redirect_uri': 'idt'
        })

    @mock.patch('authok.v3.authentication.get_token.GetToken.post')
    def test_client_credentials(self, mock_post):

        g = GetToken('my.domain.com')

        g.client_credentials(client_id='cid',
                             client_secret='clsec',
                             audience='aud',
                             grant_type='gt')

        args, kwargs = mock_post.call_args

        self.assertEqual(args[0], 'https://my.domain.com/oauth/token')
        self.assertEqual(kwargs['data'], {
            'client_id': 'cid',
            'client_secret': 'clsec',
            'audience': 'aud',
            'grant_type': 'gt'
        })

    @mock.patch('authok.v3.authentication.get_token.GetToken.post')
    def test_login(self, mock_post):

        g = GetToken('my.domain.com')

        g.login(client_id='cid',
                client_secret='clsec',
                username='usrnm',
                password='pswd',
                scope='http://test.com/api',
                realm='rlm',
                audience='aud',
                grant_type='gt')

        args, kwargs = mock_post.call_args

        self.assertEqual(args[0], 'https://my.domain.com/oauth/token')
        self.assertEqual(kwargs['data'], {
            'client_id': 'cid',
            'client_secret': 'clsec',
            'username': 'usrnm',
            'password': 'pswd',
            'scope': 'http://test.com/api',
            'realm': 'rlm',
            'audience': 'aud',
            'grant_type': 'gt'
        })

    @mock.patch('authok.v3.authentication.get_token.GetToken.post')
    def test_refresh_token(self, mock_post):
        g = GetToken('my.domain.com')

        g.refresh_token(client_id='cid',
                        client_secret='clsec',
                        refresh_token='rt',
                        grant_type='gt',
                        scope='s')

        args, kwargs = mock_post.call_args

        self.assertEqual(args[0], 'https://my.domain.com/oauth/token')
        self.assertEqual(kwargs['data'], {
            'client_id': 'cid',
            'client_secret': 'clsec',
            'refresh_token': 'rt',
            'grant_type': 'gt',
            'scope': 's'
        })


    @mock.patch('authok.v3.authentication.get_token.GetToken.post')
    def test_passwordless_login_with_sms(self, mock_post):

        g = GetToken('my.domain.com')

        g.passwordless_login(
                client_id='cid',
                client_secret='csec',
                username='123456',
                otp='abcd',
                realm='sms',
                audience='aud',
                scope='openid')

        args, kwargs = mock_post.call_args

        self.assertEqual(args[0], 'https://my.domain.com/oauth/token')
        self.assertEqual(kwargs['data'], {
            'client_id': 'cid',
            'client_secret': 'csec',
            'realm': 'sms',
            'grant_type': 'http://authok.cn/oauth/grant-type/passwordless/otp',
            'username': '123456',
            'otp': 'abcd',
            'audience': 'aud',
            'scope': 'openid',
        })


    @mock.patch('authok.v3.authentication.get_token.GetToken.post')
    def test_passwordless_login_with_email(self, mock_post):

        g = GetToken('my.domain.com')

        g.passwordless_login(
                client_id='cid',
                client_secret='csec',
                username='a@b.c',
                otp='abcd',
                realm='email',
                audience='aud',
                scope='openid')

        args, kwargs = mock_post.call_args

        self.assertEqual(args[0], 'https://my.domain.com/oauth/token')
        self.assertEqual(kwargs['data'], {
            'client_id': 'cid',
            'client_secret': 'csec',
            'realm': 'email',
            'grant_type': 'http://authok.cn/oauth/grant-type/passwordless/otp',
            'username': 'a@b.c',
            'otp': 'abcd',
            'audience': 'aud',
            'scope': 'openid',
        })
