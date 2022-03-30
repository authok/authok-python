|pypi| |build| |coverage| |license|

在 Python 中集成 AuthOK.

=====
使用
=====

************
安装
************

通过以下命令来安装 authok Python SDK.

.. code-block:: python

    pip install authok-python

python3 使用以下命令

.. code-block:: python

    pip3 install authok-python

Python 3.2 和 3.3 have reached `EOL <https://en.wikipedia.org/wiki/CPython#Version_history>`__ and support will be removed in the near future.

******************
认证 SDK
******************

认证 SDK is organized into components that mirror the structure of the
`API documentation <https://docs.authok.cn/auth-api>`__.
例如:

.. code-block:: python

    from authok.v3.authentication import Social

    social = Social('myaccount.authok.cn')

    social.login(client_id='...', access_token='...', connection='facebook')


如果你通过 邮箱/密码 注册用户, 你可以使用数据库对象.

.. code-block:: python

    from authok.v3.authentication import Database

    database = Database('myaccount.cn.authok.cn'')

    database.signup(client_id='...', email='user@domain.com', password='secr3t', connection='Username-Password-Authentication')


如果你通过 邮箱/密码 注册用户, 你可以使用 ``GetToken`` 对象, 会对应请求 ``/oauth/token`` 端点.

.. code-block:: python

    from authok.v3.authentication import GetToken

    token = GetToken('myaccount.cn.authok.cn')

    token.login(client_id='...', client_secret='...', username='user@domain.com', password='secr3t', realm='Username-Password-Authentication')


ID Token 验证
-------------------

认证成功后, 会接收到 ``id_token``, 如果认证请求包含 ``openid`` scope. ``id_token`` 将包含被认证用户的详细信息. 你可以通过 `此处 <https://docs.authok.cn/tokens/concepts/id-tokens>`__ 了解 更多关于 ID tokens 的信息.

Before you access its contents, you must verify that the ID token has not been tampered with and that it is meant for your application to consume. The ``TokenVerifier`` class can be used to perform this verification.

To create a ``TokenVerifier``, the following arguments are required:

- A ``SignatureVerifier`` instance, which is responsible for verifying the token's algorithm name and signature.
- The expected issuer value, which typically matches the AuthOK domain prefixed with ``https://`` and suffixed with ``/``.
- The expected audience value, which typically matches the AuthOK application client ID.

The type of ``SignatureVerifier`` used depends upon the signing algorithm used by your AuthOK application. You can view this value in your application settings under ``Advanced settings | OAuth | JsonWebToken Signature Algorithm``. AuthOK recommends using the RS256 asymmetric signing algorithm. You can read more about signing algorithms `here <https://docs.authok.cn/tokens/signing-algorithms>`__.

For asymmetric algorithms like RS256, use the ``AsymmetricSignatureVerifier`` class, passing
the public URL where the certificates for the public keys can be found. This will typically be your AuthOK domain with the ``/.well-known/jwks.json`` path appended to it. For example, ``https://your-domain.cn.authok.cn/.well-known/jwks.json``.

For symmetric algorithms like HS256, use the ``SymmetricSignatureVerifier`` class, passing the value of the client secret of your AuthOK application.

The following example demonstrates the verification of an ID token signed with the RS256 signing algorithm:

.. code-block:: python

    from authok.v3.authentication.token_verifier import TokenVerifier, AsymmetricSignatureVerifier

    domain = 'myaccount.cn.authok.cn'
    client_id = 'exampleid'

    # After authenticating
    id_token = auth_result['id_token']

    jwks_url = 'https://{}/.well-known/jwks.json'.format(domain)
    issuer = 'https://{}/'.format(domain)

    sv = AsymmetricSignatureVerifier(jwks_url)  # Reusable instance
    tv = TokenVerifier(signature_verifier=sv, issuer=issuer, audience=client_id)
    tv.verify(id_token)

If the token verification fails, a ``TokenValidationError`` will be raised. In that scenario, the ID token should be deemed invalid and its contents should not be trusted.


Organizations
-------------

`Organizations <https://docs.authok.cn/organizations>`__ is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

Using Organizations, you can:
* Represent teams, business customers, partner companies, or any logical grouping of users that should have different ways of accessing your applications, as organizations.
* Manage their membership in a variety of ways, including user invitation.
* Configure branded, federated login flows for each organization.
* Implement role-based access control, such that users can have different roles when authenticating in the context of different organizations.
* Build administration capabilities into your products, using Organizations APIs, so that those businesses can manage their own organizations.

Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.


Log in to an organization
^^^^^^^^^^^^^^^^^^^^^^^^^

Log in to an organization by specifying the ``organization`` property when calling ``authorize()``:

.. code-block:: python

    from authok.v3.authentication.authorize_client import AuthorizeClient

    client = AuthorizeClient('my.domain.com')

    client.authorize(client_id='client_id',
                redirect_uri='http://localhost',
                organization="org_abc")

When logging into an organization, it is important to ensure the ``org_id`` claim of the ID Token matches the expected organization value. The ``TokenVerifier`` can be be used to ensure the ID Token contains the expected ``org_id`` claim value:

.. code-block:: python

    from authok.v3.authentication.token_verifier import TokenVerifier, AsymmetricSignatureVerifier

    domain = 'myaccount.cn.authok.cn'
    client_id = 'exampleid'

    # After authenticating
    id_token = auth_result['id_token']

    jwks_url = 'https://{}/.well-known/jwks.json'.format(domain)
    issuer = 'https://{}/'.format(domain)

    sv = AsymmetricSignatureVerifier(jwks_url)  # Reusable instance
    tv = TokenVerifier(signature_verifier=sv, issuer=issuer, audience=client_id)

    # pass the expected organization the user logged in to:
    tv.verify(id_token, organization='org_abc')


Accept user invitations
^^^^^^^^^^^^^^^^^^^^^^^

Accept a user invitation by specifying the ``invitation`` property when calling ``authorize()``. Note that you must also specify the ``organization`` if providing an ``invitation``.
The ID of the invitation and organization are available as query parameters on the invitation URL, e.g., ``https://your-domain.cn.authok.cn/login?invitation=invitation_id&organization=org_id&organization_name=org_name``

.. code-block:: python

    from authok.v3.authentication.authorize_client import AuthorizeClient

    client = AuthorizeClient('my.domain.com')

    client.authorize(client_id='client_id',
            redirect_uri='http://localhost',
            organization='org_abc',
            invitation="invitation_123")


Authorizing users from an Organization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If an ``org_id`` claim is present in the Access Token, then the claim should be validated by the API to ensure that the value received is expected or known.

In particular:

- The issuer (``iss``) claim should be checked to ensure the token was issued by AuthOK
- The organization ID (``org_id``) claim should be checked to ensure it is a value that is already known to the application. This could be validated against a known list of organization IDs, or perhaps checked in conjunction with the current request URL. e.g. the sub-domain may hint at what organization should be used to validate the Access Token.

Normally, validating the issuer would be enough to ensure that the token was issued by AuthOK. In the case of organizations, additional checks should be made so that the organization within an AuthOK tenant is expected.

If the claim cannot be validated, then the application should deem the token invalid.

The snippet below attempts to illustrate how this verification could look like using the external `PyJWT <https://pyjwt.readthedocs.io/en/latest/usage.html#encoding-decoding-tokens-with-rs256-rsa>`__ library. This dependency will take care of pulling the RS256 Public Key that was used by the server to sign the Access Token. It will also validate its signature, expiration, and the audience value. After the basic verification, get the ``org_id`` claim and check it against the expected value. The code assumes your application is configured to sign tokens using the RS256 algorithm. Check the `Validate JSON Web Tokens <https://docs.authok.cn/tokens/json-web-tokens/validate-json-web-tokens>`__ article to learn more about this verification.

.. code-block:: python

    import jwt  # PyJWT
    from jwt import PyJWKClient

    access_token = # access token from the request
    url = 'https://{YOUR AUTHOK DOMAIN}/.well-known/jwks.json'
    jwks_client = PyJWKClient(url)
    signing_key = jwks_client.get_signing_key_from_jwt(access_token)
    data = jwt.decode(
        access_token,
        signing_key.key,
        algorithms=['RS256'],
        audience='{YOUR API AUDIENCE}'
    )

    organization = # expected organization ID
    if data['org_id'] != organization:
        raise Exception('Organization (org_id) claim mismatch')

    # if this line is reached, validation is successful


**************
管理 SDK
**************

To use the management library you will need to instantiate an AuthOK object with a domain and a `Management API v1 token <https://docs.authok.cn/api/management/v1/tokens>`__. Please note that these token last 24 hours, so if you need it constantly you should ask for it programmatically using the client credentials grant with a `non interactive client <https://docs.authok.cn/api/management/v1/tokens#1-create-and-authorize-a-client>`__ authorized to access the API. For example:

.. code-block:: python

    from authok.v3.authentication import GetToken

    domain = 'myaccount.cn.authok.cn'
    non_interactive_client_id = 'exampleid'
    non_interactive_client_secret = 'examplesecret'

    get_token = GetToken(domain)
    token = get_token.client_credentials(non_interactive_client_id,
        non_interactive_client_secret, 'https://{}/api/v1/'.format(domain))
    mgmt_api_token = token['access_token']


Then use the token you've obtained as follows:

.. code-block:: python

    from authok.v3.management import AuthOK

    domain = 'myaccount.cn.authok.cn'
    mgmt_api_token = 'MGMT_API_TOKEN'

    authok = AuthOK(domain, mgmt_api_token)

The ``AuthOK()`` object is now ready to take orders!
Let's see how we can use this to get all available connections.
(this action requires the token to have the following scope: ``read:connections``)

.. code-block:: python

    authok.connections.all()

Which will yield a list of connections similar to this:

.. code-block:: python

    [
        {
            'enabled_clients': [u'rOsnWgtw23nje2QCDuDJNVpxlsCylSLE'],
            'id': u'con_ErZf9LpXQDE0cNBr',
            'name': u'Amazon-Connection',
            'options': {u'profile': True, u'scope': [u'profile']},
            'strategy': u'amazon'
        },
        {
            'enabled_clients': [u'rOsnWgtw23nje2QCDuDJNVpxlsCylSLE'],
            'id': u'con_i8qF5DPiZ3FdadwJ',
            'name': u'Username-Password-Authentication',
            'options': {u'brute_force_protection': True},
            'strategy': u'authok'
        }
    ]

Modifying an existing connection is equally as easy. Let's change the name
of connection ``'con_ErZf9LpXQDE0cNBr'``.
(The token will need scope: ``update:connections`` to make this one work)

.. code-block:: python

    authok.connections.update('con_ErZf9LpXQDE0cNBr', {'name': 'MyNewName'})

That's it! Using the ``get`` method of the connections endpoint we can verify
that the rename actually happened.

.. code-block:: python

    modified_connection = authok.connections.get('con_ErZf9LpXQDE0cNBr')

Which returns something like this

.. code-block:: python

    {
        'enabled_clients': [u'rOsnWgtw23nje2QCDuDJNVpxlsCylSLE'],
        'id': u'con_ErZf9LpXQDE0cNBr',
        'name': u'MyNewName',
        'options': {u'profile': True, u'scope': [u'profile']},
        'strategy': u'amazon'
    }

成功!

All endpoints follow a similar structure to ``connections``, and try to follow as
closely as possible the `API documentation <https://docs.authok.cn/api/v1>`__.

==============
错误处理
==============

When consuming methods from the API clients, the requests could fail for a number of reasons:
- Invalid data sent as part of the request: An ``AuthOKError` is raised with the error code and description.
- Global or Client Rate Limit reached: A ``RateLimitError`` is raised and the time at which the limit
resets is exposed in the ``reset_at`` property. When the header is unset, this value will be ``-1``.
- Network timeouts: Adjustable by passing a ``timeout`` argument to the client. See the `rate limit docs <https://docs.authok.cn/policies/rate-limits>`__ for details.


==============
支持的 API
==============

************************
认证端点
************************

- API 授权 - 授权码 (``authentication.AuthorizeClient``)
- 数据库 ( ``authentication.Database`` )
- Delegated ( ``authentication.Delegated`` )
- 企业 ( ``authentication.Enterprise`` )
- API 授权 - Get Token ( ``authentication.GetToken``)
- 免密登录 ( ``authentication.Passwordless`` )
- 撤销令牌 ( ``authentication.RevokeToken`` )
- 社会化 ( ``authentication.Social`` )
- 用户 ( ``authentication.Users`` )


********************
管理端点
********************

- Actions() (``AuthOK().actions``)
- AttackProtection() (``AuthOK().attack_protection``)
- Blacklists() ( ``AuthOK().blacklists`` )
- ClientGrants() ( ``AuthOK().client_grants`` )
- Clients() ( ``AuthOK().clients`` )
- Connections() ( ``AuthOK().connections`` )
- CustomDomains() ( ``AuthOK().custom_domains`` )
- DeviceCredentials() ( ``AuthOK().device_credentials`` )
- EmailTemplates() ( ``AuthOK().email_templates`` )
- Emails() ( ``AuthOK().emails`` )
- Grants() ( ``AuthOK().grants`` )
- Guardian() ( ``AuthOK().guardian`` )
- Hooks() ( ``AuthOK().hooks`` )
- Jobs() ( ``AuthOK().jobs`` )
- LogStreams() ( ``AuthOK().log_streams`` )
- Logs() ( ``AuthOK().logs`` )
- Organizations() ( ``AuthOK().organizations`` )
- Prompts() ( ``AuthOK().prompts`` )
- ResourceServers() (``AuthOK().resource_servers`` )
- Roles() ( ``AuthOK().roles`` )
- RulesConfigs() ( ``AuthOK().rules_configs`` )
- Rules() ( ``AuthOK().rules`` )
- Stats() ( ``AuthOK().stats`` )
- Tenants() ( ``AuthOK().tenants`` )
- Tickets() ( ``AuthOK().tickets`` )
- UserBlocks() (``AuthOK().user_blocks`` )
- UsersByEmail() ( ``AuthOK().users_by_email`` )
- Users() ( ``AuthOK().users`` )

=====
关于我们
=====

******
作者
******

`AuthOK`_

**********
变更日志
**********

Please see `CHANGELOG.md <https://github.com/authok/authok-python/blob/master/CHANGELOG.md>`__.

***************
问题报告
***************

If you have found a bug or if you have a feature request, please report them at this repository issues section.
Please do not report security vulnerabilities on the public GitHub issue tracker.
The `Responsible Disclosure Program <https://authok.cn/whitehat>`__ details the procedure for disclosing security issues.

**************
什么是 AuthOK?
**************

AuthOK 可以帮助您:

* Add authentication with `multiple authentication sources <https://docs.authok.cn/identityproviders>`__,
  either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, among others**,
  or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional `username/password databases <https://docs.authok.cn/connections/database/mysql>`__.
* Add support for `linking different user accounts <https://docs.authok.cn/link-accounts>`__ with the same user.
* Support for generating signed `JSON Web Tokens <https://docs.authok.cn/jwt>`__ to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through `JavaScript rules <https://docs.authok.cn/rules>`__.

***************************
创建免费的 AuthOK 账号
***************************

1. 进入 `AuthOK <https://authok.cn/>`__ 并点击注册.
2. 使用 微信，企业微信，Google, GitHub 等账号登录.

*******
许可
*******

本项目基于 MIT 许可. 参考 `LICENSE <https://github.com/authok/authok-python/blob/master/LICENSE>`_ 获取更多信息.

.. _AuthOK: https://authok.cn

.. |pypi| image:: https://img.shields.io/pypi/v/authok-python.svg?style=flat-square&label=latest%20version
    :target: https://pypi.org/project/authok-python/
    :alt: Latest version released on PyPI

.. |build| image:: https://img.shields.io/circleci/project/github/authok/authok-python.svg?style=flat-square&label=circleci
    :target: https://circleci.com/gh/authok/authok-python
    :alt: Build status

.. |coverage| image:: https://img.shields.io/codecov/c/github/authok/authok-python.svg?style=flat-square&label=codecov
    :target: https://codecov.io/gh/authok/authok-python
    :alt: Test coverage

.. |license| image:: https://img.shields.io/:license-mit-blue.svg?style=flat-square
    :target: https://opensource.org/licenses/MIT
    :alt: License
