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

在访问其内容之前，必须验证ID令牌未被篡改。``TokenVerifier`` 类用于执行此验证。

创建 ``TokenVerifier`` 实例需要提供以下参数:
- ``SignatureVerifier`` 实例, 用于验证令牌的算法和签名.
- 期望的 issuer, 通常是以 ``https://`` 开头，以 ``/`` 结尾的 AuthOK 子域名.
- 期望的 audience, 匹配 AuthOK 应用的 client ID.

使用的 ``SignatureVerifier`` 具体类型取决于 AuthOK应用使用的签名算法. 你可以在管理后台具体应用的 ``高级设置 | OAuth | JsonWebToken 签名算法`` 中查看签名算法类型. AuthOK 推荐使用 RS256 非对称签名算法. 在 `这里 <https://docs.authok.cn/tokens/signing-algorithms>`__ 了解更多签名算法相关.

对于类似 RS256 的非对称加密算法, 使用 ``AsymmetricSignatureVerifier`` 类, 传递返回公钥的公开URL作为构造函数参数. 通常是您的 AuthOK 域名 加上 ``/.well-known/jwks.json`` 路径. 例如, ``https://your-domain.cn.authok.cn/.well-known/jwks.json``.

对于类似 HS256的对称加密算法, 使用 ``SymmetricSignatureVerifier`` 类, 传递 AuthOK 应用的 client secret 作为构造函数参数.

下面的示例演示如何使用RS256签名算法验证 ID Token:

.. code-block:: python

    from authok.v3.authentication.token_verifier import TokenVerifier, AsymmetricSignatureVerifier

    domain = 'myaccount.cn.authok.cn'
    client_id = 'exampleid'

    # 认证后
    id_token = auth_result['id_token']

    jwks_url = 'https://{}/.well-known/jwks.json'.format(domain)
    issuer = 'https://{}/'.format(domain)

    sv = AsymmetricSignatureVerifier(jwks_url)  # 可重用实例
    tv = TokenVerifier(signature_verifier=sv, issuer=issuer, audience=client_id)
    tv.verify(id_token)

如果令牌验证失败，将抛出 ``TokenValidationError``。在这种情况下，ID令牌应被视为无效，其内容不应被信任。

组织
-------------

`组织 <https://docs.authok.cn/organizations>`__ 主要用于 SaaS 和 B2B类系统的构建。

你可以使用组织:
* 代表团队、业务客户、合作伙伴公司或任何逻辑用户分组，这些用户可以用不同的方式访问您的应用程序.
* 通过多种方式管理其成员，包括用户邀请.
* 为每个组织配置品牌化的联合登录流程.
* 实现基于角色的访问控制，这样用户在不同组织的上下文中进行身份验证时可以拥有不同的角色.
* 使用组织API将管理功能构建到您的产品中，以便这些企业能够管理自己的组织.

登录到一个组织
^^^^^^^^^^^^^^^^^^^^^^^^^

在调用 ``authorize()`` 端点时指定 ``organization`` 参数即代表登录到指定组织:

.. code-block:: python

    from authok.v3.authentication.authorize_client import AuthorizeClient

    client = AuthorizeClient('my.domain.com')

    client.authorize(client_id='client_id',
                redirect_uri='http://localhost',
                organization="org_abc")

登录组织时，一定要确保 ID Token 的 ``org_id`` 声明与预期的组织匹配。``TokenVerifier`` 可用于确保 ID Token 包含预期的 ``org_id``:

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


接收用户邀请
^^^^^^^^^^^^^^^^^^^^^^^

在调用 ``authorize()`` 端点时通过指定 ``invitation`` 参数来接收用户邀请. 如果指定了 ``invitation``, 必须同时指定 ``organization``.
邀请ID 和 组织ID 作为邀请链接的查询参数, 例如: ``https://your-domain.cn.authok.cn/login?invitation=invitation_id&organization=org_id&organization_name=org_name``

.. code-block:: python

    from authok.v3.authentication.authorize_client import AuthorizeClient

    client = AuthorizeClient('my.domain.com')

    client.authorize(client_id='client_id',
            redirect_uri='http://localhost',
            organization='org_abc',
            invitation="invitation_123")

授权来自组织的用户
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
