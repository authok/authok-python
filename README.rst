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

认证 SDK 对应 `API documentation <https://docs.authok.cn/auth-api>`__ 被组织成不同的模块.
例如:

.. code-block:: python

    from authok.v3.authentication import Social

    social = Social('myaccount.authok.cn')

    social.login(client_id='...', access_token='...', connection='facebook')


邮箱/密码 注册用户, 可使用数据库对象:

.. code-block:: python

    from authok.v3.authentication import Database

    database = Database('myaccount.cn.authok.cn'')

    database.signup(client_id='...', email='user@domain.com', password='secr3t', connection='Username-Password-Authentication')


邮箱/密码 注册用户, 可使用 ``GetToken`` 对象, 会对应去请求 ``/oauth/token`` 端点.

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

如果访问令牌中存在 ``org_id`` 声明，则API应验证该声明，以确保收到的值是预期的.

- 必须检查 (``iss``) 声明以确保令牌由 AuthOK 颁发.
- 必须检查 (``org_id``) 声明以确保组织是预期的.

通常，验证颁发者就足以确保令牌是由AuthOK颁发的。对于组织，应进行额外的检查以确保组织是合法的.

如果声明无法验证，应用程序应认为令牌无效.

下面的代码使用 `PyJWT <https://pyjwt.readthedocs.io/en/latest/usage.html#encoding-decoding-tokens-with-rs256-rsa>`__ 库进行 Token 校验. 
This dependency will take care of pulling the RS256 Public Key that was used by the server to sign the Access Token.
PyJWT 将负责从服务器获取RS256公钥, 并验证签名，超时，还有 audience. 
经过基本验证后, 进一步校验 ``org_id`` 声明是否符合预期. 
代码假定应用使用RS256算法对令牌进行签名. 更多信息可参考 `验证 JSON Web Tokens <https://docs.authok.cn/tokens/json-web-tokens/validate-json-web-tokens>`__.

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

您需要用 域名 和 `管理 API v1 令牌 <https://docs.authok.cn/api/management/v1/tokens>`__ 来实例化AuthOK对象. 
请注意，令牌有效期只有24小时，因此如果您需要长时间调用管理API，应该使用 `非交互式客户端 <https://docs.authok.cn/api/management/v1/tokens#1-create-and-authorize-a-client>`__ 的客户端凭据授权以编程方式请求它. 例如:

.. code-block:: python

    from authok.v3.authentication import GetToken

    domain = 'myaccount.cn.authok.cn'
    non_interactive_client_id = 'exampleid'
    non_interactive_client_secret = 'examplesecret'

    get_token = GetToken(domain)
    token = get_token.client_credentials(non_interactive_client_id,
        non_interactive_client_secret, 'https://{}/api/v1/'.format(domain))
    mgmt_api_token = token['access_token']


使用获取到的令牌:

.. code-block:: python

    from authok.v3.management import AuthOK

    domain = 'myaccount.cn.authok.cn'
    mgmt_api_token = 'MGMT_API_TOKEN'

    authok = AuthOK(domain, mgmt_api_token)

``AuthOK()`` 对象现在可以开始执行API调用了!
下面使用它来获取所有可用的身份源.
(此调用需要的 scope: ``read:connections``)

.. code-block:: python

    authok.connections.all()

调用成功将返回身份源列表:

.. code-block:: python

    [
        {
            'enabled_clients': [u'rOsnWgtw23nje2QCDuDJNVpxlsCylSLE'],
            'id': u'con_ErZf9LpXQDE0cNBr',
            'name': u'Wechat-PC-Connection',
            'options': {u'profile': True, u'scope': [u'profile']},
            'strategy': u'wechat:pc'
        },
        {
            'enabled_clients': [u'rOsnWgtw23nje2QCDuDJNVpxlsCylSLE'],
            'id': u'con_i8qF5DPiZ3FdadwJ',
            'name': u'Username-Password-Authentication',
            'options': {u'brute_force_protection': True},
            'strategy': u'authok'
        }
    ]

修改一个现有的身份源信息. (此调用 需要令牌中包含以下 scope: ``update:connections``)

.. code-block:: python

    authok.connections.update('con_ErZf9LpXQDE0cNBr', {'name': 'MyNewName'})

可以调用 ``get`` 方法来查看修改是否成功.

.. code-block:: python

    modified_connection = authok.connections.get('con_ErZf9LpXQDE0cNBr')

返回如下

.. code-block:: python

    {
        'enabled_clients': [u'rOsnWgtw23nje2QCDuDJNVpxlsCylSLE'],
        'id': u'con_ErZf9LpXQDE0cNBr',
        'name': u'MyNewName',
        'options': {u'profile': True, u'scope': [u'profile']},
        'strategy': u'wechat:pc'
    }

成功!

所有其它端点的调用都类似于 ``connections``, 更多可详细参考 `API 文档 <https://docs.authok.cn/api/v1>`__.

==============
错误处理
==============

API调用可能会由于多种原因而失败:
- 请求数据无效：抛出了一个带有错误代码和详情的``AuthOKError``.
- 已达到全局或客户端速率限制：会抛出 ``RateLimitError``，并在 ``reset_at`` 属性中包含限制重置的时间.
- 网络超时: 客户端可传递 ``timeout`` 参数进行调整. 详情可参考 `频率限制 <https://docs.authok.cn/policies/rate-limits>`__.


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

请查看 `CHANGELOG.md <https://github.com/authok/authok-python/blob/master/CHANGELOG.md>`__.

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
