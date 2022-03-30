from .base import AuthenticationBase
try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus


class Logout(AuthenticationBase):

    """Logout Endpoint

    Args:
        domain (str): Your authok domain (e.g: username.cn.authok.cn)
    """

    def logout(self, client_id, return_to, federated=False):
        """Logout

        Use this endpoint to logout a user. If you want to navigate the user to a
        specific URL after the logout, set that URL at the return_to parameter.
        The URL should be included in any the appropriate Allowed Logout URLs list:

        Args:
            client_id (str): The client_id of your application.

            return_to (str): URL to redirect the user after the logout.

            federated (bool): Querystring parameter to log the user out of the IdP
        """
        return_to = quote_plus(return_to)

        if federated is True:
            return self.get(
                '{}://{}/v1/logout?federated&client_id={}&return_to={}'.format(
                    self.protocol, self.domain, client_id, return_to)
            )
        return self.get(
            '{}://{}/v1/logout?client_id={}&return_to={}'.format(self.protocol,
                                                                   self.domain,
                                                                   client_id,
                                                                   return_to)
        )
