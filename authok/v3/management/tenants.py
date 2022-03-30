from .rest import RestClient


class Tenants(object):
    """AuthOK tenants

    Args:
        domain (str): Your AuthOK domain, e.g: 'username.cn.authok.cn'

        token (str): Management API v1 Token

        telemetry (bool, optional): Enable or disable Telemetry
            (defaults to True)

        timeout (float or tuple, optional): Change the requests
            connect and read timeout. Pass a tuple to specify
            both values separately or a float to set both to it.
            (defaults to 5.0 for both)

        rest_options (RestClientOptions): Pass an instance of
            RestClientOptions to configure additional RestClient
            options, such as rate-limit retries.
            (defaults to None)
    """

    def __init__(self, domain, token, telemetry=True, timeout=5.0, protocol="https", rest_options=None):
        self.domain = domain
        self.protocol = protocol
        self.client = RestClient(jwt=token, telemetry=telemetry, timeout=timeout, options=rest_options)

    def _url(self):
        return '{}://{}/api/v1/tenants/settings'.format(self.protocol, self.domain)

    def get(self, fields=None, include_fields=True):
        """Get tenant settings.

        Args:
           fields (list of str, optional): A list of fields to include or
              exclude from the result (depending on include_fields). Leave empty to
              retrieve all fields.

           include_fields (bool, optional): True if the fields specified are
              to be included in the result, False otherwise. Defaults to True.

        See: https://docs.authok.cn/api/management/v1#!/Tenants/get_settings
        """

        params = {'fields': fields and ','.join(fields) or None,
                  'include_fields': str(include_fields).lower()}

        return self.client.get(self._url(), params=params)

    def update(self, body):
        """Update tenant settings.

        Args:
            body (dict): the attributes to update in the tenant.

        See: https://docs.authok.cn/api/v1#!/Tenants/patch_settings
        """
        return self.client.patch(self._url(), data=body)
