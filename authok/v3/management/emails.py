from .rest import RestClient


class Emails(object):
    """AuthOK 邮箱

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

    def _url(self, id=None):
        url = '{}://{}/api/v1/emails/provider'.format(self.protocol, self.domain)
        if id is not None:
            return '{}/{}'.format(url, id)
        return url

    def get(self, fields=None, include_fields=True):
        """Get the email provider.

        Args:
            fields (list of str, optional): A list of fields to include or
                exclude from the result (depending on include_fields). Leave empty to
                retrieve all fields.

            include_fields (bool, optional): True if the fields specified are
                to be included in the result, False otherwise. Defaults to True.

        See: https://docs.authok.cn/api/management/v1#!/Emails/get_provider
        """
        params = {'fields': fields and ','.join(fields) or None,
                  'include_fields': str(include_fields).lower()}

        return self.client.get(self._url(), params=params)

    def config(self, body):
        """Configure the email provider.

        Args:
            body (dict): attributes of the created email provider.

        See: https://docs.authok.cn/api/v1#!/Emails/post_provider
        """
        return self.client.post(self._url(), data=body)

    def delete(self):
        """Delete the email provider. (USE WITH CAUTION)

        See: https://docs.authok.cn/api/management/v1#!/Emails/delete_provider
        """
        return self.client.delete(self._url())

    def update(self, body):
        """Update the email provider.

        Args:
            body (dict): attributes to update on the email provider

        See: https://docs.authok.cn/api/v1#!/Emails/patch_provider
        """
        return self.client.patch(self._url(), data=body)
