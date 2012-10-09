import time
import urlparse
import urllib
import httplib2
try:
    import json
except ImportError:
    import simplejson as json
from xml.utils import iso8601

# Python 2.5 compat fix
if not hasattr(urlparse, 'parse_qsl'):
    import cgi
    urlparse.parse_qsl = cgi.parse_qsl

from openstack.compute import exceptions

class ComputeClient(httplib2.Http):
    
    def __init__(self, config):
        super(ComputeClient, self).__init__()
        self.config = config
        self.management_urls = None
        self.auth_token = None
        
        # httplib2 overrides
        self.force_exception_to_status_code = True

    def request(self, *args, **kwargs):
        kwargs.setdefault('headers', {})
        kwargs['headers']['User-Agent'] = self.config.user_agent
        if 'body' in kwargs:
            kwargs['headers']['Content-Type'] = 'application/json'
            kwargs['body'] = json.dumps(kwargs['body'])
            
        resp, body = super(ComputeClient, self).request(*args, **kwargs)
        if body:
            try:
                body = json.loads(body)
            except ValueError:
                # OpenStack is JSON expect when it's not -- error messages
                # sometimes aren't actually JSON.
                body = {'error' : {'message' : body}}
        else:
            body = None

        if resp.status in (400, 401, 403, 404, 413, 500):
            raise exceptions.from_response(resp, body)

        return resp, body

    def _cs_request(self, url, method, **kwargs):
        if not self.management_urls:
            self.authenticate()
        if time.time() > self.auth_token['expiration'] - 5:
            self.authenticate()

        # Perform the request once. If we get a 401 back then it
        # might be because the auth token expired, so try to
        # re-authenticate and try again. If it still fails, bail.
        try:
            kwargs.setdefault('headers', {})['X-Auth-Token'] = self.auth_token['id']
            resp, body = self.request(self.management_url + url, method, **kwargs)
            return resp, body
        except exceptions.Unauthorized, ex:
            try:
                self.authenticate()
                resp, body = self.request(self.management_url + url, method, **kwargs)
                return resp, body
            except exceptions.Unauthorized:
                raise ex

    def get(self, url, **kwargs):
        url = self._munge_get_url(url)
        return self._cs_request(url, 'GET', **kwargs)
    
    def post(self, url, **kwargs):
        return self._cs_request(url, 'POST', **kwargs)
    
    def put(self, url, **kwargs):
        return self._cs_request(url, 'PUT', **kwargs)
    
    def delete(self, url, **kwargs):
        return self._cs_request(url, 'DELETE', **kwargs)

    def authenticate(self):
        body = {"auth":{"RAX-KSKEY:apiKeyCredentials":{"username":self.config.username, "apiKey": self.config.apikey}}}
        resp, body = self.request(self.config.auth_url, 'POST', body=body)
        self.auth_token = {'expiration': iso8601.parse(body['access']['token']['expires']), 'id': body['access']['token']['id']}
        self.management_urls = {}
        for serviceCatalog in body['access']['serviceCatalog']:
            self.management_urls[serviceCatalog['name']] = serviceCatalog['endpoints']
        
    def _munge_get_url(self, url):
        """
        Munge GET URLs to always return uncached content if
        self.config.allow_cache is False (the default).
        
        The Cloud Servers API caches data *very* agressively and doesn't respect
        cache headers. To avoid stale data, then, we append a little bit of
        nonsense onto GET parameters; this appears to force the data not to be
        cached.
        """
        if self.config.allow_cache:
            return url
        else:
            scheme, netloc, path, query, frag = urlparse.urlsplit(url)
            query = urlparse.parse_qsl(query)
            query.append(('fresh', str(time.time())))
            query = urllib.urlencode(query)
            return urlparse.urlunsplit((scheme, netloc, path, query, frag))
