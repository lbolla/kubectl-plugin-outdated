#!/usr/bin/env python3
import distutils.spawn
import json
import logging
import subprocess
import http.client
from base64 import b64decode, b64encode
from functools import lru_cache
from pkg_resources import parse_version
from pprint import pformat
from urllib.parse import urlparse
from urllib.request import parse_http_list, parse_keqv_list


HAS_GCLOUD = bool(distutils.spawn.find_executable('gcloud'))


def kubectl(cmd):
    if not isinstance(cmd, list):
        cmd = cmd.split()
    args = ['kubectl'] + cmd + ['-o', 'json']
    output = subprocess.check_output(args)
    return json.loads(output)


class KubeObject:

    def __init__(self, spec, parent=None):
        self._spec = spec
        self.parent = parent

    def __repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, pformat(self._spec))


class Workload(KubeObject):

    def __init__(self, spec):
        self._spec = spec

    @property
    def full_name(self):
        meta = self._spec['metadata']
        return '{}:{}/{}'.format(
            self.__class__.__name__, meta['namespace'], meta['name'])

    @property
    def containers(self):
        return [
            Container(c, self)
            for c in self._spec['spec']['template']['spec']['containers']]

    @property
    def images(self):
        return [c.image for c in self.containers]

    @property
    def image_pull_secrets(self):
        try:
            return [
               ImagePullSecret.from_name(s['name'], self._spec['metadata']['namespace'])
               for s in self._spec['spec']['template']['spec']['imagePullSecrets']]
        except LookupError:
            return []

    def get_pull_secrets(self, host):
        for secret in self.image_pull_secrets:
            if host in secret.dockercfg:
                return secret
        return None


class Deployment(Workload):
    pass


class DaemonSet(Workload):
    pass


class Container(KubeObject):

    @property
    def image(self):
        return Image(self._spec['image'], workload=self.parent)


class Image:

    def __init__(self, url, workload=None):
        self.full_url = url
        self.workload = workload

    @property
    def tag(self):
        tokens = self.full_url.rsplit(':', 1)
        if len(tokens) == 1:
            return 'latest'
        return tokens[-1]

    @property
    def repo(self):
        tokens = self.full_url.rsplit(':', 1)
        url = tokens[0]
        tokens = url.split('/', 1)
        if len(tokens) == 1 or '.' not in tokens[0]:
            host = 'hub.docker.com'
        else:
            host = tokens[0]

        return Repo.from_host(
            host=host,
            pull_secret=self.workload.get_pull_secrets(host)
        )

    @property
    def path(self):
        tokens = self.full_url.rsplit(':', 1)
        url = tokens[0]
        tokens = url.split('/', 1)
        if len(tokens) == 1:
            return tokens[0]
        if '.' not in tokens[0]:
            return url
        return tokens[1]

    def __str__(self):
        return 'Image(repo={}, path={}, tag={})'.format(
            self.repo, self.path, self.tag)


class ImagePullSecret(KubeObject):

    @staticmethod
    @lru_cache()  # avoids fetching the same token multiple times
    def from_name(name, namespace):
        spec = kubectl(['get', 'secret', name, '--namespace', namespace])
        return ImagePullSecret(spec)

    @property
    def dockercfg(self):
        try:
            # cache on-demand property value
            return self._cfg
        except AttributeError:
            cfg = json.loads(b64decode(self._spec['data']['.dockercfg']))
            if 'auths' in cfg:
                cfg = cfg['auths']
            self._cfg = cfg
            return cfg

    def for_host(self, host):
        return self.dockercfg.get(host)


class CheckFailed(RuntimeError):
    pass


class Repo:

    def __init__(self, host, pull_secret=None):
        self.host = host
        self.pull_secret = pull_secret
        self.headers = {}  # updated by _fetch_oauth2_token

    @staticmethod
    @lru_cache()  # cache object for token header
    def from_host(host, pull_secret=None):
        if host == 'hub.docker.com' or host == 'docker.io':
            # Endpoints on hub.docker.com don't need authentication.
            return DockerHub('hub.docker.com', pull_secret=pull_secret)
        elif HAS_GCLOUD and (host == 'gcr.io' or host.endswith('.gcr.io')):
            # Prefer calling gcloud, to handle private repos.
            return GoogleContainerRegistry(host, pull_secret=pull_secret)
        else:
            return DockerRegistry(host, pull_secret=pull_secret)

    def available_tags(self, path):
        return None

    def latest_available_tag(self, path, allow_alpha=False,
                             allow_beta=False, allow_rc=False):
        tags = self.available_tags(path)
        if not tags:
            raise CheckFailed("No tags found for {}".format(path))

        if not allow_alpha:
            tags = [tag for tag in tags if '-alpha' not in tag]
            if not allow_beta:
                tags = [tag for tag in tags if '-beta' not in tag]
                if not allow_rc:
                    tags = [tag for tag in tags if '-rc' not in tag]

        tags = sorted(tags, key=lambda t: parse_version(t))
        return tags[-1]

    def _fetch_json(self, host, url):
        c = http.client.HTTPSConnection(host)
        try:
            c.request('GET', url, headers=self.headers)
        except OSError as e:
            raise CheckFailed('Request to https://{}{} failed: {}'.format(
                host, url, e))

        r = c.getresponse()
        if r.status == 401:
            # Initialize self.headers on demand using the WWW-Authenticate header.
            if self.pull_secret and not self.headers.get('Authorization'):
                if not self._fetch_oauth2_token(host, r.headers):
                    raise CheckFailed(
                        "Registry {} authentication failed".format(self.host))

                return self._fetch_json(host, url)

            raise CheckFailed(
                "Registry {} requires authentication, skipping".format(host))
        elif r.status == 301:
            raise CheckFailed('Request at https://{}{} returned: 301 to {}'.format(
                host, url, r.headers['Location']))
        elif r.status != 200:
            raise CheckFailed('Request at https://{}{} returned: {}'.format(
                host, url, r.status))

        return json.load(r)

    def _fetch_oauth2_token(self, host, response_headers):
        www_auth = response_headers['WWW-Authenticate']
        dockercfg = self.pull_secret.for_host(host)
        if not www_auth.startswith('Bearer ') or not dockercfg:
            return None

        items = parse_http_list(www_auth[7:])
        opts = parse_keqv_list(items)  # realm, scope, service

        realm = urlparse(opts['realm'])
        url = ('{path}'
               '?client_id=docker'
               '&offline_token=true'
               '&service={service}'
               '&scope={scope}').format(path=realm.path, **opts)
        c = http.client.HTTPSConnection(realm.netloc)
        c.request('GET', url, headers={
            'Authorization': "Basic {}".format(dockercfg['auth'])
        })
        r = c.getresponse()
        if r.status != 200:
            return False

        data = json.loads(r.read())
        self.headers['Authorization'] = 'Bearer {}'.format(data['token'])
        return True


class DockerHub(Repo):

    def available_tags(self, path):
        # No group for image defaults to "library"
        if '/' not in path:
            path = 'library/{}'.format(path)

        url = '/v2/repositories/' + path + '/tags/'
        data = self._fetch_json(self.host, url)
        if data is None:
            return None

        return [r['name'] for r in data['results']]


class DockerRegistry(Repo):

    def available_tags(self, path):
        host = self.host
        if '/' not in path:
            if host == 'k8s.gcr.io':
                # Use the public endpoint instead:
                host = 'gcr.io'
                path = 'google-containers/{}'.format(path)
            else:
                path = 'library/{}'.format(path)

        url = '/v2/' + path + '/tags/list'
        data = self._fetch_json(host, url)
        if data is None:
            return None

        return data['tags']


class GoogleContainerRegistry(Repo):

    def available_tags(self, path):
        args = (
            'gcloud container images list-tags '
            '{}/{}'
        ).format(self.host, path).split()
        try:
            output = subprocess.check_output(args)
        except Exception:
            raise CheckFailed('gcloud failed for {}'.format(path))
        lines = output.decode('utf8').splitlines()

        tags = []
        for l in lines[1:]:
            tags.append(l.split()[1])
        return tags


def main():
    rs = kubectl('get deployments --all-namespaces')
    deployments = [Deployment(spec) for spec in rs['items']]

    rs = kubectl('get daemonsets --all-namespaces')
    daemonsets = [DaemonSet(spec) for spec in rs['items']]

    workloads = deployments + daemonsets

    for w in workloads:
        # Extract pull secrets that might be needed
        for i in w.images:
            try:
                tag = i.repo.latest_available_tag(
                    path=i.path,
                    allow_alpha='-alpha' in i.tag,
                    allow_beta='-beta' in i.tag,
                    allow_rc='-rc' in i.tag
                )
            except CheckFailed as e:
                logging.warning("{}: {}".format(i.path, e))
                continue

            if (
                    i.tag != 'latest' and
                    parse_version(i.tag) < parse_version(tag)
            ):
                print('{:55} {:>70} -> {:20}'.format(
                    w.full_name, i.full_url, tag))


if __name__ == '__main__':
    main()
