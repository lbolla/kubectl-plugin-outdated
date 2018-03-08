#!/usr/bin/env python3
import distutils.spawn
import json
import logging
import subprocess
import http.client
from pkg_resources import parse_version


HAS_GCLOUD = bool(distutils.spawn.find_executable('gcloud'))


def kubectl(cmd):
    args = ['kubectl'] + cmd.split() + ['-o', 'json']
    output = subprocess.check_output(args)
    return json.loads(output)


class KubeObject:

    def __init__(self, spec):
        self._spec = spec


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
            Container(c)
            for c in self._spec['spec']['template']['spec']['containers']]

    @property
    def images(self):
        return [c.image for c in self.containers]


class Deployment(Workload):
    pass


class DaemonSet(Workload):
    pass


class Container(KubeObject):

    @property
    def image(self):
        return Image(self._spec['image'])


class Image:

    def __init__(self, url):
        self.full_url = url

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
            return Repo.from_host('hub.docker.com')
        else:
            return Repo.from_host(tokens[0])

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


class CheckFailed(RuntimeError):
    pass


class Repo:

    def __init__(self, host):
        self.host = host

    @classmethod
    def from_host(cls, host):
        if host == 'hub.docker.com':
            # Endpoints on hub.docker.com don't need authentication.
            return DockerHub(host)
        elif HAS_GCLOUD and (host == 'gcr.io' or host.endswith('.gcr.io')):
            # Prefer calling gcloud, to handle private repos.
            return GoogleContainerRegistry(host)
        else:
            return DockerRegistry(host)

    def available_tags(self, path):
        return None

    def latest_available_tag(self, path):
        tags = self.available_tags(path)
        if not tags:
            raise CheckFailed("No tags found for {}".format(path))

        tags = sorted(tags, key=lambda t: parse_version(t))
        return tags[-1]

    def _fetch_json(self, host, url):
        c = http.client.HTTPSConnection(host)
        try:
            c.request('GET', url)
        except OSError as e:
            raise CheckFailed('Request to https://{}{} failed: {}'.format(
                host, url, e))

        r = c.getresponse()
        if r.status == 401:
            raise CheckFailed(
                "Registry {} requires authentication, skipping".format(host))
        elif r.status != 200:
            raise CheckFailed('Request at https://{}{} returned: {}'.format(
                host, url, r.status))

        return json.load(r)


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
        for i in w.images:
            try:
                tag = i.repo.latest_available_tag(i.path)
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
