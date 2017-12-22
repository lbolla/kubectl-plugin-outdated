import json
import logging
import subprocess
import http.client
from pkg_resources import parse_version


def kubectl(cmd):
    args = ['kubectl'] + cmd.split() + ['-o', 'json']
    output = subprocess.check_output(args)
    return json.loads(output)


class KubeObject:

    def __init__(self, spec):
        self._spec = spec


class Deployment(KubeObject):

    def __init__(self, spec):
        self._spec = spec

    @property
    def full_name(self):
        meta = self._spec['metadata']
        return '{}/{}'.format(meta['namespace'], meta['name'])

    @property
    def containers(self):
        return [
            Container(c)
            for c in self._spec['spec']['template']['spec']['containers']]

    @property
    def images(self):
        return [c.image for c in self.containers]


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
        if len(tokens) == 1:
            return Repo.from_url(None)
        if '.' not in tokens[0]:
            return Repo.from_url(None)
        return Repo.from_url(tokens[0])

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


class Repo:

    @classmethod
    def from_url(cls, url):
        if url is None or url == 'hub.docker.com':
            return DockerHub()
        if url == 'gcr.io':
            return GoogleContainerRegistry()
        return UnkonwnRepo(url)

    def latest_available_tag(self, path):
        return None


class UnkonwnRepo(Repo):

    def __init__(self, url):
        self._url = url


class DockerHub(Repo):

    def latest_available_tag(self, path):
        url = '/v2/repositories/' + path + '/tags/'
        c = http.client.HTTPSConnection('hub.docker.com')
        c.request('GET', url)
        r = c.getresponse()
        if r.status != 200:
            logging.warning('hub.docker.com failed for %s', url)
            return None
        data = json.load(r)
        tags = sorted([
            r['name']
            for r in data['results']
        ], key=lambda t: parse_version(t))
        if tags:
            return tags[-1]
        return None


class GoogleContainerRegistry(Repo):

    @staticmethod
    def gcloud_container_images_list_tags(path):
        tags = []
        args = (
            'gcloud container images list-tags '
            'gcr.io/{}'
        ).format(path).split()
        try:
            output = subprocess.check_output(args)
        except Exception:
            logging.warning('gcloud failed for %s', path)
            return tags
        lines = output.decode('utf8').splitlines()
        for l in lines[1:]:
            tags.append(l.split()[1])
        return sorted(tags, key=lambda t: parse_version(t))

    def latest_available_tag(self, path):
        tags = self.gcloud_container_images_list_tags(path)
        if tags:
            return tags[-1]
        return None


rs = kubectl('get deployments --all-namespaces')
deployments = [Deployment(spec) for spec in rs['items']]

for d in deployments:
    for i in d.images:
        tag = i.repo.latest_available_tag(i.path)
        if (
                tag is not None and
                i.tag != 'latest' and
                parse_version(i.tag) < parse_version(tag)
        ):
            print('{:40} {:>70} -> {:20}'.format(
                d.full_name, i.full_url, tag))
