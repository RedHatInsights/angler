import logging
import sys
import os
import json
import hmac
import hashlib
import yaml

import requests
from logstash_formatter import LogstashFormatterV1
from flask import Flask, request

app = Flask(__name__)

LOGLEVEL = os.getenv("LOGLEVEL", "INFO")
if any('KUBERNETES' in k for k in os.environ):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(LogstashFormatterV1())
    logging.root.setLevel(LOGLEVEL)
    logging.root.addHandler(handler)
else:
    logging.basicConfig(
        level=LOGLEVEL,
        format="%(threadName)s %(levelname)s %(name)s = %(message)s"
    )

logger = logging.getLogger(__name__)

LISTEN_PORT = os.getenv("LISTEN_PORT", 8080)
GITHUB_SECRET = os.getenv("GITHUB_SECRET", 'secret')
HEADERS = {'Authorization': 'token ' + os.getenv('NACHOBOT_TOKEN', 'supertoken')}
SECRET_PATH = '/var/run/secrets/kubernetes.io/serviceaccount'
CONFIG_MAP_URL = os.getenv('CONFIG_MAP_URL', 'https://api.insights-dev.openshift.com:443/api/v1/namespaces/')

if os.path.isfile(SECRET_PATH + '/token'):
    with open(SECRET_PATH + '/token', 'r') as f:
        TOKEN = f.read()

configMap = """{
"apiVersion": "v1",
"data": {
  "{0}" : "{1}"
  },
"kind": "ConfigMap",
"metadata": {
  "name": "{2}",
  "namespace": {3}
  }
}
"""


def verify_hmac_hash(data, signature):
    mac = hmac.new(GITHUB_SECRET.encode('utf-8'), data.encode('utf-8'), hashlib.sha1)
    return hmac.compare_digest('sha1=' + mac.hexdigest(), str(signature))


def api_put(headers, url, data):
    response = requests.put(url, headers=headers, json=data)
    if response.status_code == 200:
        return response.status_code
    else:
        return response.status_code, response.text


def get_file(url, headers):
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.status_code
    else:
        return response.status_code, response.text
    contents = requests.get(response.json()['download_url'], headers=HEADERS)
    return contents


class ConfigMapUpdater(object):

    def __init__(self, mapname, namespace, repo, filename, env='dev', rawdata=False):

        self.mapname = mapname
        self.namespace = namespace
        self.repo = repo
        self.filename = filename
        self.rawdata = rawdata
        self.url = 'https://api.insights-dev.openshift.com:443/api/v1/namespaces/{0}/{1}/{2}'

        if env == 'prod':
            self.url = 'https://api.insight.openshift.com:443/api/v1/namespaces/{0}/{1}/{2}'

        self.git_url = 'https://api.github.com/repos/RedHatInsights/{0}/contents/{1}'

    def check_file_change(self, payload):
        url = "{0}/files".format(payload['pull_request']['url'])
        response = requests.get(url, headers=HEADERS)
        data = response.json()
        if response.status_code == 200:
            for i in data:
                if self.filename == i.get('filename'):
                    return True
                else:
                    logger.info('File not updated in this PR')

    def update_configMap(self, newMap):
        url = self.url.format(self.namespace, '/configmaps/', self.mapname)
        headers = {'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/json', 'Content-Type': 'application/json'}
        result = api_put(headers, url, newMap)
        if result == 200:
            return True
        else:
            logger.error('Failed to post update - Code: %s - %s', result[0], result[1])

    def github_pr(self, headers, data, payload):

        if verify_hmac_hash(data, headers.get('X-Hub-Signature')):
            if headers.get('X-GitHub-Event') == 'ping':
                return json.loads('{"msg": "Ok"}')
            if headers.get('X-GitHub-Event') == 'pull_request':
                if not (payload['pull_request']['merged'] and payload['pull_request']['state'] == 'closed'):
                    return json.loads('{"msg": "PR not merged or closed"}')
                if not self.check_file_change(payload):
                    return json.loads('{"msg": "No file changes in this PR"}')
            result = get_file(self.git_url.format(self.repo, self.filename), headers=HEADERS)
            if self.rawdata:
                newMap = json.loads(configMap.format(self.filename.split('/')[-1], result, self.mapname, self.namespace))
                return newMap
            else:
                return json.dumps(yaml.safe_load(result))
        else:
            return json.loads({'msg': 'Invalid Secret'})


@app.route("/", methods=['GET'])
def get():
        """
        Handle GET requests to the root url
        """
        return 'boop'


@app.route("/github/hook/valid-topics", methods=['POST'])
def post():

    NAMESPACE = os.getenv('NAMESPACE', 'platform-ci')

    MAPNAME = 'upload-service-valid-topics'
    headers = request.headers
    data = request.get_data(as_text=True)
    payload = request.json

    Updater = ConfigMapUpdater(MAPNAME,
                               NAMESPACE,
                               'platform-mq',
                               'topics/topics.json',
                               rawdata=True)

    newMap = Updater.github_pr(headers, data, payload)
    print(newMap)

    if not newMap.get('msg'):
        if Updater.update_configMap(newMap):
            logger.info('ConfigMap updated')
            return json.dumps({'msg': 'Config Map Updated'})
        else:
            return json.dumps({'msg': 'Something went wrong. Config map not updated'})
            logger.error('configMap not updated')
    else:
        return json.dumps({'msg': newMap.get('msg')})


def main():
    app.run(host='0.0.0.0', port=LISTEN_PORT)


if __name__ == "__main__":
    main()
