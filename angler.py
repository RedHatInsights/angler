import logging
import sys
import os
import json
import hmac
import hashlib

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
VALID_TOPICS_MAP = os.getenv('VALID_TOPICS_MAP', 'upload-service-valid-topics')
GITHUB_URL = 'https://api.github.com/repos/RedHatInsights/platform-mq/contents/topics/topics.json'
CONFIG_MAP_URL = os.getenv('CONFIG_MAP_URL', 'https://api.insights-dev.openshift.com:443/api/v1/namespaces/')

if os.path.isfile(SECRET_PATH + '/token'):
    with open(SECRET_PATH + '/token', 'r') as f:
        TOKEN = f.read()

if os.path.isfile(SECRET_PATH + '/namespace'):
    with open(SECRET_PATH + '/namespace', 'r') as f:
        NAMESPACE = f.read()

configMap = """
            apiVersion: v1
            kind: ConfigMap
            metadata:
                name: upload-service-valid-topics
                namespace: platform-ci
            data:
                topics.json: \"{0}\"
            """


def verify_hmac_hash(data, signature):
    mac = hmac.new(GITHUB_SECRET.encode('utf-8'), data, hashlib.sha1)
    return hmac.compare_digest('sha1=' + mac.hexdigest(), str(signature))


def check_for_topics(payload):
    url = "https://api.github.com/repos/redhatinsights/platform-mq/pulls/{0}/files".format(payload['number'])
    response = requests.get(url, headers=HEADERS)
    data = response.json()
    if response.status_code == 200:
        for i in data:
            if 'topics.json' in i.get('raw_url').split('/'):
                return True
            else:
                logger.info('No topics.json update in this PR')


def update_configMap(newMap):
    url = CONFIG_MAP_URL + NAMESPACE + '/configmaps/' + VALID_TOPICS_MAP
    headers = {'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    response = requests.put(url, headers=headers, data=newMap)
    if response.status_code == 200:
        return True
    else:
        logger.error('Failed to post update - Code: %s - %s', response.status_code, response.text)


@app.route("/", methods=['GET'])
def get():
        """
        Handle GET requests to the root url
        """
        return 'boop'


@app.route("/github/hook/valid-topics", methods=['POST'])
def post():

    headers = request.headers

    # Validate Webhook
    signature = headers.get('X-Hub-Signature')
    data = request.get_data(as_text=True)
    if verify_hmac_hash(data, signature):
        return True
    else:
        logger.error("Bad Signature")

    if headers.get('X-GitHub-Event') == 'ping':
        return json.dumps({'msg': 'Ok'})
    if headers.get('X-GitHub-Event') == 'pull_request':
        payload = request.json
        if not (payload['pull_request']['merged'] and payload['pull_request']['state'] == 'closed'):
            return
        else:
            logger.info('PR %s not close or merged', payload['number'])
        response = requests.get(GITHUB_URL, headers=HEADERS)
        topics_json = requests.get(response.json()['download_url'], headers=HEADERS).text
        newMap = configMap.format(topics_json)

        if update_configMap(newMap):
            logger.info('successully updated topic configMap')
        else:
            logger.error('configMap not updated')


def main():
    app.run(host='0.0.0.0', port=LISTEN_PORT)


if __name__ == "__main__":
    main()
