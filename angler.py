import logging
import sys
import os
import json
import hmac
import hashlib

import requests
import tornado.web
import tornado.escape
import tornado.ioloop
from logstash_formatter import LogstashFormatterV1


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
CONFIG_MAP_URL = os.getenv('CONFIG_MAP_URL', 'https://api.insights-dev.openshift.com:443/api/v1/namespaces/platform-ci/configmaps/')

if os.path.isfile(SECRET_PATH + '/token'):
    with open(SECRET_PATH + '/token', 'r') as f:
        TOKEN = f.read()

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
    mac = hmac.new(GITHUB_SECRET, data, hashlib.sha1)
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
    url = CONFIG_MAP_URL + VALID_TOPICS_MAP
    headers = {'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    response = requests.put(url, headers=headers, data=newMap)
    if response.status_code == 200:
        return True
    else:
        logger.error('Failed to post update - Code: %s - %s', response.status_code, response.text)


class NoAccessLog(tornado.web.RequestHandler):
    """
    A class to override tornado's logging mechanism.
    Reduce noise in the logs via GET requests we don't care about
    """

    def _log(self):
        if LOGLEVEL == "DEBUG":
            super()._log()
        else:
            pass


class RootHandler(NoAccessLog):

    def get(self):
        """
        Handle GET requests to the root url
        """
        self.write('boop')


class TopicsHandler(tornado.web.RequestHandler):

    def get(self):
        """
        Handle GET requests to Topics handler
        """
        self.write('this works')

    def post(self):

        headers = self.requests.headers

        # Validate Webhook
        signature = headers.get('X-Hub-Signature')
        data = self.request.body
        if verify_hmac_hash(data, signature):
            return True
        else:
            logger.error("Bad Signature")

        if headers.get('X-GitHub-Event') == 'ping':
            self.write(json.dumps({'msg': 'Ok'}))
            self.finish()
        if headers.get('X-GitHub-Event') == 'pull_request':
            payload = tornado.escape.json_decode(self.request.body)
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


endpoints = [
    (r"/", RootHandler),
    (r"/github/hook/valid-topics", TopicsHandler)
]

app = tornado.web.Application(endpoints)


def main():
    app.listen(LISTEN_PORT)
    logger.info(f"Web server listening on port {LISTEN_PORT}")
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
