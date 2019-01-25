import os
import requests

SLACK_TOKEN = os.getenv('SLACK_TOKEN', 'T026NJJ6Z/BFQF13KHD/qSohzFHa6qt8GeUah8TLo0dY')
SLACK_URL = "https://hooks.slack.com/services/"

def send_message(msg):

    message_json = {"text": msg}
    requests.post(SLACK_URL + SLACK_TOKEN, json=message_json)
