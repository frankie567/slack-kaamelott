from functools import wraps
from flask import abort, Flask, jsonify, request, send_from_directory, url_for
import hashlib
import hmac
import json
import logging
import os
import random

SLACK_SIGNING_SECRET = os.environ['SLACK_SIGNING_SECRET']

app = Flask(__name__, static_url_path='')

with open('quotes.json') as quotes_files:
    quotes = json.load(quotes_files)


def verify_slack_signature(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        req_timestamp = request.headers.get('X-Slack-Request-Timestamp')
        req_signature = request.headers.get('X-Slack-Signature')

        app.logger.debug(
            f'''
                Request: X-Slack-Request-Timestamp={req_timestamp} \
                X-Slack-Signature={req_signature} \
            '''
        )

        if req_timestamp is None or req_signature is None:
            return abort(401)

        req = str.encode(f'v0:{str(timestamp)}:') + request.data
        request_hash = 'v0=' + hmac.new(
            str.encode(SLACK_SIGNING_SECRET),
            req, hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(request_hash, req_signature):
            return abort(401)

        return f(*args, **kwargs)
    return decorated_function


@app.route('/<character>', methods=['POST'])
@verify_slack_signature
def character(character):
    app.logger.debug(f'Character: {character}')
    try:
        response = {
            'response_type': 'in_channel',
            'username': quotes[character]['name'],
            'icon_url': url_for('avatar', character=character, _external=True),
            'text': random.choice(quotes[character]['quotes']),
        }

        return jsonify(response), 200
    except KeyError:
        return 'Connais pas ce clampin.', 404


@app.route('/avatar/<character>')
def avatar(character):
    return send_from_directory('./static/avatars', f'{character}.jpg')


if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
