from flask import Flask, render_template, jsonify, redirect, request
import requests
import json
import base64
from urllib.parse import urlencode, quote
from uuid import uuid4

app = Flask(__name__, 
            static_folder='./static',
            template_folder='./templates')

authServer = {
    'authorizationEndpoint': 'http://localhost:9001/authorize',
    'tokenEndpoint': 'http://localhost:9001/token'
}

client = {
    "client_id": "oauth-client-1",
    "client_secret": "oauth-client-secret-1",
    "redirect_uris": ["http://localhost:9000/callback"]
}

protectedResource = 'http://localhost:9002/resource'

state = None
access_token = None
scope = None

@app.route('/')
def index():
    return render_template('index.html', access_token=access_token, scope=scope)


@app.route('/authorize')
def authorize():
    global access_token
    state = str(uuid4())

    redirect_uri = client['redirect_uris'][0]
    print("URI: " + redirect_uri)

    query_items = {
        'response_type': 'code',
        'client_id': client['client_id'],
        'redirect_uri': client['redirect_uris'][0],
        'state': state
    }
    authUrl = buildUrl(authServer['authorizationEndpoint'], query_items)
    print('redirect', authUrl)
    return redirect(authUrl)
    

def encodeClientCreds(id, secret):
    base_str = f"{id}:{secret}"
    return base64.b64encode(bytes(base_str, 'utf-8')).decode('utf-8')


@app.route('/callback')
def callback():
    print('callback')
    if 'error' in request.args:
        return render_template('error.html', error="State value did not match")
    code = request.args['code']
    form_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': client["redirect_uris"][0]
    }
    encoded_str = encodeClientCreds(client['client_id'], client['client_secret'])
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f"Basic {encoded_str}"
    }

    token_request = requests.post(authServer['tokenEndpoint'], 
                                  data=form_data,
                                  headers=headers)

    print(f"Requesting access token for code {code}")

    status_code = token_request.status_code
    if status_code >= 200 and status_code < 300:
        body = json.loads(token_request.content)
        print(f"Request Body: {body}")
        global access_token
        access_token = body['access_token']
        print(f"access_token: {access_token}")

        return render_template('index.html', access_token=access_token, scope=scope)
    else:
        error_msg = f"Unable to fetch access token, server response: {status_code}"
        return render_template('error.html', error=error_msg)



@app.route('/fetch_resource')
def fetch_resource():
    pass


def buildUrl(base, options, hash=""):
    return f"{base}?{urlencode(options)}"



app.run(port=9000, debug=True)
