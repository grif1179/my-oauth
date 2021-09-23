from flask import Flask, render_template, \
                  redirect, request, url_for
import requests
import json
import base64
from urllib.parse import urlencode, quote
from uuid import uuid4

app = Flask(__name__, 
            static_folder='./static/client',
            template_folder='./templates/client')

authServer = {
    'authorizationEndpoint': 'http://localhost:9001/authorize',
    'tokenEndpoint': 'http://localhost:9001/token',
    'revocationEndpoint': 'http://localhost:9001/revoke',
    'registrationEndpoint': 'http://localhost:9001/register',
    'userInfoEndpoint': 'http://localhost:9001/userinfo' 
}

client = {
    "client_id": "oauth-client-1",
    "client_secret": "oauth-client-secret-1",
    "redirect_uris": ["http://localhost:9000/callback"],
    "scope": ""
}

protectedResource = 'http://localhost:9002/resource'

access_token = None
refresh_token = None
state = None
scope = None

@app.route('/')
def index():
    return render_template('index.html', access_token=access_token, 
                            refresh_token=refresh_token, scope=scope)


@app.route('/authorize')
def authorize():
    global access_token, scope, state

    access_token = None
    refresh_token = None
    scope = None

    state = str(uuid4())

    redirect_uri = client['redirect_uris'][0]
    print("URI: " + redirect_uri)

    query_items = {
        'response_type': 'code',
        'client_id': client['client_id'],
        'redirect_uri': client['redirect_uris'][0],
        'scope': client['scope'],
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
    if 'error' in request.args:
        return render_template('error.html', error=request.args['error'])

    if request.args['state'] != state:
        print(f"State DOES NOT MATCH: expected {state} got {request.args['state']}")
        return render_template('error.html', error="State value did not match")

    print(f"State value matches: expected {state} got {request.args['state']}")

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

        global access_token, refresh_token, scope

        access_token = body['access_token']
        print(f"access_token: {access_token}")

        if 'refresh_token' in body:
            refresh_token = body['refresh_token']
            print(f"Go refresh token: {refresh_token}")

        scope = body['scope']
        print(f"Got scope: {scope}")

        return render_template('index.html', access_token=access_token, 
                               refresh_token=refresh_token, scope=scope)
    else:
        error_msg = f"Unable to fetch access token, server response: {status_code}"
        return render_template('error.html', error=error_msg)


def refresh_access_token(req):
    global access_token, refresh_token, scope

    form_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }

    encoded_str = encodeClientCreds(client['client_id'], client['client_secret'])
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f"Basic {encoded_str}"
    }

    token_request = requests.post(authServer['tokenEndpoint'], 
                                  data=form_data,
                                  headers=headers)

    status_code = token_request.status_code
    if status_code >= 200 and status_code < 300:
        body = json.loads(token_request.content)
        print(f"Request Body: {body}")


        access_token = body['access_token']
        print(f"access_token: {access_token}")

        if 'refresh_token' in body:
            refresh_token = body['refresh_token']
            print(f"Got refresh token: {refresh_token}")

        scope = body['scope']
        print(f"Got scope: {scope}")

        return redirect('/fetch_resource')
    else:
        error_msg = f"Unable to refresh token."
        return render_template('error.html', error=error_msg)


@app.route('/fetch_resource')
def fetch_resource():
    global access_token
    if not access_token:
        return render_template('error', error='Missing Access Token')
    
    print(f"Making request with access token {access_token}")

    headers = {
        'Authorization': f"Bearer {access_token}",
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    resource = requests.post(protectedResource, headers=headers)
    status_code = resource.status_code
    if status_code >= 200 and status_code < 300:
        body = json.loads(resource.content)
        print(f"Resource Body: {body}")
        return render_template('data.html', resource=body)
    else:
        access_token = None
        if refresh_token:
            return refresh_access_token(request)
        else:
            return render_template('error.html', error=resource.status_code)



def buildUrl(base, options, hash=""):
    return f"{base}?{urlencode(options)}"


app.run(port=9000, debug=True)
