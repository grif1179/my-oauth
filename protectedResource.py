from flask import Flask, render_template, \
                  redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
import requests
import json
import base64
from urllib.parse import urlencode, quote
from uuid import uuid4

app = Flask(__name__,
            static_folder='./static/protected_resource',
            template_folder='./templates/protected_resource')

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.sqlite"
db = SQLAlchemy(app)

class client_token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String, unique=True, nullable=False)
    refresh_token = db.Column(db.String, unique=True, nullable=False)
    client_id = db.Column(db.String, unique=True, nullable=False)
    scope = db.Column(db.String, default="")

resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
}

def getAccessToken(req):
    auth = req.headers['authorization']
    inToken = None
    if req.contents: 
        body = json.loads(req.contents)
    else:
        body = None

    if auth and 'bearer ' in auth.lower():
        inToken = auth[7:]
    elif req.contents and 'access_token' in body:
        inToken = body['access_token']
    elif req.args and 'access_token' in req.args:
        inToken = req.args['access_token']

    print(f"Incoming token: {inToken}")



@app.route('/resource')
def resource():
    pass


app.run(port=9002, debug=True)
