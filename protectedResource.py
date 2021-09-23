from flask import Flask, render_template, \
                  redirect, request, url_for
import requests
import json
import base64
from urllib.parse import urlencode, quote
from uuid import uuid4

app = Flask(__name__, 
            static_folder='./static/protected_resource',
            template_folder='./templates/protected_resource')

resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
}

def getAccessToken():
	#  Scan for an access token on the incoming request.
    pass


@app.route('/resource')
def resource():
    pass


app.run(port=9002, debug=True)
