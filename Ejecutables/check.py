from crypt import methods
import os
import sys
import typing as t
import json

from datetime import datetime
from flask import Flask, jsonify, url_for, request, redirect

LISTENING_PORT = int(sys.argv[1])
FORMATO = sys.argv[2]
app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
app.config['JSON_SORT_KEYS'] = False

def get_user(username: str) -> t.Optional[str]:
    if FORMATO == '1':
        command = 'check %s 6' % username
        result = os.popen(command).readlines()
        final = result[0].strip()
        return final
    elif FORMATO == '2':
        command = 'check %s 7' % username
        result = os.popen(command).readlines()
        final = result[0].strip()
        return final
    

@app.route('/checkUser',methods = ['POST', 'GET'])
def check_user():
    if request.method == 'POST':
        try:
            req_data = request.get_json()
            user = req_data.get("user")
            x = get_user(user)
            return x
        except Exception as e:
            return jsonify({'error': str(e)})
    else:
        try:
            return 'Cannot GET /checkUser'
        except Exception as e:
            return jsonify({'error': str(e)})


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(sys.argv[1]) if len(sys.argv) > 1 else LISTENING_PORT,
    )