from crypt import methods
import os
import sys
import typing as t
import json

from datetime import datetime
from flask import Flask, jsonify, request

a = "{"
b = "}"
LISTENING_PORT = int(sys.argv[1])
app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
app.config['JSON_SORT_KEYS'] = False

def get_user(username: str) -> t.Optional[str]:
    command = 'check %s 1' % username
    result = os.popen(command).readlines()
    final = result[0].strip()
    return final

def cont_online(username: str) -> t.Optional[str]:
    command = 'check %s 2' % username
    result = os.popen(command).readlines()
    final = result[0].strip()
    return final

def limiter_user(username: str) -> t.Optional[str]:
    command = 'check %s 3' % username
    result = os.popen(command).readlines()
    final = result[0].strip()
    return final

def check_data(username: str) -> t.Optional[str]:
    command = 'check %s 4' % username
    result = os.popen(command).readlines()
    final = result[0].strip()
    return final

def check_dias(username: str) -> t.Optional[str]:
    command = 'check %s 5' % username
    result = os.popen(command).readlines()
    final = result[0].strip()
    return final


@app.route('/checkUser',methods = ['POST', 'GET'])
def check_user():
    if request.method == 'POST':
        try:
            req_data = request.get_json()
            user_get = req_data.get("user")
            username = get_user(user_get)
            user = get_user(username)
            if user == "Not exist":
                return ("{0}\"username\":\"{1}\",\"count_connection\":\"Null\",\"expiration_date\":\"Null\",\"expiration_days\":\"Null\",\"limiter_user\":\"Null\"{2}" .format(a, user, b))
            else:
                return ("{0}\"username\":\"{1}\",\"count_connection\":\"{2}\",\"expiration_date\":\"{3}\",\"expiration_days\":\"{4}\",\"limiter_user\":\"{5}\"{6}" .format(a, username, cont_online(username), check_data(username), check_dias(username), limiter_user(username), b))
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
