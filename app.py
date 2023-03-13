import flask
import requests
from argparse import Namespace
import json
import subprocess
import time
from pathlib import Path
import ruamel.yaml
import os
from base64 import b64encode
from secrets import token_bytes
from copy import deepcopy
import numpy as np
from flask import Flask
from flask import request
from io import StringIO 
from tools.common import yaml
import tools
from tools.common import ClientApp


app = Flask(__name__)


@app.route('/serverop/<op>')
def api_service_op(op):
    resp_data = tools.get_default_resp_data()
    try:
        res = tools.service_op(op)    
        resp_data['data'] = res
    except Exception as e:
        resp_data['code'] = 0
        resp_data['info'] = 'Failed: ' + str(e)
    return resp_data

@app.route('/serverlog')
def api_server_log():
    # parame: last_rows  default 300
    # 应该要实时返回用户的日志, 默认返回最新的300条数据
    resp_data = tools.get_default_resp_data()
    try:
        server_profile = tools.load_server_profile()
        log_path = server_profile['log']['output']
        with open(log_path, 'r') as f:
            lines = f.readlines()
        
        last = min(len(lines), 300)
        out_str = "\n".join(lines[-last:])
        
        return out_str
    
    except Exception as e:
        resp_data['code'] = 0
        resp_data['info'] = 'Failed: ' + str(e)
    return resp_data

@app.route('/serverconfig')
def api_server_config():
    # API接口 返回本服务器的相关配置的一些信息，需要验证统一的key
    resp_data = tools.get_default_resp_data()
    try:
        server_profile = tools.load_server_profile()
        config_json = tools.load_server_config(config_json_path=server_profile['dst_server_cfg'])
        return config_json
    except Exception as e:
        resp_data['code'] = 0
        resp_data['info'] = 'Failed: ' + str(e)
    return resp_data
    

@app.route('/subscrib')
def api_subscrib():
    # 返回用户的的订阅，需要检查用户名和密码，和客户端，clash_verge 支持吃v2的tls
    resp_data = tools.get_default_resp_data()
    try:
    
        username = request.args.get("uname", None)
        password = request.args.get("password", None)
        client_type = request.args.get("client", None)
        
        if not username or not password:
            raise Exception("miss uname or password or client")

        server_profile = tools.load_server_profile()
        users = server_profile['users']
        
        if not users.get(username):
            raise Exception("user not found")
        
        user_auth = users[username]['auth']
        assert user_auth == password, "password mismatch"
        
        config_file = server_profile['dst_server_cfg']
        server_config = tools.load_server_config(config_json_path=config_file)
        
        
        from tools import subscrib
        
        client_config = "error"
        
        if client_type == ClientApp.singbox:
            # 当前主要是singbox的tp订阅，先暂时写在这里
            config_tp = tools.load_subscribe_tp(tp_type=ClientApp.singbox)
            singbox_config_json = subscrib.singbox(server_profile=server_profile,server_config=server_config, config_tp=config_tp, username=username, client_type=client_type)
            client_config = singbox_config_json
        
        elif client_type in [ClientApp.clashmeta, ClientApp.shadowrocket]:
            config_tp = tools.load_subscribe_tp(tp_type=ClientApp.clashmeta)
            clashmeta_config = subscrib.clashmeta(server_profile=server_profile,server_config=server_config, config_tp=config_tp, username=username,  client_type=client_type)
            out_ = StringIO()
            yaml.dump(clashmeta_config,out_)
            out_.seek(0)
            client_config = out_.read()
        
        return client_config

    except Exception as e:
        resp_data['code'] = 0
        resp_data['info'] = 'Failed: ' + str(e)
        raise e
    return resp_data

@app.route("/serverstate")
def api_user_state():
    # TODO 查看服务状态和用户状态，流量等
    resp_data = tools.get_default_resp_data()
    try:
        state = tools.get_service_state()
        data = {"service": state}
        resp_data['data'] = data

    except Exception as e:
        resp_data['code'] = 0
        resp_data['info'] = 'Failed: ' + str(e)
    return resp_data


@app.route('/update_server')
def api_update_server():
    # 更新服务器参数
    resp_data = tools.get_default_resp_data()
    try:
        server_profile=tools.load_server_profile()
        tools.serverconfig.update(server_profile=server_profile)
        
    except Exception as e:
        resp_data['code'] = 0
        resp_data['info'] = 'Failed: ' + str(e)
        raise e
    return resp_data

@app.before_request
def print_request_info():
    white_list = ["/subscrib"]
    print("请求地址：" + str(request.path))
    print("请求方法：" + str(request.method))
    print("---请求headers--start--")
    print(str(request.headers).rstrip())
    print("---请求headers--end----")
    print("GET参数:" + str(request.args))
    print("POST参数: " + str(request.form))

    if str(request.path) not in white_list:
        # 验证头部auth
        server_info = tools.load_server_profile()
        
        rpc = server_info['rpc_key']
        
        auth = request.headers.get('rpckey', None)
        
        if auth is None:
            return "rpckey header is none"
        
        if rpc != auth:
            return  "rpc key error"

def main():
    # 运行app
    app.run(host="0.0.0.0", port=8180,debug=False)


if __name__ == "__main__":
    
    main()
    # api_update_server()
