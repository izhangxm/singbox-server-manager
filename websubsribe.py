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

yaml = ruamel.yaml.YAML()


service_state_cmd = "systemctl status sing-box"
service_restart_cmd = "systemctl restart sing-box"
service_stop_cmd = "systemctl stop sing-box"


server_info_file = "./profile.yaml"


class ServiceState():
    inactive = "inactive"
    active = "active"
    failed = "faild"


def load_server_info():
    # server_info = json.load(open(args.server_info, 'r'))
    server_info = yaml.load(open(server_info_file, 'r'))
    return server_info


def get_users_from_db():
    return load_server_info()['users']


def get_subscribe_tp():
    serverinfo = load_server_info()
    subscribe_tp = yaml.load(open(serverinfo['subscribe_tp'], 'r'))
    return subscribe_tp

def dump_server_config(server_cfg, dst_server_cfg):
    
    json.dump(server_cfg, open(dst_server_cfg, 'w+'),
              sort_keys=False, indent=2, separators=(',', ':'))
    # yaml.dump(subscribe_tp, open(args.dst_server_cfg,'w+'))


def get_service_state():
    # return active, failed, inactive
    p = subprocess.Popen(service_state_cmd, shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    out = p.communicate()[0].decode('utf8')
    if "Active: inactive" in out:
        return ServiceState.inactive
    if "Active: active" in out:
        return ServiceState.active
    if "FAILURE" in out:
        return ServiceState.failed
    raise Exception(f"unknown state. {out}")


def get_random_password():
    return b64encode(token_bytes(16)).decode()


def service_op(op="status"):
    # 操作服务状态，并返回操作完成后的结果
    cmd = f"systemctl {op} sing-box"
    p = subprocess.Popen(service_state_cmd, shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    time.sleep(1)

    return get_service_state()


def get_server_config():
    # 返回当前服务器信息，本地调用的功能函数
    server_state = get_service_state()
    pass


def get_default_resp_data():
    # 返回值模版
    return {"code": 1, "info": "ok"}


def api_server_log():
    # parame: last_rows  default 300
    # 应该要实时返回用户的日志, 默认返回最新的300条数据
    pass


def api_server_config():
    # API接口 返回本服务器的相关配置的一些信息，需要验证统一的key
    pass


def api_subscrib():
    # 返回用户的的订阅，需要检查用户名和密码，和客户端，clash_verge 支持吃v2的tls
    pass


def api_user_state():
    # TODO 查看服务状态和用户状态，流量等
    resp_data = get_default_resp_data()
    try:
        state = get_service_state()
        data = {"service": state}
        resp_data['data'] = data

    except Exception as e:
        resp_data['code'] = 0
        resp_data['info'] = 'Failed: ' + str(e)
    return resp_data


def api_update_server():
    # 更新服务器参数
    resp_data = get_default_resp_data()
    try:
        # 读取userconfig，更新到运行目录并重启服务器，然后查看服务器状态
        users = get_users_from_db()
        server_info = load_server_info()
        users = server_info['users']
        
        server_cfg_res = {}
        
        users_dt = []
        for uname in users.keys():
            user = users[uname]
            users_dt.append({"name": uname, "password": user['password']})

        shadowtls_cfg = server_info['inbounds']['shadowtls']
        listen_common = server_info['inbounds']['listen']

        shadowtls_tp = shadowtls_cfg['common']
        shadowtls_tp.update(listen_common)
        v2_tp = shadowtls_cfg['v2']

        
        # dns 相关
        server_cfg_res['dns'] = server_info['dns']
        
        # log 相关
        server_cfg_res['log'] = server_info['log']
                
        
        # 生成配置文件的inbounds
        inbounds_res = []
        interfaces = server_info['inbounds']['interfaces']
        for tag, interface in interfaces.items():
            
            # 当前监听服务的描述信息
            meta = interface["meta"]
            
            # 是否通过shadowtls来通信
            if meta['over_shadowtls']:
                s_p = meta['tls_s_port']
                # 为保证兼容性 生成三个版本的配置
                # v1-v3的tls配置
                v1_shadow_tls = deepcopy(shadowtls_tp)
                v1_shadow_tls.update({"listen_port": s_p,"version": 1,"detour": tag})
                
                v2_shadow_tls = deepcopy(shadowtls_tp)
                v2_shadow_tls.update({"listen_port": s_p+1, "version": 2, "detour": tag})
                v2_shadow_tls.update(v2_tp)

                v3_shadow_tls = deepcopy(shadowtls_tp)
                v3_shadow_tls.update({"listen_port": s_p+2, "version": 3, "detour": tag, "users":users_dt})
                
                inbounds_res += [v1_shadow_tls,v2_shadow_tls,v3_shadow_tls]
                
                # 加密类型配置
                content = interface['content']
                content.update(listen_common)
                content.update({"listen":"127.0.0.1","tag":tag})

                # 是否支持多用户
                if meta['support_multiuser']:
                    uname_key = meta.get("uname_key")
                    users = deepcopy(users_dt)
                    if uname_key:
                        for user in users:
                            _uname = user.pop('name')
                            user[uname_key] = _uname
                    content.update({"users":users})
                else:
                    # TODO
                    pass
                
                inbounds_res += [content]
                
        
        server_cfg_res['inbounds'] = inbounds_res
        dump_server_config(server_cfg_res, server_info["dst_server_cfg"])

    except Exception as e:
        resp_data['code'] = 0
        resp_data['info'] = 'Failed: ' + str(e)
        raise e
    return resp_data


def app():
    # 运行app
    pass


if __name__ == "__main__":
    # get_service_state()
    # print(service_op("status"))
    api_update_server()
    print(service_op("restart"))

    # a = get_random_password()
    # print(a)
