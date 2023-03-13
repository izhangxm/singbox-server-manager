import json
import subprocess
import time
import ruamel.yaml
from base64 import b64encode
from secrets import token_bytes
from copy import deepcopy
import numpy as np
from io import StringIO 
yaml = ruamel.yaml.YAML()

service_state_cmd = "systemctl status sing-box"
service_restart_cmd = "systemctl restart sing-box"
service_stop_cmd = "systemctl stop sing-box"

class ClientApp():
    clash = "clash"
    stash = "stash"
    clashmeta = "clashmeta"
    shadowrocket = "shadowrocket"
    singbox = "singbox"

class ProxyProtocol():
    shadowsocks = "shadowsocks"
    http = "http"
    shadowtls= "shadowtls"
    trojan = "trojan"


class ServiceState():
    inactive = "inactive"
    active = "active"
    failed = "faild"

def xj_update_dict(base:dict, update:dict):
    # 仅支持两级更新
    for k,v in update.items():
        if k in base.keys():
            b_v = base[k]
            if isinstance(b_v, dict) and isinstance(v, dict):
                b_v.update(v)
            else:
                b_v = v
            base[k] = b_v
        else:
            base[k] = v

def load_server_profile(server_profile_file="./profile.yaml"):
    # server_info = json.load(open(args.server_info, 'r'))
    server_profile = yaml.load(open(server_profile_file, 'r'))
    return server_profile


def load_server_config(config_json_path):
    return json.load(open(config_json_path, 'r'))


def load_subscribe_tp(tp_type=ClientApp.clashmeta):
    server_profile = load_server_profile()

    if tp_type == ClientApp.singbox:
        subscribe_tp = yaml.load(open(server_profile['subscribe_singbox_tp'], 'r'))
    elif tp_type == ClientApp.clashmeta:
        subscribe_tp = yaml.load(open(server_profile['subscribe_clashmeta_tp'], 'r'))
    elif tp_type == ClientApp.clash:
        subscribe_tp = yaml.load(open(server_profile['subscribe_clash_tp'], 'r'))
    else:
        raise Exception("未知的订阅模板类型")

    return subscribe_tp


def dump_server_config(server_cfg, dst_server_cfg):

    json.dump(server_cfg, open(dst_server_cfg, 'w+'), sort_keys=False, indent=2, separators=(',', ':'))
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
    print(cmd)
    p = subprocess.Popen(cmd, shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    time.sleep(1)

    return get_service_state()


def get_default_resp_data():
    # 返回值模版
    return {"code": 1, "info": "ok"}
