import flask
import requests
from argparse import Namespace
import json
import yaml
import subprocess

service_state_cmd = "systemctl state sing-box"
service_restart_cmd = "systemctl state sing-box"
service_stop_cmd = "systemctl state sing-box"

def get_service_state():
    # return active, failed, stoped
    out = subprocess.Popen(service_state_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIP)
    a = out.readlins()
    print(a)
    

def service_op(op="status"):
    # 操作服务状态，并返回操作完成后的结果
    pass


def get_server_config():
    # 返回当前服务器信息，本地调用的功能函数
    pass


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
    # 查看服务状态和用户状态，流量等
    pass


def api_update_server():
    # 读取userconfig，更新到运行目录并重启服务器，然后查看服务器状态
    pass


def app():
    # 运行app
    pass


if __name__ == "__main__":
    args = Namespace(dst_server_cfg="/etc/sing-box/config.json", tp_server_cfg="./data/tp_server_cfg.json", users="./data/users.json", subscribe_tp="./data/clash_tp.yaml")




