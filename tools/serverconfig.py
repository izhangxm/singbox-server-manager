from copy import deepcopy
from flask import request
from tools import common


def update(server_profile):

    # 读取userconfig，更新到运行目录并重启服务器，然后查看服务器状态
    users = server_profile['users']

    server_cfg_res = {}

    users_dt = []
    for uname in users.keys():
        user = users[uname]
        users_dt.append({"name": uname, "password": user['password']})

    shadowtls_cfg = server_profile['inbounds']['shadowtls']
    listen_common = server_profile['inbounds']['listen']
    tls_common = server_profile['inbounds']['tls']
    trans_common = server_profile['inbounds']['transport']

    shadowtls_tp = shadowtls_cfg['common']
    shadowtls_tp.update(listen_common)
    v2_tp = shadowtls_cfg['v2']

    # dns 相关
    server_cfg_res['dns'] = server_profile['dns']

    # log 相关
    server_cfg_res['log'] = server_profile['log']

    # 生成配置文件的inbounds
    inbounds_res = []
    interfaces = server_profile['inbounds']['interfaces']
    for tag, interface in interfaces.items():

        # 当前监听服务的描述信息
        meta = interface["meta"]

        # 是否通过shadowtls来通信
        if meta['over_shadowtls']:
            s_p = meta['tls_s_port']
            # 为保证兼容性 生成三个版本的配置
            # v1-v3的tls配置
            v1_shadow_tls = deepcopy(shadowtls_tp)
            v1_shadow_tls.update(
                {"listen_port": s_p, "version": 1, "detour": tag})

            v2_shadow_tls = deepcopy(shadowtls_tp)
            v2_shadow_tls.update(
                {"listen_port": s_p+1, "version": 2, "detour": tag})
            v2_shadow_tls.update(v2_tp)

            v3_shadow_tls = deepcopy(shadowtls_tp)
            v3_shadow_tls.update(
                {"listen_port": s_p+2, "version": 3, "detour": tag, "users": users_dt})

            inbounds_res += [v1_shadow_tls, v2_shadow_tls, v3_shadow_tls]

            # 加密类型配置
            content = interface['content']
            content.update(listen_common)
            content.update({"listen": "127.0.0.1", "tag": tag})

            # 是否支持多用户
            if meta['support_multiuser']:
                uname_key = meta.get("uname_key")
                users = deepcopy(users_dt)
                if uname_key:
                    for user in users:
                        _uname = user.pop('name')
                        user[uname_key] = _uname
                content.update({"users": users})
            else:
                # TODO
                pass
            inbounds_res += [content]
        else:
            # 不通过tls的协议
            content = {"tag": tag}
            content['listen'] = listen_common
            content['tls'] = tls_common
            content['transport'] = trans_common
            common.xj_update_dict(content, interface['content'])
            # 是否支持多用户
            if meta['support_multiuser']:
                uname_key = meta.get("uname_key")
                users = deepcopy(users_dt)
                if uname_key:
                    for user in users:
                        _uname = user.pop('name')
                        user[uname_key] = _uname
                content.update({"users": users})
            else:
                # TODO
                pass
            inbounds_res += [content]
    
    server_cfg_res['inbounds'] = inbounds_res
    
    common.dump_server_config(server_cfg_res, server_profile["dst_server_cfg"])
