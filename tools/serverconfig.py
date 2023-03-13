from copy import deepcopy
from tools import common
import numpy as np


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

    
    random_numbers = np.arange(2000)
    np.random.shuffle(random_numbers)
    random_numbers = list(random_numbers)
    
    
    # 生成配置文件的inbounds
    inbounds_res = []
    interfaces = server_profile['inbounds']['interfaces']
    for tag, interface in interfaces.items():

        # 当前监听服务的描述信息
        meta = interface["meta"]
        p_content = interface["content"]
        
        rand_num = random_numbers[0]
        del random_numbers[0]
        
        
        tag_suffix = p_content['listen_port'] if "listen_port" in p_content.keys() else f"{rand_num:04d}"
        new_tag = f"{tag}-{tag_suffix}"
        
        # 生成shadowtls来通信
        if meta['shadowtls_mode'] in ['all', 'only_tls']:
            
            s_p = meta['tls_s_port']
            
            # 为保证兼容性 生成三个版本的配置
            # v1-v3的tls配置
            v1_shadow_tls = deepcopy(shadowtls_tp)
            listen_port = s_p
            v1_shadow_tls.update(
                {"tag":f"shadowtls-{listen_port}","listen_port": listen_port, "version": 1, "detour": new_tag})
            
            v2_shadow_tls = deepcopy(shadowtls_tp)
            listen_port += 1
            v2_shadow_tls.update(
                {"tag":f"shadowtls-{listen_port}","listen_port": listen_port, "version": 2, "detour": new_tag})
            v2_shadow_tls.update(v2_tp)

            v3_shadow_tls = deepcopy(shadowtls_tp)
            listen_port += 1
            v3_shadow_tls.update(
                {"tag":f"shadowtls-{listen_port}","listen_port": listen_port, "version": 3, "detour": new_tag, "users": users_dt})

            inbounds_res += [v1_shadow_tls, v2_shadow_tls, v3_shadow_tls]
        
        # 构建监听入口
        res_content = {"tag": new_tag}
        common.xj_update_dict(res_content, listen_common)
        
        if meta['use_tls']:
            res_content['tls'] = tls_common
        if meta['use_transport']:  
            res_content['transport'] = trans_common
        common.xj_update_dict(res_content, interface['content'])
        if meta['shadowtls_mode'] == 'only_tls':
            # 如果仅通过tls服务，则禁用外网监听
            res_content['listen'] = "127.0.0.1"
            # del res_content['listen_port']
        
        # 是否支持多用户
        if meta['support_multiuser']:
            uname_key = meta.get("uname_key")
            users = deepcopy(users_dt)
            if uname_key:
                for user in users:
                    _uname = user.pop('name')
                    user[uname_key] = _uname
            res_content.update({"users": users})
        else:
            # TODO 不支持多用户的情况下处理
            pass
        
        inbounds_res += [res_content]
    
    server_cfg_res['inbounds'] = inbounds_res
    
    common.dump_server_config(server_cfg_res, server_profile["dst_server_cfg"])
