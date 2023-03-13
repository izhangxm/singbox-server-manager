from base64 import b64encode
from secrets import token_bytes
from copy import deepcopy
import numpy as np


def singbox(server_profile, server_config,  config_tp, username,client_shadowtls_versions=[1,2,3]):

    contry_code = server_profile['contry']

    server_url = server_profile['server_url']

    singbox_tp = config_tp

    # 最终的出口结果，模板中的也要继承
    outbounds_result = singbox_tp['outbounds']
    
    all_outbound_tags = []

    # 依靠tag来索引信息比较方便
    inbound_info = {}
    for inbound in server_config['inbounds']:
        tag = inbound.get("tag", False)
        if not tag:
            continue
        inbound['processed'] = False
        inbound_info[tag] = inbound

    random_numbers = np.arange(2000)
    np.random.shuffle(random_numbers)
    random_numbers = list(random_numbers)

    protocol_defult = server_profile['outbounds']['protocol_defult']
    
    for inbound in server_config['inbounds']:
        p_type = inbound['type']

        # 看是否已经被处理过
        tag = inbound.get("tag", False)
        if tag and inbound_info[tag]['processed']:
            continue
        
        if p_type == "shadowtls":
            # 这种类型的inbound不是真正的inbound 会有其他协议辅助才行，所以不会是直连
            shadowtls_in = inbound

            # 一定含有detour标签
            detour_tag = shadowtls_in['detour']

            detour_bound = inbound_info[detour_tag]
            inbound_info[detour_tag]['processed'] = True
            
            # 不论哪种协议，出口都是shadowtls
            rand_num = random_numbers[0]
            del random_numbers[0]
            _out_tag = f"shadowtls{rand_num:04d}"
            
            s_version = shadowtls_in["version"]
            
            if s_version not in client_shadowtls_versions:
                continue
            
            _tls_info = { 
                        "type": "shadowtls",  
                        "tag": _out_tag,
                        "version":shadowtls_in["version"],
                        "server": server_url,
                        "server_port": shadowtls_in['listen_port'],
                        "tls": { "enabled": True, "server_name": shadowtls_in['handshake']["server"] } 
                        }
            
            if shadowtls_in['version'] == 2:
                _tls_info['password'] = shadowtls_in["password"]
            elif shadowtls_in['version'] == 3:
                password = [x['password'] for x in shadowtls_in['users'] if x['name'] == username][0]
                _tls_info['password'] = password
                
            outbounds_result.append(_tls_info)
            
            _ccc_out_tag = None
            
            # 处理shadowsocks类型的信息
            if detour_bound['type'] == "shadowsocks":
                _upass = [x['password'] for x in detour_bound['users'] if x['name'] == username][0]
                
                _ccc_out_tag = f"{contry_code}-ss-v{s_version}"
                _ppp = deepcopy(protocol_defult['shadowsocks'])
                _ppp.update({
                    "type": "shadowsocks",
                    "tag": _ccc_out_tag,
                    "method": detour_bound['method'],
                    "password": f"{detour_bound['password']}:{_upass}",
                    "detour": _out_tag,
                })
                outbounds_result.append(_ppp)
                
            elif detour_bound['type'] == "http":
                password = [ x['password'] for x in detour_bound['users'] if x['username'] == username][0]
                _ccc_out_tag = f"{contry_code}-http-v{s_version}"
                _ppp = deepcopy(protocol_defult['http'])
                _ppp.update({
                    "type": "http",
                    "tag": _ccc_out_tag,
                    "username": username,
                    "password": password,
                    "detour": _out_tag,
                    })
                outbounds_result.append(_ppp)
            
            # 处理完成
            if _ccc_out_tag is None:
                raise Exception("有类型未处理out-tag")
            all_outbound_tags.append(_ccc_out_tag)
            
        elif p_type == "trojan":
            _ccc_out_tag = f"{contry_code}-tron-ws"
            password = [ x['password'] for x in inbound['users'] if x['name'] == username][0]
            _ppp = {
                "tag": _ccc_out_tag,
                "server": server_url,
                "server_port": inbound['listen_port'],
                "password":password,
                "type": "trojan",
                "network": "tcp",
                "tls":{
                    "disable_sni": False,
                    "insecure": False,
                    "alpn": inbound['tls']['alpn'],
                    "min_version": inbound['tls']['min_version'],
                    "max_version": inbound['tls']['max_version'],
                    "cipher_suites": inbound['tls']['cipher_suites']
                },
                "transport":inbound['transport']
            }
            _ppp['multiplex'] = server_profile['outbounds']['multiplex']
            
            outbounds_result.append(_ppp)
            # 处理完成
            all_outbound_tags.append(_ccc_out_tag)
    
    # 生成final出站 selector tag为final
    final_outbound =  {
            "type": "selector",
            "tag": "final",
            "outbounds": all_outbound_tags + ['direct'],
            "default": all_outbound_tags[0]
            }
    
    outbounds_result.append(final_outbound)
    # 整合完成，替换原本的配置
    singbox_tp["outbounds"] = outbounds_result
    
    return singbox_tp
    

def clashmeta(server_profile, server_config,  config_tp, username,client_shadowtls_versions=[2], is_shadowrocket = False):

    contry_code = server_profile['contry']
    server_url = server_profile['server_url']

    # 最终的出口结果，模板中的也要继承
    proxy_result = config_tp['proxies']
    all_proxy_names = []

    # 依靠tag来索引信息比较方便
    inbound_info = {}
    for inbound in server_config['inbounds']:
        tag = inbound.get("tag", False)
        if not tag:
            continue
        inbound['processed'] = False
        inbound_info[tag] = inbound

    random_numbers = np.arange(2000)
    np.random.shuffle(random_numbers)
    random_numbers = list(random_numbers)

    protocol_defult = server_profile['outbounds']['protocol_defult']
    
    for inbound in server_config['inbounds']:
        p_type = inbound['type']

        # 看是否已经被处理过
        tag = inbound.get("tag", False)
        if tag and inbound_info[tag]['processed']:
            continue
        
        if p_type == "shadowtls":
            # 这种类型的inbound不是真正的inbound 会有其他协议辅助才行，所以不会是直连
            shadowtls_in = inbound

            # 一定含有detour标签
            detour_tag = shadowtls_in['detour']
            detour_bound = inbound_info[detour_tag]
            inbound_info[detour_tag]['processed'] = True
            s_version = shadowtls_in["version"]
            if s_version not in client_shadowtls_versions:
                continue
            
            # shadowtls的password
            tls_password = ""
            if shadowtls_in['version'] == 2:
                tls_password = shadowtls_in["password"]
            elif shadowtls_in['version'] == 3:
                password = [x['password'] for x in shadowtls_in['users'] if x['name'] == username][0]
                tls_password = password
                
            _ccc_out_tag = None
            
            
            # 处理shadowsocks类型的信息
            if detour_bound['type'] == "shadowsocks":
                _upass = [x['password'] for x in detour_bound['users'] if x['name'] == username][0]
                _ccc_out_tag = f"{contry_code}-ss-v{s_version}"
                
                _ppp = { "type": "ss",
                    "cipher": detour_bound['method'],
                    "name": _ccc_out_tag,
                    "password": f"{detour_bound['password']}:{_upass}",
                    "port": shadowtls_in['listen_port'],
                    "server": server_url,
                    "udp": True,
                    "plugin": "shadow-tls",
                    "plugin-opts": {
                        "host": shadowtls_in['handshake']["server"],
                        "password": tls_password
                        }
                }
                
                if is_shadowrocket:
                    _ppp.pop("plugin-opts")
                    _ppp['pluginParam'] = {
                        "version" : s_version,
                        "host" : shadowtls_in['handshake']["server"]
                    }
                
                proxy_result.append(_ppp)
                
            elif detour_bound['type'] == "http":
                password = [ x['password'] for x in detour_bound['users'] if x['username'] == username][0]
                _ccc_out_tag = f"{contry_code}-http-v{s_version}"
                _ppp = {}
                _ppp.update({
                    "type": "http",
                    "name": _ccc_out_tag,
                    "username": username,
                    "password": password,
                    "server": server_url,
                    "port": shadowtls_in['listen_port'],
                    "plugin": "shadow-tls",
                    "plugin-opts": {
                        "host": shadowtls_in['handshake']["server"],
                        "password": tls_password
                        }
                    })
                if is_shadowrocket:
                    _ppp.pop("plugin-opts")
                    _ppp['pluginParam'] = {
                        "version" : s_version,
                        "host" : shadowtls_in['handshake']["server"]
                    }
                proxy_result.append(_ppp)
            
            # 处理完成
            if _ccc_out_tag is not  None:
                all_proxy_names.append(_ccc_out_tag)
        elif p_type == "trojan":
            _ccc_out_tag = f"{contry_code}-tron-ws"
            password = [ x['password'] for x in inbound['users'] if x['name'] == username][0]
            _ppp = {
                "name": _ccc_out_tag,
                "server": server_url,
                "port": inbound['listen_port'],
                "password":password,
                "type": "trojan",
                "network": "ws",
                "sni": server_url,
                "udp": True,
                "ws-opts":{
                    "path": inbound['transport']['path']
                }
            }
            
            proxy_result.append(_ppp)
            # 处理完成
            all_proxy_names.append(_ccc_out_tag)
    
    
    config_tp['proxies'] = proxy_result
    
    config_tp["proxy-groups"][0]['proxies'] = all_proxy_names
    
    return config_tp
    
        