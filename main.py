#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tkinter import *
import re
import time
def fofa_find_NOT(text):
    ls = []
    pattern = r'\b([a-z_]+)(\s*!=)'
    matches = re.findall(pattern, text)
    for match in matches:
        ls.append(''.join(match))
    return ls

def hunter_find_NOT(text):
    ls = []
    # 定义正则表达式模式，只捕获 "NOT" 后面的单词
    # pattern = r'NOT\s+([a-zA-Z_]+)'
    pattern = r'\b([a-z_.]+)(\s*!=)'
    # 使用正则表达式搜索文本
    matches = re.findall(pattern, text)
    for match in matches:
        ls.append(''.join(match))
    return ls

def quake_find_NOT(text):
    ls = []
    pattern = r'NOT\s+(\w+):\s*"([^"]+)"'
    # 使用正则表达式搜索文本
    matches = re.findall(pattern, text)
    for match in matches:
        ls.append(match)
    return ls

def remove_blacklisted_fields(query, blacklist):
    # 构建一个正则表达式模式，匹配以黑名单字段开始的整个字段表达式
    # \s* 匹配任意空白字符（包括空格、制表符等）
    # .*? 非贪婪匹配任意字符直到遇到下一个特定的模式（这里是 && 或 || 或字符串结束）
    # (&&|\|\|)? 匹配 && 或 || ，出现0次或1次，用于处理逻辑运算符
    new_query = query
    for blacklist_field in blacklist:
        pattern = r'(\b' + re.escape(blacklist_field) + r'\s*[^&|]*?\S)(?=\s*(&&|\|\|)\s*|\Z)'

        # 使用 re.sub 函数替换掉所有匹配的字段表达式
        new_query = re.sub(pattern, ' ', new_query)

        # 移除可能产生的连续逻辑运算符
        new_query = re.sub(r'(\s*&&\s*\|\|\s*|\s*\|\|\s*&&\s*)+', ' ', new_query).strip()

    return new_query

def extract_ports(query):
    # 正则表达式匹配 "ip.ports=" 后面的数字
    pattern = r'ip\.ports="?(\d+)"?'

    # 使用 re.findall 找到所有匹配的数字
    ports = re.findall(pattern, query)

    return ','.join(ports)

def fofa_to_quake(source):
    text = source.init_data_Text.get(1.0, END).strip().replace("\n", "")
    not_list = fofa_find_NOT(text)
    for not_word in not_list:
        text = text.replace(not_word, "NOT "+not_word[:-2]+":")
    text = text.replace('=', ':')
    text = text.replace("==", ":")
    text = text.replace("&&", " AND ")
    text = text.replace("||", " OR ")
    text = text.replace("server", "app")
    text = text.replace("base_protocol", "transport")
    text = text.replace("region", "province")
    text = text.replace("product", "app")
    text = text.replace('category', 'app')
    text = text.replace('banner', 'response')
    text = text.replace('protocol', 'service')
    text = text.replace('header', 'headers')
    text = text.replace('header_hash', 'header_order_hash')
    text = text.replace('body_hash', 'html_hash')
    text = text.replace('cname', 'hostname')
    text = text.replace('icon_hash', 'favicon')

    blacklist = ['fid', 'product', 'fid', 'type', 'cloud_name', 'is_cloud', 'is_fraud', 'is_honeypot', 'js_name', 'js_md5', 'cname_domain', 'sdk_hash', 'cert.subject', 'cert.issuer', 'cert.subject.org', 'cert.subject.cn', 'cert.issuer.org', 'cert.issuer.cn', 'cert.is_valid', 'cert.is_match', 'cert.is_expired', 'jarm', 'tls.version', 'tls.ja3s', 'after', 'before', 'after&before']
    text = remove_blacklisted_fields(text, blacklist)
    text = text.replace('&&   ', '')
    text = text.replace('||   ', '')
    text = text.rstrip('AND').rstrip('OR')
    source.result_data_Text.delete(1.0, END)
    source.result_data_Text.insert(1.0, text)

def hunter_to_quake(source):
    text = source.init_data_Text.get(1.0, END).strip().replace("\n", "")
    not_list = hunter_find_NOT(text)
    for not_word in not_list:
        text = text.replace(not_word, "NOT " + not_word[:-2] + ":")
    text = text.replace('=', ':')
    text = text.replace("==", ":")
    text = text.replace("&&", " AND ")
    text = text.replace("||", " OR ")
    text = text.replace("domain.name_server", 'domain')
    # text = text.replace("web.tag", )
    text = text.replace("ip.port", 'port')
    text = text.replace('ip.country', 'country')
    text = text.replace('ip.province', 'province_cn')
    text = text.replace('ip.city', 'city_cn')
    text = text.replace('ip.isp', 'isp')
    text = text.replace('ip.os', 'os')
    #port
    port = extract_ports(text)
    if port != '':
        text = text + ' AND ports=' + port
    text = text.replace('ip.port_count', 'port')
    text = text.replace('header.server', 'server')
    text = text.replace('header.status_code', 'server')
    text = text.replace('web.title', 'title')
    text = text.replace('web.body', 'body')
    text = text.replace('icp.number', 'icp')
    text = text.replace('icp.type', 'icp_nature')
    text = text.replace('icp.web_name', 'icp_keywords')
    text = text.replace('icp.name', 'icp_keywords')
    text = text.replace('protocol', 'service')
    text = text.replace('protocol.transport', 'transport')
    text = text.replace('protocol_banner', 'response')
    text = text.replace('app.name', 'app')
    text = text.replace('app.version', 'app_version')
    text = text.replace('app.vendor', 'powered_by')
    text = text.replace('cert_subject', 'cert')
    text = text.replace('cert.subject_suffix', 'cert')
    text = text.replace('cert.subject_org', 'cert')
    text = text.replace('as.number', 'asn')
    text = text.replace('web.tag', 'page_type')
    text = text.replace('web.icon', 'favicon')
    blacklist = ['tls-jarm.hash', 'tls-jarm.ans', 'as.name', 'as.org', 'vul.gev', 'vul.cve', 'web.is_vul','cert.sha-1','cert.sha-256','cert.sha-md5', 'cert.serial_number', 'cert.is_expired', 'cert.is_trust','cert.issuer', 'cert.issuer_org','icp.web_name','icp.name','icp.industry','icp.is_exception','after', 'before', 'web.similar', 'web.similar_icon', 'web.similar_id','is_web', 'header.content_length','domain.created_date','domain.expires_date','domain.updated_date','domain.cname','is_domain.cname','domain.status', 'domain.whois_server','ip.ports', 'ip.tag', 'web.similar', 'web.similar_icon', 'web.similar_id', 'domain.suffix', 'web.icon', 'ip.port_count', 'is_web', 'cert.is_trust', 'icp.is_exception', 'domain.cname', 'domain.status', 'domain.whois_server']
    text = remove_blacklisted_fields(text, blacklist)
    text = text.replace('&&   ', '')
    text = text.replace('||   ', '')
    text = text.rstrip('AND').rstrip('OR')
    text = text.replace('  ',' ')
    text = text.replace('   ', ' ')
    source.result_data_Text.delete(1.0, END)
    source.result_data_Text.insert(1.0, text)

def quake_to_hunter(source):
    text = source.init_data_Text.get(1.0, END).strip().replace("\n", "")
    not_list = quake_find_NOT(text)
    for not_word in not_list:
        text = text.replace("NOT "+ not_word[0] + ':', not_word[0] + "!=")
    text = text.replace(" AND ", "&&")
    text = text.replace(" OR ", "||")
    text = text.replace("port", "ip.port")
    # text = text.replace('ports', 'ip.ports')
    #端口范围
    #多端口
    text = text.replace('transport', 'protocol.transport')
    text = text.replace('asn', 'as.number')
    text = text.replace('org', 'as.org')
    text = text.replace('os', 'ip.os')
    text = text.replace('service', 'protocol')
    text = text.replace('app', 'app.name')
    text = text.replace('app_version', 'app.version')
    text = text.replace('response', 'protocol_banner')
    text = text.replace('country', 'ip.country')
    text = text.replace('country_cn', 'ip.country')
    text = text.replace('province', 'ip.province')
    text = text.replace('province_cn', 'ip.province')
    text = text.replace('city', 'ip.city')
    text = text.replace('city_cn', 'ip.city')
    text = text.replace('isp', 'ip.isp')
    text = text.replace('status_code', 'header.status_code')
    text = text.replace('title', 'web.title')
    text = text.replace('server', 'header.server')
    text = text.replace('powered_by', 'app.vendor')
    text = text.replace('favicon', 'web.icon')
    text = text.replace('headers', 'header')
    text = text.replace('body', 'web.body')
    text = text.replace('icp_nature', 'icp.type')
    text = text.replace('icp_keywords', 'icp.name')
    text = text.replace('page_type', 'web.tag')
    text = text.replace('icp:', 'icp.number:')
    text = text.replace(':', '=')
    blacklist = ['is_latest', 'tls_client_version', 'tls_server_version', 'tls_subject_O', 'tls_subject_C', 'tls_subject_CN', 'tls_subject', 'tls_issuer_O', 'tls_issuer_C', 'tls_issuer_CN', 'tls_issuer', 'tls_SN', 'tls_SPKI', 'tls_SAN', 'tls_SKID', 'tls_md5', 'tls_sha1', 'tls_sha256', 'tls_AKID', 'service.smb.RemoteName', 'ervice.smb.ServerDomain', 'service.smb.ServerOS', 'service.smb.Authentication', 'service.smb.Capabilities', 'service.smb.ListDialects', 'service.smb.ServerDefaultDialect', 'service.s7.Serial_number_of_memory_card', 'service.s7.Module_type_name', 'service.s7.Plant_identification', 'service.s7.Name_of_the_module', 'service.s7.Name_of_the_PLC', 'service.s7.Basic_Firmware', 'service.s7.Basic_Hardware', 'service.s7.Module', 'service.modbus.MemoryCard', 'service.modbus.CpuModule', 'service.modbus.SlaveIDdata', 'service.modbus.DeviceIdentification', 'service.modbus.UnitId', 'service.ethernetip.serial_num', 'service.ethernetip.revision', 'service.ethernetip.vendor', 'service.ethernetip.device_ip', 'service.ethernetip.product_code', 'service.ethernetip.product_name', 'service.mongodb.listDatabases.totalSize', 'service.mongodb.listDatabases.databases.sizeOnDisk', 'service.mongodb.listDatabases.databases.name', 'service.mongodb.serverStatus.connections.totalCreated', 'service.mongodb. serverStatus.connections.available', 'service.mongodb.serverStatus.connections.current', 'service.mongodb.serverStatus.pid', 'service.mongodb.serverStatus.process', 'service.mongodb.serverStatus.host', 'service.mongodb.buildInfo.gitVersion', 'service.mongodb.buildInfo.version', 'service.hive.hive_dbs.tables', 'service.hive.hive_dbs.dbname', 'service.elastic.indices.store_size', 'service.elastic.indices.docs_count', 'service.elastic.indices.index', 'service.elastic.indices.status', 'service.elastic.indices.health', 'service.domain.version_bind', 'service.domain.id_server', 'service.docker.version.BuildTime', 'service.docker.version.KernelVersion', 'service.docker.version.Arch', 'service.docker.version.GoVersion', 'service.docker.version.GitCommit', 'service.docker.version.MinAPIVersion', 'service.docker.version.ApiVersion', 'service.docker.version.Version', 'service.docker.containers.Command', 'service.docker.containers.Image', 'service.snmp.sysobjectid', 'service.snmp.syscontact', 'service.snmp.syslocation', 'service.snmp.sysuptime', 'service.snmp.sysdesc', 'service.snmp.sysname', 'service.upnp.friendlyName', 'service.upnp.manufacturer', 'service.upnp.modelDescription', 'service.upnp.modelName', 'service.upnp.modelNumber', 'service.ssh.server_keys.type', 'service.ssh.server_keys.fingerprint', 'service.ssh.ciphers', 'service.ssh.kex', 'service.ssh.digests', '	service.ssh.key_types', 'service.rsync.authentication', 'service.ftp.is_anonymous', 'domain_is_wildcard', 'district', 'iframe_keywords', 'iframe_title', 'iframe_hash', 'iframe_url', 'page_type', 'mail', 'copyright', 'css_id', 'url_load', 'css_id', 'css_class	', 'script_variable', 'script_function', 'dom_tree.dom_hash	', 'dom_tree.key	', 'dom_tree.simhash	', 'cookie_order_hash', 'cookie_simhash', 'sitemap', 'sitemap_hash', 'robots', 'robots_hash', 'header_order_hash', 'html_hash', 'host', 'meta_keywords', 'http_path','hostname', 'services', 'catalog', 'type', 'level', 'vendor', 'district', 'owner', 'img_tag', 'img_ocr', 'sys_tag']
    text = remove_blacklisted_fields(text, blacklist)
    text = text.replace('&&   ', '')
    text = text.replace('||   ', '')
    text = text.rstrip('AND').rstrip('OR')
    text = text.replace('  ',' ')
    text = text.replace('   ', ' ')
    source.result_data_Text.delete(1.0, END)
    source.result_data_Text.insert(1.0, text)

def quake_to_fofa(source):
    text = source.init_data_Text.get(1.0, END).strip().replace("\n", "")
    not_list = quake_find_NOT(text)
    for not_word in not_list:
        text = text.replace("NOT " + not_word[0] + ':', not_word[0] + "!=")
    text = text.replace(" AND ", "&&")
    text = text.replace(" OR ", "||")
    text = text.replace("hostname", "cname")
    text = text.replace("service", "protocol")
    #port范围
    text = text.replace("transport", 'base_protocol')
    text = text.replace("response", "banner")
    text = text.replace("country_cn", "country")
    text = text.replace("province", "region")
    text = text.replace("province_cn", "region")
    text = text.replace("server", "header")
    text = text.replace("favicon", "icon_hash")
    text = text.replace("html_hash", "body_hash")
    text = text.replace("headers", "header")
    text = text.replace("header_order_hash", "header_hash")
    text = text.replace("tls_client_version", "tls.version")
    blacklist = ['icp_nature', 'icp_keywords', 'powered_by', 'city_cn', 'app_version', 'services','ports', 'is_latest', 'tls_client_version', 'tls_server_version', 'tls_subject_O', 'tls_subject_C', 'tls_subject_CN', 'tls_subject', 'tls_issuer_O', 'tls_issuer_C', 'tls_issuer_CN', 'tls_issuer', 'tls_SN', 'tls_SPKI', 'tls_SAN', 'tls_SKID', 'tls_md5', 'tls_sha1', 'tls_sha256', 'tls_AKID', 'service.smb.RemoteName', 'ervice.smb.ServerDomain', 'service.smb.ServerOS', 'service.smb.Authentication', 'service.smb.Capabilities', 'service.smb.ListDialects', 'service.smb.ServerDefaultDialect', 'service.s7.Serial_number_of_memory_card', 'service.s7.Module_type_name', 'service.s7.Plant_identification', 'service.s7.Name_of_the_module', 'service.s7.Name_of_the_PLC', 'service.s7.Basic_Firmware', 'service.s7.Basic_Hardware', 'service.s7.Module', 'service.modbus.MemoryCard', 'service.modbus.CpuModule', 'service.modbus.SlaveIDdata', 'service.modbus.DeviceIdentification', 'service.modbus.UnitId', 'service.ethernetip.serial_num', 'service.ethernetip.revision', 'service.ethernetip.vendor', 'service.ethernetip.device_ip', 'service.ethernetip.product_code', 'service.ethernetip.product_name', 'service.mongodb.listDatabases.totalSize', 'service.mongodb.listDatabases.databases.sizeOnDisk', 'service.mongodb.listDatabases.databases.name', 'service.mongodb.serverStatus.connections.totalCreated', 'service.mongodb. serverStatus.connections.available', 'service.mongodb.serverStatus.connections.current', 'service.mongodb.serverStatus.pid', 'service.mongodb.serverStatus.process', 'service.mongodb.serverStatus.host', 'service.mongodb.buildInfo.gitVersion', 'service.mongodb.buildInfo.version', 'service.hive.hive_dbs.tables', 'service.hive.hive_dbs.dbname', 'service.elastic.indices.store_size', 'service.elastic.indices.docs_count', 'service.elastic.indices.index', 'service.elastic.indices.status', 'service.elastic.indices.health', 'service.domain.version_bind', 'service.domain.id_server', 'service.docker.version.BuildTime', 'service.docker.version.KernelVersion', 'service.docker.version.Arch', 'service.docker.version.GoVersion', 'service.docker.version.GitCommit', 'service.docker.version.MinAPIVersion', 'service.docker.version.ApiVersion', 'service.docker.version.Version', 'service.docker.containers.Command', 'service.docker.containers.Image', 'service.snmp.sysobjectid', 'service.snmp.syscontact', 'service.snmp.syslocation', 'service.snmp.sysuptime', 'service.snmp.sysdesc', 'service.snmp.sysname', 'service.upnp.friendlyName', 'service.upnp.manufacturer', 'service.upnp.modelDescription', 'service.upnp.modelName', 'service.upnp.modelNumber', 'service.ssh.server_keys.type', 'service.ssh.server_keys.fingerprint', 'service.ssh.ciphers', 'service.ssh.kex', 'service.ssh.digests', '	service.ssh.key_types', 'service.rsync.authentication', 'service.ftp.is_anonymous', 'domain_is_wildcard', 'district', 'iframe_keywords', 'iframe_title', 'iframe_hash', 'iframe_url', 'page_type', 'mail', 'copyright', 'css_id', 'url_load', 'css_id', 'css_class	', 'script_variable', 'script_function', 'dom_tree.dom_hash	', 'dom_tree.key	', 'dom_tree.simhash	', 'cookie_order_hash', 'cookie_simhash', 'sitemap', 'sitemap_hash', 'robots', 'robots_hash', 'header_order_hash', 'html_hash', 'host', 'meta_keywords', 'http_path','hostname', 'services', 'catalog', 'type', 'level', 'vendor', 'district', 'owner', 'img_tag', 'img_ocr', 'sys_tag']
    text = remove_blacklisted_fields(text, blacklist)
    text = text.replace(":", "=")
    text = text.replace('&&   ', '')
    text = text.replace('||   ', '')
    text = text.strip('&&').strip('||').strip()
    # text = text.rstrip('AND').rstrip('OR')
    text = text.replace('  ', ' ')
    text = text.replace('   ', ' ')
    source.result_data_Text.delete(1.0, END)
    source.result_data_Text.insert(1.0, text)

def fofa_to_hunter(source):
    text = source.init_data_Text.get(1.0, END).strip().replace("\n", "")
    print(text)
    # not_list = hunter_find_NOT(text)
    # for not_word in not_list:
    #     text = text.replace(not_word, "NOT " + not_word[:-2] + ":")
    text = text.replace("port", "ip.port")
    text = text.replace("os", "ip.os")
    text = text.replace("server", "header.server")
    text = text.replace("asn", "as.number")
    text = text.replace("org", "as.org")
    text = text.replace("product", "app.name")
    text = text.replace("category", "app.type")
    text = text.replace("banner", "protocol.banner")
    text = text.replace("base_protocol", "protocol.transport")
    text = text.replace("title", "web.title")
    text = text.replace("body", "web.body")
    text = text.replace("cname", 'domain.cname')
    text = text.replace("icon_hash", 'web.icon')
    text = text.replace("status_code", "header.status_code")
    text = text.replace("icp", "icp.number")
    text = text.replace("country", 'ip.country')
    text = text.replace("region", "ip.province")
    text = text.replace("city", "ip.city")
    text = text.replace("cert.subject.cn", "cert.subject")
    text = text.replace("cert.subject.org", "cert.subject_org")
    text = text.replace("cert.issuer.org", "cert.issuer_org")
    text = text.replace("cert.issuer.cn", "cert.issuer")
    text = text.replace("jarm", "tls-jarm.hash")
    blacklist = ['tls.version', 'tls.ja3s', 'cert.is_valid	', 'cert.is_match', 'sdk_hash', 'cname_domain', 'body_hash', 'js_name', 'js_md5', 'cloud_name', 'is_cloud', 'is_fraud', 'is_honeypot', 'type', 'app', 'host', 'is_ipv6']

    text = remove_blacklisted_fields(text, blacklist)
    text = text.replace('&&   ', '')
    text = text.replace('||   ', '')
    text = text.strip('&&').strip('||').strip()
    # text = text.rstrip('AND').rstrip('OR')
    text = text.replace('  ', ' ')
    text = text.replace('   ', ' ')
    source.result_data_Text.delete(1.0, END)
    source.result_data_Text.insert(1.0, text)

def hunter_to_fofa(source):
    text = source.init_data_Text.get(1.0, END).strip().replace("\n", "")
    text = text.replace('ip.port', 'port')
    text = text.replace('ip.country', 'country')
    text = text.replace('ip.province', 'region')
    text = text.replace('ip.city', 'city')
    text = text.replace('ip.os', 'os')
    text = text.replace('domain.suffix', 'domain')
    text = text.replace('domain.cname', 'cname')
    text = text.replace('header.server', 'server')
    text = text.replace('header.status_code', 'status_code')
    text = text.replace('web.title', 'title')
    text = text.replace('web.body', 'body')
    text = text.replace('web.icon', 'icon_hash')
    text = text.replace('icp.number', 'icp')
    text = text.replace('protocol.transport', 'base_protocol')
    text = text.replace('protocol.banner', 'banner')
    text = text.replace('app.name', 'app')
    text = text.replace('cert.subject_suffix', 'cert.subject')
    text = text.replace('cert.subject_org', 'cert.subject.org')
    text = text.replace('cert.issuer_org', 'cert.issuer.org')
    text = text.replace('as.number', 'asn')
    text = text.replace('as.org', 'org')
    text = text.replace('tls-jarm.hash', 'jarm')

    blacklist = ['tls-jarm.ans', 'as.name', 'vul.get', 'vul.cve', 'vul.gev', 'web.is_vul', 'cert.is_trust', 'cert.sha-1', 'cert.sha-245', 'cert.sha-md5', 'cert.serial_number', 'app.type', 'app.vendor', 'app.version', 'icp.web_name', 'icp.name', 'icp.type', 'icp.industry', 'icp.exception', 'web.similar_id', 'web.tag', 'web.similar', 'web.similar_icon', 'is_web', 'header.content_length', 'is_domain_cname', 'ip.isp', 'ip.port_count', 'ip.ports', 'ip.tag', 'domain.status', 'domain.whois_server', 'domain.name_server', 'domain.created_date', 'domain.expires_date', 'domain.updated_date']

    text = remove_blacklisted_fields(text, blacklist)
    text = text.replace('&&   ', '')
    text = text.replace('||   ', '')
    text = text.strip('&&').strip('||').strip()
    # text = text.rstrip('AND').rstrip('OR')
    text = text.replace('  ', ' ')
    text = text.replace('   ', ' ')
    source.result_data_Text.delete(1.0, END)
    source.result_data_Text.insert(1.0, text)
    # return text
def gui_start():
    global LOG_LINE_NUM  # 声明为全局变量以便在函数间共享
    LOG_LINE_NUM = 0  # 初始化日志行数
    init_window = Tk()
    init_window.title("测绘平台语法互转")
    init_window.geometry('1000x300+10+10')

    init_window.init_data_label = Label(init_window, text="原始语句")
    init_window.init_data_label.grid(row=0, column=0)
    init_window.result_data_label = Label(init_window, text="转后结果")
    init_window.result_data_label.grid(row=0, column=12)

    init_window.init_data_Text = Text(init_window, width=67, height=20)
    init_window.init_data_Text.grid(row=1, column=0, rowspan=10, columnspan=10)
    init_window.result_data_Text = Text(init_window, width=70, height=20)
    init_window.result_data_Text.grid(row=1, column=12, rowspan=15, columnspan=10)

    init_window.str_trans_to_md5_button = Button(init_window, text="fofa转quake", bg="lightblue", width=15, command=lambda: fofa_to_quake(init_window))
    init_window.str_trans_to_md5_button.grid(row=1, column=11)
    init_window.str_trans_to_md5_button = Button(init_window, text="fofa转hunter", bg="lightgreen", width=15, command=lambda: fofa_to_hunter(init_window))
    init_window.str_trans_to_md5_button.grid(row=2, column=11)
    init_window.str_trans_to_md5_button = Button(init_window, text="quake转hunter", bg="gray", width=15, command=lambda: quake_to_hunter(init_window))
    init_window.str_trans_to_md5_button.grid(row=3, column=11)
    init_window.str_trans_to_md5_button = Button(init_window, text="quake转fofa", bg="orange", width=15, command=lambda: quake_to_fofa(init_window))
    init_window.str_trans_to_md5_button.grid(row=4, column=11)
    init_window.str_trans_to_md5_button = Button(init_window, text="hunter转fofa", bg="yellow", width=15, command=lambda: hunter_to_fofa(init_window))
    init_window.str_trans_to_md5_button.grid(row=5, column=11)
    init_window.str_trans_to_md5_button = Button(init_window, text="hunter转quake", bg="brown", width=15, command=lambda: hunter_to_quake(init_window))
    init_window.str_trans_to_md5_button.grid(row=6, column=11)
    init_window.mainloop()

gui_start()