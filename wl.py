# -*- coding: utf-8 -*-

import sys
reload(sys)
sys.setdefaultencoding('utf-8') # 解决 UnicodeEncodeError

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import subprocess
import cgi
import re
import os
import base64
import hashlib
import time
from datetime import datetime, timedelta
import random
import string

HOST_NAME = '0.0.0.0'
PORT_NUMBER = 62371
USERS_FILE = 'users.conf'
WHITELIST_FILE = 'whitelisted_ips.conf'
IPTABLES_INIT_FILE = 'iptables.init' # 定义 iptables 初始备份文件

# --- 全局辅助函数：用户认证、密码管理和防火墙操作 ---

def load_users():
    """从文件中加载用户数据，返回 {username: password_hash} 字典"""
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    username, password = line.split(':', 1)
                    users[username] = password
    return users

def save_users(users):
    """将用户数据保存到文件"""
    with open(USERS_FILE, 'w') as f:
        for username, password in users.items():
            f.write("%s:%s\n" % (username, password))

def check_auth(username, password):
    """检查用户名和密码是否正确"""
    users = load_users()
    return users.get(username) == password

def generate_random_password(length=12):
    """生成一个包含大小写字母、数字和符号的随机密码"""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def _check_firewall_rule_exists(ip_address=None, port=None, proto='tcp'):
    """检查防火墙规则是否已存在"""
    command = ["sudo", "iptables", "-C", "INPUT"]
    if ip_address:
        command.extend(["-s", ip_address])
    if port:
        command.extend(["-p", proto, "--dport", str(port)])

    command.extend(["-j", "ACCEPT"])

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.communicate()
        return process.returncode == 0
    except Exception as e:
        print "检查防火墙规则时发生错误:", e
        return False

def _save_firewall_rules():
    """保存防火墙规则到文件（并复制到 iptables.init）"""
    save_system_rules_command = ["sudo", "service", "iptables", "save"]
    copy_to_init_command = ["sudo", "cat", "/etc/sysconfig/iptables", ">", IPTABLES_INIT_FILE] # 假设系统规则文件在此位置

    print "正在保存防火墙规则到系统默认位置..."
    try:
        process = subprocess.Popen(save_system_rules_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            print "防火墙规则成功保存到系统默认位置。"
            if stdout: print "Save stdout:", stdout.strip()

            # 额外执行：将系统规则文件复制到 iptables.init
            print "正在将系统保存的规则复制到 %s..." % IPTABLES_INIT_FILE
            # 注意：这里不能直接使用 subprocess.Popen(copy_to_init_command)
            # 因为 ">" 是 shell 语法，需要 shell=True 或者使用文件重定向
            # 为了安全和明确，我们直接读取文件内容再写入
            try:
                # 检查 /etc/sysconfig/iptables 是否存在
                if not os.path.exists("/etc/sysconfig/iptables"):
                    # 针对基于Debian/Ubuntu的系统，规则可能在 /etc/iptables/rules.v4
                    # 您需要根据实际系统调整此路径。这里提供一个通用警告。
                    print "警告: /etc/sysconfig/iptables 文件不存在。尝试查找 /etc/iptables/rules.v4..."
                    system_rules_path = "/etc/iptables/rules.v4"
                    if not os.path.exists(system_rules_path):
                         print "错误: 无法找到系统默认的 iptables 规则文件（/etc/sysconfig/iptables 或 /etc/iptables/rules.v4）。无法更新 %s。" % IPTABLES_INIT_FILE
                         return True, "系统规则文件未找到，仅保存了系统规则，未更新 iptables.init。"
                else:
                    system_rules_path = "/etc/sysconfig/iptables"


                # 读取系统保存的规则文件内容
                cat_command = ["sudo", "cat", system_rules_path]
                cat_process = subprocess.Popen(cat_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                cat_stdout, cat_stderr = cat_process.communicate()

                if cat_process.returncode == 0:
                    with open(IPTABLES_INIT_FILE, 'w') as f_init:
                        f_init.write(cat_stdout)
                    print "系统规则已成功复制到 %s。" % IPTABLES_INIT_FILE
                    return True, ""
                else:
                    error_msg = "复制系统规则到 %s 失败。cat 命令错误: %s" % (IPTABLES_INIT_FILE, cat_stderr.strip().decode('utf-8', errors='ignore'))
                    print error_msg
                    return False, error_msg # 虽然系统保存成功，但复制失败，所以返回失败
            except Exception as e:
                error_msg = "执行复制到 %s 命令时发生错误: %s" % (IPTABLES_INIT_FILE, e)
                print error_msg
                return False, error_msg # 复制失败，返回失败

        else:
            print "防火墙规则保存到系统默认位置失败。"
            if stderr:
                error_msg = "service iptables save 错误: %s" % stderr.strip().decode('utf-8', errors='ignore')
                print error_msg
                return False, error_msg
            return False, "未知 service iptables save 错误。"
    except Exception as e:
        print "执行防火墙保存命令时发生错误:", e
        return False, str(e)

# --- IP 白名单管理函数（带有效期） ---

def load_whitelisted_ips():
    """从文件中加载 IP 白名单及其过期时间，返回 {ip: expiration_timestamp} 字典"""
    ips = {}
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ',' in line:
                    ip, timestamp_str = line.split(',', 1)
                    try:
                        ips[ip] = float(timestamp_str)
                    except ValueError:
                        print "警告: 无效的过期时间戳格式在文件中:", line
                        continue
    return ips

def save_whitelisted_ips(ips):
    """将 IP 白名单及其过期时间保存到文件"""
    with open(WHITELIST_FILE, 'w') as f:
        for ip, timestamp in ips.items():
            f.write("%s,%f\n" % (ip, timestamp))

def add_ip_to_whitelist(ip_address, days_valid=None):
    """
    添加 IP 地址到白名单，并记录过期时间。
    days_valid: 如果是整数，表示加白天数；如果为 None，表示永久。
    """
    current_ips = load_whitelisted_ips()
    now = time.time()

    # 检查IP是否已在白名单中且未过期
    if ip_address in current_ips:
        exp_time = current_ips[ip_address]
        # 如果是永久，或过期时间在未来
        if exp_time == 0 or exp_time > now:
            print "IP %s 已存在于内部白名单中且未过期。" % ip_address
            # 如果选择永久，且当前不是永久，则更新为永久
            if days_valid is None and exp_time != 0:
                print "更新 IP %s 为永久白名单。" % ip_address
                current_ips[ip_address] = 0 # 0 表示永久
                save_whitelisted_ips(current_ips)
                # 由于iptables规则是无期的，无需重新添加iptables规则
                return u"IP 地址 %s 已存在并已更新为永久白名单。" % ip_address, u"info"
            else:
                return u"IP 地址 %s 已存在于白名单中且未过期，无需重复添加。" % ip_address, u"info"

    # 计算过期时间
    if days_valid is None:
        expiration_timestamp = 0 # 0 表示永久
    else:
        expiration_timestamp = now + (days_valid * 24 * 60 * 60) # 秒数

    # 尝试添加到 iptables
    message_text = u""
    message_class = u"error"

    if not re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", ip_address):
        return u"无效的 IP 地址格式: %s" % ip_address, u"error"

    # 再次检查防火墙规则（外部，防止内部文件与实际规则不同步）
    if _check_firewall_rule_exists(ip_address=ip_address):
        # 内部文件没有，但iptables有，则修复内部文件
        print "IP %s 内部白名单文件无记录但防火墙规则已存在，修复内部记录。" % ip_address
        current_ips[ip_address] = expiration_timestamp
        save_whitelisted_ips(current_ips)
        return u"IP 地址 %s 外部防火墙规则已存在，已修复内部白名单记录并更新有效期。" % ip_address, u"info"

    try:
        command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "ACCEPT"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            current_ips[ip_address] = expiration_timestamp
            save_whitelisted_ips(current_ips)

            expiration_info = u"永久有效" if days_valid is None else u"有效期至 %s" % datetime.fromtimestamp(expiration_timestamp).strftime('%Y-%m-%d %H:%M:%S')

            message_text = u"成功添加 IP 地址: %s 到防火墙白名单 (%s)。" % (ip_address, expiration_info)
            message_class = u"success"
            if stdout:
                try:
                    message_text += u"<br>stdout: %s" % stdout.strip().decode('utf-8')
                except UnicodeDecodeError:
                    message_text += u"<br>stdout (无法解码): %s" % stdout.strip()

            save_success, save_error_msg = _save_firewall_rules()
            if save_success:
                message_text += u"<br>防火墙规则已持久化保存。"
            else:
                message_text += u"<br><strong>警告：防火墙规则持久化保存失败！</strong>"
                if save_error_msg:
                    try:
                        message_text += u" 错误: %s" % save_error_msg.decode('utf-8')
                    except UnicodeDecodeError:
                        message_text += u" 错误 (无法解码): %s" % save_error_msg
                message_class = u"error"
        else:
            message_text = u"添加 IP 地址失败。错误信息: "
            if stderr:
                try:
                    message_text += u"%s" % stderr.strip().decode('utf-8')
                except UnicodeDecodeError:
                    message_text += u"(无法解码)%s" % stderr.strip()
    except Exception as e:
        message_text = u"执行命令时发生错误: %s" % unicode(e)

    return message_text, message_class

def remove_ip_from_whitelist(ip_address):
    """从 iptables 和内部白名单文件中移除指定 IP"""
    message_text = u""
    message_class = u"error"

    try:
        # 先尝试从 iptables 删除
        command = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "ACCEPT"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            message_text = u"成功从防火墙中移除 IP: %s。" % ip_address
            message_class = u"success"

            # 从内部白名单文件移除
            current_ips = load_whitelisted_ips()
            if ip_address in current_ips:
                del current_ips[ip_address]
                save_whitelisted_ips(current_ips)
                message_text += u"<br>已从白名单记录中移除。"
            else:
                message_text += u"<br>警告：内部白名单记录中未找到该 IP，可能已手动删除。"

            # 保存 iptables 规则
            save_success, save_error_msg = _save_firewall_rules()
            if not save_success:
                message_text += u"<br><strong>警告：防火墙规则持久化保存失败！</strong>"
                if save_error_msg:
                    try:
                        message_text += u" 错误: %s" % save_error_msg.decode('utf-8')
                    except UnicodeDecodeError:
                        message_text += u" 错误 (无法解码): %s" % save_error_msg
                message_class = u"error"
        else:
            # 如果 iptables 删除失败，可能是规则不存在
            if _check_firewall_rule_exists(ip_address=ip_address):
                message_text = u"从防火墙中移除 IP: %s 失败。错误: %s" % (ip_address, stderr.strip().decode('utf-8', errors='ignore'))
            else:
                message_text = u"防火墙中未找到 IP: %s，可能已移除或从未添加。" % ip_address
                message_class = u"info"
                # 即使iptables中不存在，也要尝试从内部白名单文件移除
                current_ips = load_whitelisted_ips()
                if ip_address in current_ips:
                    del current_ips[ip_address]
                    save_whitelisted_ips(current_ips)
                    message_text += u"<br>已从白名单记录中移除。"

    except Exception as e:
        message_text = u"执行移除命令时发生错误: %s" % unicode(e)

    return message_text, message_class


def cleanup_expired_ips():
    """清理所有过期的 IP 地址及其对应的防火墙规则"""
    print "开始清理过期的 IP 白名单..."
    current_ips = load_whitelisted_ips()
    now = time.time()

    ips_to_remove = []
    for ip, timestamp in current_ips.items():
        if timestamp != 0 and timestamp < now:
            ips_to_remove.append(ip)
            print "发现过期 IP:", ip, "过期时间:", datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    if not ips_to_remove:
        print "没有发现过期的 IP 地址。"
        return u"没有发现过期的 IP 地址需要清理。", u"info"

    cleanup_messages = []
    overall_success = True
    for ip in ips_to_remove:
        msg, cls = remove_ip_from_whitelist(ip)
        cleanup_messages.append(u'<span class="%s">%s</span>' % (cls, msg))
        if cls == u"error":
            overall_success = False

    message_text = u"已完成过期 IP 清理。<br>" + u"<br>".join(cleanup_messages)
    message_class = u"success" if overall_success else u"error"
    return message_text, message_class

# --- HTTP 请求处理类 ---

class MyHandler(BaseHTTPRequestHandler):
    def _render_page(self, title, body_content, extra_style_css=""):
        """辅助函数，用于生成带样式的 HTML 页面"""
        base_css = u"""
            /* 模拟 Bootstrap 样式 */
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                line-height: 1.5;
                color: #333;
                background-color: #f8f9fa;
                margin: 0;
                padding: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }
            .container {
                background-color: #fff;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 0.5rem 1rem rgba(0,0,0,.15);
                width: 100%;
                max-width: 500px;
                text-align: center;
            }
            h1 {
                color: #007bff;
                margin-bottom: 25px;
            }
            form div {
                margin-bottom: 15px;
            }
            label {
                display: block;
                margin-bottom: 5px;
                font-weight: 600;
                text-align: left;
            }
            input[type="text"], input[type="password"] {
                display: block;
                width: 100%;
                padding: 10px 15px;
                font-size: 1rem;
                line-height: 1.5;
                color: #495057;
                background-color: #fff;
                background-clip: padding-box;
                border: 1px solid #ced4da;
                border-radius: 0.25rem;
                transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
                box-sizing: border-box;
            }
            input[type="text"]:focus, input[type="password"]:focus {
                color: #495057;
                background-color: #fff;
                border-color: #80bdff;
                outline: 0;
                box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
            }
            input[type="submit"] {
                color: #fff;
                background-color: #007bff;
                border-color: #007bff;
                display: inline-block;
                font-weight: 400;
                text-align: center;
                vertical-align: middle;
                user-select: none;
                border: 1px solid transparent;
                padding: 10px 20px;
                font-size: 1rem;
                line-height: 1.5;
                border-radius: 0.25rem;
                transition: color 0.15s ease-in-out, background-color 0.15s ease-in-out, border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
                cursor: pointer;
                width: 100%;
            }
            input[type="submit"]:hover {
                color: #fff;
                background-color: #0069d9;
                border-color: #0062cc;
            }
            p {
                margin-top: 20px;
                font-size: 0.9rem;
                color: #666;
                text-align: center;
            }
            p.note {
                font-size: 0.8rem;
                color: #888;
            }
            p strong {
                color: #dc3545; /* Danger red */
            }
            p.success {
                color: #28a745; /* Success green */
            }
            p.error {
                color: #dc3545; /* Error red */
            }
            p.info {
                color: #17a2b8; /* Info blue */
            }
            .button-group {
                margin-top: 20px;
                display: flex;
                justify-content: space-around;
                gap: 10px;
            }
            .button-group a, .button-group input[type="submit"] {
                flex-grow: 1;
                padding: 10px;
                border: 1px solid #007bff;
                background-color: #007bff;
                color: #fff;
                text-decoration: none;
                border-radius: 0.25rem;
                font-weight: 400;
                cursor: pointer;
                text-align: center;
            }
            .button-group a:hover, .button-group input[type="submit"]:hover {
                background-color: #0069d9;
                border-color: #0062cc;
            }
            .button-group a.secondary {
                background-color: #6c757d;
                border-color: #6c757d;
            }
            .button-group a.secondary:hover {
                background-color: #5a6268;
                border-color: #545b62;
            }
        """

        html_template = u"""
            <html>
            <head>
                <meta charset="utf-8">
                <title>%s</title>
                <style>
                    %s
                    %s
                </style>
            </head>
            <body>
                <div class="container">
                    %s
                </div>
            </body>
            </html>
        """ % (title, base_css, extra_style_css, body_content)

        return html_template.encode('utf-8')

    def _authenticate(self):
        """处理 HTTP Basic Auth 认证"""
        auth_header = self.headers.get('Authorization')
        if auth_header and auth_header.startswith('Basic '):
            encoded_credentials = auth_header[len('Basic '):].strip()
            try:
                decoded_credentials = base64.b64decode(encoded_credentials)
                username, password = decoded_credentials.split(':', 1)
                username = username.decode('utf-8')
                password = password.decode('utf-8')

                if check_auth(username, password):
                    return True
            except Exception as e:
                print "认证解码错误:", e

        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Restricted Area"')
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(self._render_page(
            u"未授权",
            u"""
            <h1>未授权</h1>
            <p>您没有权限访问此页面。</p>
            """
        ))
        return False

    def do_GET(self):
        if self.path == '/change_password':
            self._handle_change_password_get()
            return
        elif self.path == '/cleanup':
            self._handle_cleanup_get()
            return

        if not self._authenticate():
            return

        auto_add_message = u""
        auto_add_class = u""

        # 仅当首次访问主页时才自动加白
        if not self.headers.get('Referer') or '/change_password' in self.headers.get('Referer', '') or '/cleanup' in self.headers.get('Referer', ''):
             current_ip = self.client_address[0]
             print "尝试自动加白本机IP:", current_ip
             # 保持30天有效期，如需永久请改为 days_valid=None
             auto_add_message, auto_add_class = add_ip_to_whitelist(current_ip, days_valid=30)

        message_html = u""
        if auto_add_message:
            message_html = u'<p class="%s"><strong>自动加白本机 IP (%s):</strong></br> %s</p>' % (auto_add_class, self.client_address[0], auto_add_message)

        body_content = u"""
            <h1>管理 IP 白名单</h1>
            %s
            <div style="text-align: left; margin-top: 20px;">
                <h2>添加 IP 白名单</h2>
                <form method="POST" action="/">
                    <div>
                        <label for="ip_address">IP 地址:</label>
                        <input type="text" id="ip_address" name="ip_address" pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$" required>
                    </div>
                    <div>
                        <label>有效期:</label>
                        <input type="radio" id="validity_30_days" name="validity" value="30" checked>
                        <label for="validity_30_days" style="display:inline; margin-right: 20px;">30 天</label>
                        <input type="radio" id="validity_permanent" name="validity" value="permanent">
                        <label for="validity_permanent" style="display:inline;">永久</label>
                    </div>
                    <input type="submit" value="添加 IP">
                </form>
            </div>
            <p class="note">已添加的 IP 将允许所有传入连接。</p>
            <div class="button-group">
                <a href="/cleanup" class="secondary">清理过期 IP</a>
                <a href="/change_password" class="secondary">修改密码</a>
            </div>
        """ % message_html
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(self._render_page(u"管理 IP 白名单", body_content))

    def do_POST(self):
        if self.path == '/change_password':
            self._handle_change_password_post()
            return

        if not self._authenticate():
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })

        ip_address = form.getvalue("ip_address")
        validity = form.getvalue("validity")

        message_text = u""
        message_class = u"error"

        if ip_address:
            days_valid = None
            if validity == "30":
                days_valid = 30

            message_text, message_class = add_ip_to_whitelist(ip_address, days_valid)
        else:
            message_text = u"IP 地址不能为空。"
            message_class = u"error"

        body_content = u"""
            <h1>管理 IP 白名单</h1>
            <p class="%s">%s</p>
            <div class="button-group">
                <a href="/">返回主页</a>
                <a href="/cleanup" class="secondary">清理过期 IP</a>
                <a href="/change_password" class="secondary">修改密码</a>
            </div>
        """ % (message_class, message_text)

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(self._render_page(u"操作结果", body_content))

    def _handle_change_password_get(self):
        """显示修改密码表单"""
        if not self._authenticate():
            return

        body_content = u"""
            <h1>修改密码</h1>
            <form method="POST" action="/change_password">
                <div>
                    <label for="current_password">当前密码:</label>
                    <input type="password" id="current_password" name="current_password" required>
                </div>
                <div>
                    <label for="new_password">新密码:</label>
                    <input type="password" id="new_password" name="new_password" required>
                </div>
                <div>
                    <label for="confirm_password">确认新密码:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                <input type="submit" value="修改密码">
            </form>
            <div class="button-group">
                <a href="/">返回主页</a>
            </div>
        """
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(self._render_page(u"修改密码", body_content))

    def _handle_change_password_post(self):
        """处理修改密码请求"""
        auth_header = self.headers.get('Authorization')
        username = None
        if auth_header and auth_header.startswith('Basic '):
            encoded_credentials = auth_header[len('Basic '):].strip()
            try:
                decoded_credentials = base64.b64decode(encoded_credentials)
                username, _ = decoded_credentials.split(':', 1)
                username = username.decode('utf-8')
            except Exception as e:
                print "认证解码错误 (修改密码):", e

        if not username or not self._authenticate():
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })

        current_password = form.getvalue("current_password")
        new_password = form.getvalue("new_password")
        confirm_password = form.getvalue("confirm_password")

        message_text = u""
        message_class = u"error"

        if not current_password or not new_password or not confirm_password:
            message_text = u"所有密码字段都不能为空。"
        elif new_password != confirm_password:
            message_text = u"新密码和确认密码不匹配。"
        else:
            users = load_users()
            if users.get(username) == current_password:
                users[username] = new_password
                save_users(users)
                message_text = u"密码修改成功！请用新密码重新登录。"
                message_class = u"success"
            else:
                message_text = u"当前密码不正确。"

        body_content = u"""
            <h1>修改密码</h1>
            <p class="%s">%s</p>
            <div class="button-group">
                <a href="/">返回主页</a>
                <a href="/change_password" class="secondary">继续修改</a>
            </div>
        """ % (message_class, message_text)

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(self._render_page(u"修改密码结果", body_content))

    def _handle_cleanup_get(self):
        """处理清理过期 IP 的请求"""
        if not self._authenticate():
            return

        print "用户手动触发清理过期 IP。"
        message_text, message_class = cleanup_expired_ips()

        body_content = u"""
            <h1>清理过期 IP</h1>
            <p class="%s">%s</p>
            <div class="button-group">
                <a href="/">返回主页</a>
            </div>
        """ % (message_class, message_text)

        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(self._render_page(u"清理结果", body_content))


if __name__ == '__main__':
# --- 1. 载入 iptables.init 文件作为 iptables 的初始化状态 ---
    print "开始载入 %s 文件作为 iptables 初始化..." % IPTABLES_INIT_FILE
    if not os.path.exists(IPTABLES_INIT_FILE):
        print "iptables 初始化文件 %s 不存在，正在创建默认文件..." % IPTABLES_INIT_FILE
        default_iptables_content = """*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 62371 -j ACCEPT
-A INPUT -s 100.100.0.0/16 -j ACCEPT
-A INPUT -s 127.0.0.0/8 -j ACCEPT
-A INPUT -s 10.0.0.0/8 -j ACCEPT
-A INPUT -s 172.16.0.0/12 -j ACCEPT
-A INPUT -s 192.168.0.0/16 -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
COMMIT
"""
        try:
            with open(IPTABLES_INIT_FILE, 'w') as f:
                f.write(default_iptables_content)
            print "默认 %s 文件创建成功。" % IPTABLES_INIT_FILE
        except Exception as e:
            print "创建 %s 文件失败: %s" % (IPTABLES_INIT_FILE, e)
            print "警告: 仍将尝试加载 iptables，但可能失败。请手动检查文件权限或内容。"
            # 如果创建文件失败，后面的 iptables-restore 仍然会尝试打开它，可能会再次失败，但这是预期行为。

    # 以下部分保持不变，因为无论文件是原有还是新创建的，都将尝试加载它
    try:
        command = ["sudo", "/sbin/iptables-restore"]
        with open(IPTABLES_INIT_FILE, 'r') as f_in:
            process = subprocess.Popen(command, stdin=f_in, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

        if process.returncode == 0:
            print "成功载入 iptables 初始规则：%s" % IPTABLES_INIT_FILE
            if stdout: print "Restore stdout:", stdout.strip().decode('utf-8', errors='ignore')
            # 无论是否新创建，都应该保存当前规则，确保系统状态和备份同步
            save_success, save_error_msg = _save_firewall_rules()
            if not save_success:
                print "警告：初始 iptables 规则持久化保存失败！", save_error_msg.decode('utf-8', errors='ignore')
        else:
            print "载入 iptables 初始规则失败。错误: %s" % stderr.strip().decode('utf-8', errors='ignore')
            print "请检查 %s 文件内容和sudo权限。" % IPTABLES_INIT_FILE
    except Exception as e:
        print "执行 iptables-restore 命令时发生错误:", e
        print "请确保 /sbin/iptables-restore 已安装且运行脚本的用户有足够的sudo权限。"
    # --- 1. 结束 ---

    # --- 2. 检查用户文件和 IP 白名单文件 ---
    if not os.path.exists(USERS_FILE):
        print "用户文件 %s 不存在，正在创建默认用户 'admin'..." % USERS_FILE
        new_random_password = generate_random_password()
        save_users({'admin': new_random_password})
        print "创建成功。"
        print "请访问 http://%s:%s/ 并使用 'admin' 登录。" % (HOST_NAME, PORT_NUMBER)
        print "首次登录密码为: %s" % new_random_password
        print "登录后建议立即修改密码。"

    if not os.path.exists(WHITELIST_FILE):
        print "IP 白名单文件 %s 不存在，正在创建空文件..." % WHITELIST_FILE
        save_whitelisted_ips({})
        print "创建成功。"

    # --- 3. 程序启动时执行清理过期 IP ---
    print "程序启动，执行过期 IP 清理任务..."
    cleanup_msg, cleanup_cls = cleanup_expired_ips()
    print "清理结果:", cleanup_msg.replace('<br>', ' ').encode('utf-8')

    # --- 4. 载入清理后的 ip 白名单 (重新同步iptables与whitelisted_ips.conf) ---
    print "开始同步内部白名单文件与防火墙规则..."
    current_ips_in_file = load_whitelisted_ips()
    sync_messages = []
    sync_success = True

    for ip_address, timestamp in current_ips_in_file.items():
        now = time.time()
        if timestamp == 0 or timestamp > now:
            if not _check_firewall_rule_exists(ip_address=ip_address):
                print "发现白名单文件中的未过期IP %s 在防火墙中不存在，尝试添加..." % ip_address
                try:
                    command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "ACCEPT"]
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    if process.returncode == 0:
                        msg = u"成功添加白名单 IP %s 到防火墙。" % ip_address
                        sync_messages.append(u'<span class="success">%s</span>' % msg)
                    else:
                        msg = u"添加白名单 IP %s 到防火墙失败。错误: %s" % (ip_address, stderr.strip().decode('utf-8', errors='ignore'))
                        sync_messages.append(u'<span class="error">%s</span>' % msg)
                        sync_success = False
                except Exception as e:
                    msg = u"执行命令添加白名单 IP %s 时发生错误: %s" % (ip_address, unicode(e))
                    sync_messages.append(u'<span class="error">%s</span>' % msg)
                    sync_success = False

    if sync_messages:
        sync_result_msg = u"白名单同步完成。<br>" + u"<br>".join(sync_messages)
        print "同步结果:", sync_result_msg.replace('<br>', ' ').encode('utf-8')
    else:
        print "内部白名单文件与防火墙规则已同步，无需额外操作。"

    final_save_success, final_save_error_msg = _save_firewall_rules()
    if not final_save_success:
        print "警告：最终防火墙规则持久化保存失败！", final_save_error_msg.decode('utf-8', errors='ignore')
    # --- 4. 结束 ---

    try:
        httpd = HTTPServer((HOST_NAME, PORT_NUMBER), MyHandler)
        print "服务器运行在 %s:%s" % (HOST_NAME, PORT_NUMBER)
        print "请访问 http://%s:%s/" % (HOST_NAME, PORT_NUMBER)
        print "按 Ctrl+C 停止服务器"
        httpd.serve_forever()
    except KeyboardInterrupt:
        print "\n服务器已停止。"
        httpd.socket.close()
