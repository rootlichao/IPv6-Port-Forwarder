# core.py
import ipaddress
import re
import socket
import subprocess
import sys
import time
import datetime
import os
import types
from typing import List, Dict, Tuple

from config import load_cached_ipv6, save_cached_ipv6

# 跨平台隐藏子进程黑框
if sys.platform.startswith("win"):
    CREATE_NO_WINDOW = 0x08000000
else:
    CREATE_NO_WINDOW = 0

# ---------- 插件加载器（物理文件读取版） ----------
def load_plugins() -> List[type]:
    """动态扫描并加载 plugins 目录下的所有光猫适配插件"""
    adapters = []
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    plugin_dir = os.path.join(base_dir, "plugins")
    
    if not os.path.exists(plugin_dir):
        print(f"未找到插件目录: {plugin_dir}")
        return adapters

    base_file = os.path.join(plugin_dir, "base.py")
    BaseAdapter = None
    if os.path.exists(base_file):
        try:
            with open(base_file, "r", encoding="utf-8") as f:
                code = f.read()
            ns = {"__name__": "plugins.base", "__file__": base_file}
            exec(compile(code, base_file, "exec"), ns)
            BaseAdapter = ns.get("BaseAdapter")
        except Exception as e:
            print(f"加载 base.py 失败: {e}")
            return adapters

    if not BaseAdapter:
        return adapters

    fake_pkg = types.ModuleType("plugins")
    fake_base = types.ModuleType("plugins.base")
    fake_base.BaseAdapter = BaseAdapter
    fake_pkg.base = fake_base
    sys.modules["plugins"] = fake_pkg
    sys.modules["plugins.base"] = fake_base

    for file in os.listdir(plugin_dir):
        if file.endswith(".py") and file not in ("__init__.py", "base.py"):
            file_path = os.path.join(plugin_dir, file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    code = f.read()
                ns = {"__name__": f"plugins.{file[:-3]}", "__file__": file_path}
                exec(compile(code, file_path, "exec"), ns)
                for attr_name in ns:
                    if attr_name.startswith("__"): continue
                    obj = ns[attr_name]
                    if isinstance(obj, type) and issubclass(obj, BaseAdapter) and obj != BaseAdapter:
                        adapters.append(obj)
            except Exception as e:
                print(f"加载插件 {file} 失败: {e}")
    return adapters

# ---------- 本机网络信息获取 ----------
def get_all_ips() -> Tuple[Dict[str, str], str]:
    ips = {"p4": "", "t4": "", "p6": "", "t6": ""}
    main_dev = "未知网卡"
    try:
        if sys.platform.startswith("win"):
            out = subprocess.check_output(["ipconfig"], text=True, encoding="gbk", errors="ignore", creationflags=CREATE_NO_WINDOW)
            virtual_prefixes = ("192.168.56.", "192.168.137.", "192.168.79.", "192.168.114.", "192.168.150.", "192.168.163.")
            for line in out.splitlines():
                if "WLAN" in line or "以太网" in line:
                    if "适配器" in line:
                        main_dev = line.split("适配器")[-1].strip().strip(":").strip()
            for m in re.finditer(r"IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)", out):
                addr = m.group(1)
                if ipaddress.ip_address(addr).is_loopback or ipaddress.ip_address(addr).is_link_local: continue
                if any(addr.startswith(p) for p in virtual_prefixes): continue
                if not ips["p4"]: ips["p4"] = addr
            for line in out.splitlines():
                m = re.search(r"(?:IPv6[^\:]*|IPv6 Address[^\:]*):\s*([0-9a-fA-F:]+)", line)
                if not m: continue
                addr = m.group(1)
                if addr.startswith("fe80") or addr.startswith("::"): continue
                try:
                    if ipaddress.ip_address(addr).is_global:
                        if "临时" in line or "Temporary" in line: ips["t6"] = addr
                        else: ips["p6"] = addr
                except ValueError: continue
        else:
            out4 = subprocess.check_output(["ip", "-4", "addr", "show", "scope", "global"], text=True, stderr=subprocess.DEVNULL)
            dev_match = re.search(r"^\d+:\s+([^\:]+):.*?state UP", out4, re.MULTILINE)
            if dev_match: main_dev = dev_match.group(1)
            for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out4):
                ips["p4"] = m.group(1); break
            out6 = subprocess.check_output(["ip", "-6", "addr", "show", "scope", "global"], text=True, stderr=subprocess.DEVNULL)
            for line in out6.splitlines():
                m = re.search(r"inet6\s+([0-9a-fA-F:]+)", line)
                if not m: continue
                addr = m.group(1)
                if addr.startswith("fe80"): continue
                if "temporary" in line: ips["t6"] = addr
                else: ips["p6"] = addr
    except Exception: pass
    if not ips["p6"] and ips["t6"]: ips["p6"] = ips["t6"]
    return ips, main_dev

def ping_host(host: str, timeout: int = 2) -> bool:
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), host]
    try:
        subprocess.check_output(cmd, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        return True
    except Exception: return False

# ---------- 纯 Python Telnet 客户端 ----------
class RouterTelnet:
    IAC, DONT, DO, WONT, WILL, SB, SE = 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF0
    
    def __init__(self, ip, user, password, timeout=5, port=23):
        self.ip, self.user, self.password = ip, user, password
        self.timeout, self.port = timeout, port
        self.sock, self._buf = None, ""
        
    def __enter__(self):
        self.connect(); return self
    def __exit__(self, exc_type, exc, tb):
        self.close()
        
    def _strip_telnet(self, data: bytes) -> str:
        out, i, n = bytearray(), 0, len(data)
        while i < n:
            b = data[i]
            if b == self.IAC and i + 1 < n:
                cmd = data[i + 1]
                if cmd in (self.DO, self.DONT, self.WILL, self.WONT): i += 3; continue
                elif cmd == self.SB:
                    j = i + 2
                    while j + 1 < n and not (data[j] == self.IAC and data[j + 1] == self.SE): j += 1
                    i = j + 2; continue
                else: i += 2; continue
            out.append(b); i += 1
        return out.decode("utf-8", errors="ignore")
        
    def _recv_until(self, pattern: str, timeout: float = None) -> str:
        if timeout is None: timeout = self.timeout
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pattern in self._buf:
                idx = self._buf.index(pattern) + len(pattern)
                out, self._buf = self._buf[:idx], self._buf[idx:]
                return out
            self.sock.settimeout(max(0.2, deadline - time.time()))
            try: raw = self.sock.recv(4096)
            except socket.timeout: continue
            except Exception as e: raise RuntimeError(f"接收失败: {e}")
            if not raw: break
            self._buf += self._strip_telnet(raw)
        out, self._buf = self._buf, ""
        return out
        
    def _send_line(self, line: str): 
        self.sock.sendall((line + "\r\n").encode("utf-8"))
        
    def connect(self):
        if not self.password:
            raise RuntimeError("Telnet 密码为空，请检查输入！")
            
        self.sock = socket.create_connection((self.ip, self.port), timeout=self.timeout)
        self._recv_until("login:")
        self._send_line(self.user)
        self._recv_until("Password:")
        self._send_line(self.password)
        
        res = self._recv_until("#", timeout=self.timeout)
        if "#" not in res:
            raise RuntimeError("登录超时，密码错误或光猫未响应！")
        
    def run(self, cmd: str) -> str:
        self._send_line(cmd)
        return self._recv_until("#")
        
    def close(self):
        if self.sock:
            try: self._send_line("exit")
            except: pass
            try: self.sock.close()
            except: pass
            self.sock = None

# ---------- 核心应用与清理流程 ----------
def apply_rules(router_ip: str, user: str, password: str, rows: List[dict], adapter_class: type, log=print) -> dict:
    start_time = datetime.datetime.now()
    log(f"⏱️ [开始执行] 时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if not password:
        log("❌ 错误：Telnet 密码不能为空，请在上方输入光猫密码！")
        return {"ok": False, "changed_p6": False, "changed_t6": False, "old_p6": "", "old_t6": "", "new_p6": "", "new_t6": ""}
        
    # 【核心修复】检查是否真的填了端口，防止空表格假成功
    has_port = False
    for r in rows:
        if (r.get("port4") or "").strip() or (r.get("port6") or "").strip():
            has_port = True
            break
            
    if not has_port:
        log("❌ 错误：表格中未填写任何端口号，已取消执行！")
        return {"ok": False, "changed_p6": False, "changed_t6": False, "old_p6": "", "old_t6": "", "new_p6": "", "new_t6": ""}

    ips, main_dev = get_all_ips()
    result = {"ok": False, "changed_p6": False, "changed_t6": False, 
              "old_p6": "", "old_t6": "", "new_p6": ips["p6"], "new_t6": ips["t6"]}

    if not ips["p6"] and not ips["t6"]:
        log("❌ 未检测到全局 IPv6 地址")
        return result

    log(f"✅ 当前物理 IPv4: {ips['p4'] or '无'}")
    log(f"✅ 当前物理 IPv6: {ips['p6'] or '无'}")
    log(f"✅ 当前临时 IPv6: {ips['t6'] or '无'}")
    log(f"🔌 正在使用插件: {adapter_class.NAME}")

    cached = load_cached_ipv6()
    old_p6 = cached.get("p6", ""); old_t6 = cached.get("t6", "")
    if old_p6 != ips["p6"] or old_t6 != ips["t6"]:
        log(f"⚠️ IPv6 已变化：物理 {old_p6}->{ips['p6']} | 临时 {old_t6}->{ips['t6']}")
        save_cached_ipv6(ips)
        result["changed_p6"] = (old_p6 != ips["p6"])
        result["changed_t6"] = (old_t6 != ips["t6"])
        result["old_p6"] = old_p6; result["old_t6"] = old_t6
    else:
        log("✅ IPv6 未变化")

    add_cmds = adapter_class.build_rules(rows, ips)
    if not add_cmds:
        log("⚠️ 插件未生成任何规则（端口可能不合法）")
        end_time = datetime.datetime.now(); duration = (end_time - start_time).total_seconds()
        log(f"⏱️ [结束执行] 时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (耗时 {duration:.2f} 秒)")
        result["ok"] = False  # 改为 False 避免假成功
        return result

    try:
        with RouterTelnet(router_ip, user, password, port=23) as rt:
            log("🔌 telnet 登录中...")
            
            for c in adapter_class.purge_rules(rows):
                rt.run(c)
                
            for c in add_cmds:
                rt.run(c)

            log("")
            log("========== 光猫最新规则状态 ==========")
            
            status_cmds = adapter_class.get_status_cmds()
            
            out6_f = rt.run(status_cmds["ipv6_forward"])
            log("--- IPv6 FORWARD 链 ---"); log(out6_f.strip())
            
            if "Chain" not in out6_f and "table" not in out6_f:
                log(f"❌ 验证失败：未读取到有效的规则表，光猫可能不支持该插件语法！")
                log(f"光猫回显: {out6_f.strip()}")
                result["ok"] = False
                return result

            out6_n = rt.run(status_cmds["ipv6_nat"])
            log("--- IPv6 NAT PREROUTING 链 ---"); log(out6_n.strip())
            
            out4_f = rt.run(status_cmds["ipv4_forward"])
            log("--- IPv4 FORWARD 链 ---"); log(out4_f.strip())
            
            out4_n = rt.run(status_cmds["ipv4_nat"])
            log("--- IPv4 NAT PREROUTING 链 ---"); log(out4_n.strip())
            
            log("======================================")
            log("✅ 规则应用完成")
        
        end_time = datetime.datetime.now(); duration = (end_time - start_time).total_seconds()
        log(f"⏱️ [结束执行] 时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (耗时 {duration:.2f} 秒)")
        result["ok"] = True
        return result
    except Exception as e:
        log(f"❌ 执行失败: {e}")
        end_time = datetime.datetime.now(); duration = (end_time - start_time).total_seconds()
        log(f"⏱️ [结束执行] 时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (耗时 {duration:.2f} 秒)")
        return result

def clear_rules(router_ip: str, user: str, password: str, rows: List[dict], adapter_class: type, log=print) -> bool:
    if not password:
        log("❌ 错误：Telnet 密码不能为空，无法执行清理！")
        return False
        
    has_port = False
    for r in rows:
        if (r.get("port4") or "").strip() or (r.get("port6") or "").strip():
            has_port = True
            break
            
    if not has_port:
        log("❌ 错误：端口表格为空，没有需要清理的规则！")
        return False

    start_time = datetime.datetime.now()
    log(f"⏱️ [开始清理] 时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        with RouterTelnet(router_ip, user, password, port=23) as rt:
            log(f"🔌 telnet 登录中 (插件: {adapter_class.NAME})...")
            for c in adapter_class.purge_rules(rows):
                rt.run(c)
            log("✅ 光猫中的旧规则已彻底清理完毕")
        end_time = datetime.datetime.now(); duration = (end_time - start_time).total_seconds()
        log(f"⏱️ [清理结束] 时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (耗时 {duration:.2f} 秒)")
        return True
    except Exception as e:
        log(f"❌ 清理失败: {e}")
        end_time = datetime.datetime.now(); duration = (end_time - start_time).total_seconds()
        log(f"⏱️ [清理结束] 时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (耗时 {duration:.2f} 秒)")
        return False

# ---------- 高级控制台功能 ----------
def diagnose_router(router_ip: str, user: str, password: str, log=print) -> str:
    if not password:
        log("❌ 错误：Telnet 密码不能为空，无法提取环境！")
        return ""

    log("🔍 开始提取光猫环境信息...")
    info = "========= 光猫环境诊断报告 =========\n"
    try:
        with RouterTelnet(router_ip, user, password, port=23) as rt:
            cmds = [
                ("系统版本", "cat /etc/os-release"),
                ("CPU架构", "uname -a"),
                ("iptables路径", "which ip6tables"),
                ("nft路径", "which nft"),
                ("nft所有表", "nft list tables"),
                ("ip6tables规则", "ip6tables -L -n | head -10"),
            ]
            for name, cmd in cmds:
                info += f"\n[{name}] 执行: {cmd}\n"
                rt._send_line(cmd)
                time.sleep(0.5) 
                out = rt._recv_until("#")
                lines = out.splitlines()
                clean_lines = []
                for line in lines:
                    line_str = line.strip()
                    if not line_str or line_str == cmd or line_str.endswith("#") or line_str.endswith("$"):
                        continue
                    clean_lines.append(line_str)
                result_str = "\n".join(clean_lines).strip()
                info += result_str if result_str else "  (无返回或命令不存在)\n"
                info += "-" * 30 + "\n"
        log("✅ 诊断信息提取完毕，请查看下方输出。")
    except Exception as e:
        info += f"\n❌ 提取失败: {e}\n"
        log(f"❌ 提取失败: {e}")
    log(info)
    return info

def reboot_router(router_ip: str, user: str, password: str, log=print) -> bool:
    if not password:
        log("❌ 错误：Telnet 密码不能为空，无法重启光猫！")
        return False

    log("🔄 正在连接光猫下发重启指令...")
    try:
        with RouterTelnet(router_ip, user, password, port=23) as rt:
            rt._send_line("reboot")
            time.sleep(2)
            log("✅ 重启指令已成功下发，光猫正在断开连接，请稍后手动启动服务。")
            return True
    except Exception as e:
        if "接收失败" in str(e) or "reset by peer" in str(e).lower():
            log("✅ 重启指令已下发，连接已被光猫断开（正常现象）。")
            return True
        log(f"❌ 重启失败: {e}")
        return False

def exec_custom_script(router_ip: str, user: str, password: str, script_text: str, log=print) -> bool:
    if not password:
        log("❌ 错误：Telnet 密码不能为空，无法执行脚本！")
        return False
    if not script_text.strip():
        log("⚠️ 自定义脚本为空，跳过执行。")
        return False
    log("🚀 开始执行自定义脚本...")
    lines = [line.strip() for line in script_text.splitlines() if line.strip()]
    try:
        with RouterTelnet(router_ip, user, password, port=23) as rt:
            log("🔌 telnet 登录成功，开始下发命令...")
            for cmd in lines:
                if cmd.startswith("#"): continue
                log(f"➜ 执行: {cmd}")
                rt._send_line(cmd)
                time.sleep(0.5)
                out = rt._recv_until("#")
                clean_lines = []
                for line in out.splitlines():
                    line_str = line.strip()
                    if not line_str or line_str == cmd or line_str.endswith("#"): 
                        continue
                    clean_lines.append(line_str)
                result_str = "\n".join(clean_lines).strip()
                if result_str: log(result_str)
                else: log("  (无返回输出)")
                log("-" * 30)
        log("✅ 自定义脚本执行完毕")
        return True
    except Exception as e:
        log(f"❌ 脚本执行失败: {e}")
        return False