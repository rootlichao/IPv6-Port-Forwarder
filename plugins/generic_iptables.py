# plugins/generic_iptables.py
from .base import BaseAdapter

class GenericIptablesAdapter(BaseAdapter):
    """
    【通用原生 iptables 适配插件】
    适用场景：大部分基于 Linux 或 OpenWrt 底层，且没有对 iptables 命令进行深度魔改的光猫。
    特点：
    1. 直接调用系统环境变量里的 ip6tables / iptables。
    2. 采用 xargs 管道流式删除，执行效率极高。
    3. 兼容性最广，是未知型号光猫的首选“盲测”插件。
    """
    
    NAME = "通用原生 iptables"

    @staticmethod
    def build_rules(rows: list, ips: dict) -> list:
        """生成下发规则"""
        cmds = []
        for row in rows:
            # ---- 处理 IPv4 ----
            v4_target = (row.get("ipv4") or "").strip()
            if v4_target in ("", "自动读取"): v4_target = ips.get("p4")
            
            port4 = (row.get("port4") or "").strip()
            proto4 = (row.get("proto4") or "TCP").upper()
            
            if v4_target and port4:
                protos = ["tcp", "udp"] if proto4 == "TCP+UDP" else [proto4.lower()]
                for p in protos:
                    cmds.append(f"iptables -w -t nat -I PREROUTING -p {p} --dport {port4} -j DNAT --to-destination {v4_target}:{port4}")
                    cmds.append(f"iptables -w -I FORWARD -p {p} --dport {port4} -j ACCEPT")

            # ---- 处理 IPv6 物理地址 ----
            v6_p_target = (row.get("ipv6_p") or "").strip()
            if v6_p_target in ("", "自动读取"): v6_p_target = ips.get("p6")
            
            port6 = (row.get("port6") or "").strip()
            proto6 = (row.get("proto6") or "TCP").upper()
            
            if v6_p_target and port6:
                # IPv6 地址在 iptables 语法中必须用方括号括起来并转义
                dnat = f"\\[{v6_p_target}\\]:{port6}"
                protos = ["tcp", "udp"] if proto6 == "TCP+UDP" else [proto6.lower()]
                for p in protos:
                    cmds.append(f"ip6tables -w -t nat -I PREROUTING -p {p} --dport {port6} -j DNAT --to-destination {dnat}")
                    cmds.append(f"ip6tables -w -I FORWARD -p {p} --dport {port6} -j ACCEPT")

            # ---- 处理 IPv6 临时地址 ----
            v6_t_target = (row.get("ipv6_t") or "").strip()
            if v6_t_target in ("", "自动读取"): v6_t_target = ips.get("t6")
            
            if v6_t_target and port6:
                dnat = f"\\[{v6_t_target}\\]:{port6}"
                protos = ["tcp", "udp"] if proto6 == "TCP+UDP" else [proto6.lower()]
                for p in protos:
                    cmds.append(f"ip6tables -w -t nat -I PREROUTING -p {p} --dport {port6} -j DNAT --to-destination {dnat}")
                    cmds.append(f"ip6tables -w -I FORWARD -p {p} --dport {port6} -j ACCEPT")
                    
        return cmds

    @staticmethod
    def purge_rules(rows: list) -> list:
        """
        生成清理规则（极速流式版）
        通过 xargs 获取行号并逆向删除，防止规则堆积。
        """
        cmds = []
        for row in rows:
            port6 = (row.get("port6") or "").strip()
            if port6:
                cmds.append(f"ip6tables -w -L FORWARD -n -v --line-numbers | grep 'dpt:{port6}' | awk '{{print $1}}' | sort -nr | xargs -r -n1 ip6tables -w -D FORWARD")
                cmds.append(f"ip6tables -w -t nat -L PREROUTING -n -v --line-numbers | grep 'dpt:{port6}' | awk '{{print $1}}' | sort -nr | xargs -r -n1 ip6tables -w -t nat -D PREROUTING")

            port4 = (row.get("port4") or "").strip()
            if port4:
                cmds.append(f"iptables -w -L FORWARD -n -v --line-numbers | grep 'dpt:{port4}' | awk '{{print $1}}' | sort -nr | xargs -r -n1 iptables -w -D FORWARD")
                cmds.append(f"iptables -w -t nat -L PREROUTING -n -v --line-numbers | grep 'dpt:{port4}' | awk '{{print $1}}' | sort -nr | xargs -r -n1 iptables -w -t nat -D PREROUTING")
                
        return cmds