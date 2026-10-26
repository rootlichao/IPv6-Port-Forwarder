# plugins/gigabit_ung153h.py
from .base import BaseAdapter

class GigabitUNG153HAdapter(BaseAdapter):
    """
    【吉比特 UNG153H 光猫专属适配插件】
    适用场景：国内大部分原生 Linux 内核、支持 Telnet 且未阉割 iptables 的光猫。
    特点：
    1. 直接调用系统环境变量里的 ip6tables / iptables。
    2. 采用按端口号精准匹配删除，绝不误删光猫自带的其他规则。
    3. 适配了光猫 Shell 对 IPv6 方括号（[]）需要转义的特性。
    """
    
    NAME = "吉比特 UNG153H (原生 iptables)"

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
                # 关键：光猫 Shell 对 IPv6 方括号敏感，必须双反斜杠转义
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
        生成清理规则
        采用降序行号（sort -nr）逆向删除，防止删除过程中行号错位。
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