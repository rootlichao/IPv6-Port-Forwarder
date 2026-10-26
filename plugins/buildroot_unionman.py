# plugins/buildroot_unionman.py
from .base import BaseAdapter

class BuildrootUnionmanAdapter(BaseAdapter):
    """
    【Buildroot Unionman 专属插件】
    适用场景：光猫底层为 Buildroot 系统（如 UNG903H1-S）。
    特点：
    1. 直接硬编码 /sbin/ip6tables 和 /sbin/iptables，无视环境变量干扰。
    2. 实测完美兼容此型号光猫，稳定性极高。
    """
    
    NAME = "吉比特 UNG153H (绝对路径版)"

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
                    cmds.append(f"/sbin/iptables -w -t nat -I PREROUTING -p {p} --dport {port4} -j DNAT --to-destination {v4_target}:{port4}")
                    cmds.append(f"/sbin/iptables -w -I FORWARD -p {p} --dport {port4} -j ACCEPT")

            # ---- 处理 IPv6 物理地址 ----
            v6_p_target = (row.get("ipv6_p") or "").strip()
            if v6_p_target in ("", "自动读取"): v6_p_target = ips.get("p6")
            
            port6 = (row.get("port6") or "").strip()
            proto6 = (row.get("proto6") or "TCP").upper()
            
            if v6_p_target and port6:
                dnat = f"\\[{v6_p_target}\\]:{port6}"
                protos = ["tcp", "udp"] if proto6 == "TCP+UDP" else [proto6.lower()]
                for p in protos:
                    cmds.append(f"/sbin/ip6tables -w -t nat -I PREROUTING -p {p} --dport {port6} -j DNAT --to-destination {dnat}")
                    cmds.append(f"/sbin/ip6tables -w -I FORWARD -p {p} --dport {port6} -j ACCEPT")

            # ---- 处理 IPv6 临时地址 ----
            v6_t_target = (row.get("ipv6_t") or "").strip()
            if v6_t_target in ("", "自动读取"): v6_t_target = ips.get("t6")
            
            if v6_t_target and port6:
                dnat = f"\\[{v6_t_target}\\]:{port6}"
                protos = ["tcp", "udp"] if proto6 == "TCP+UDP" else [proto6.lower()]
                for p in protos:
                    cmds.append(f"/sbin/ip6tables -w -t nat -I PREROUTING -p {p} --dport {port6} -j DNAT --to-destination {dnat}")
                    cmds.append(f"/sbin/ip6tables -w -I FORWARD -p {p} --dport {port6} -j ACCEPT")
        return cmds

    @staticmethod
    def purge_rules(rows: list) -> list:
        """生成清理规则（使用绝对路径 + 降序行号删除）"""
        cmds = []
        for row in rows:
            port6 = (row.get("port6") or "").strip()
            if port6:
                cmds.append(f"/sbin/ip6tables -w -L FORWARD -n -v --line-numbers | grep 'dpt:{port6}' | awk '{{print $1}}' | sort -nr | xargs -r -n1 /sbin/ip6tables -w -D FORWARD")
                cmds.append(f"/sbin/ip6tables -w -t nat -L PREROUTING -n -v --line-numbers | grep 'dpt:{port6}' | awk '{{print $1}}' | sort -nr | xargs -r -n1 /sbin/ip6tables -w -t nat -D PREROUTING")

            port4 = (row.get("port4") or "").strip()
            if port4:
                cmds.append(f"/sbin/iptables -w -L FORWARD -n -v --line-numbers | grep 'dpt:{port4}' | awk '{{print $1}}' | sort -nr | xargs -r -n1 /sbin/iptables -w -D FORWARD")
                cmds.append(f"/sbin/iptables -w -t nat -L PREROUTING -n -v --line-numbers | grep 'dpt:{port4}' | awk '{{print $1}}' | sort -nr | xargs -r -n1 /sbin/iptables -w -t nat -D PREROUTING")
        return cmds

    @staticmethod
    def get_status_cmds() -> dict:
        """使用绝对路径获取状态"""
        return {
            "ipv6_forward": "/sbin/ip6tables -L FORWARD -n -v --line-numbers | head -6",
            "ipv6_nat": "/sbin/ip6tables -t nat -L PREROUTING -n -v --line-numbers | head -6",
            "ipv4_forward": "/sbin/iptables -L FORWARD -n -v --line-numbers | head -6",
            "ipv4_nat": "/sbin/iptables -t nat -L PREROUTING -n -v --line-numbers | head -6"
        }