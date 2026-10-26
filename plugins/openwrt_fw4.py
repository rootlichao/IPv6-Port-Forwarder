# plugins/openwrt_fw4.py
from .base import BaseAdapter

class OpenWrtFw4Adapter(BaseAdapter):
    """
    【OpenWrt fw4 适配插件】
    适用场景：刷了 OpenWrt 固件的路由器，或底层基于 OpenWrt 并使用 fw4 防火墙的光猫。
    特点：
    1. fw4 将 IPv4 和 IPv6 统一放在 inet 族（family）中管理。
    2. 端口转发（DNAT）的链名通常为 `dstnat`，放行链通常为 `forward`。
    3. 在同一个 inet 表中，目标为 IPv6 时必须在 IP 两端加上方括号。
    """
    
    NAME = "OpenWrt 路由 (fw4 防火墙)"

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
                    cmds.append(f"nft add rule inet fw4 dstnat {p} dport {port4} dnat to {v4_target}:{port4}")
                    cmds.append(f"nft add rule inet fw4 forward {p} dport {port4} accept")

            # ---- 处理 IPv6 物理地址 ----
            v6_p_target = (row.get("ipv6_p") or "").strip()
            if v6_p_target in ("", "自动读取"): v6_p_target = ips.get("p6")
            
            port6 = (row.get("port6") or "").strip()
            proto6 = (row.get("proto6") or "TCP").upper()
            
            if v6_p_target and port6:
                protos = ["tcp", "udp"] if proto6 == "TCP+UDP" else [proto6.lower()]
                for p in protos:
                    # fw4 的 inet 表中，IPv6 DNAT 目标必须加方括号
                    cmds.append(f"nft add rule inet fw4 dstnat {p} dport {port6} dnat to [{v6_p_target}]:{port6}")
                    cmds.append(f"nft add rule inet fw4 forward {p} dport {port6} accept")

            # ---- 处理 IPv6 临时地址 ----
            v6_t_target = (row.get("ipv6_t") or "").strip()
            if v6_t_target in ("", "自动读取"): v6_t_target = ips.get("t6")
            
            if v6_t_target and port6:
                protos = ["tcp", "udp"] if proto6 == "TCP+UDP" else [proto6.lower()]
                for p in protos:
                    cmds.append(f"nft add rule inet fw4 dstnat {p} dport {port6} dnat to [{v6_t_target}]:{port6}")
                    cmds.append(f"nft add rule inet fw4 forward {p} dport {port6} accept")
                    
        return cmds

    @staticmethod
    def purge_rules(rows: list) -> list:
        """
        生成清理规则
        在 OpenWrt fw4 中，直接 flush 链会清空系统自带的防火墙规则（导致断网或失去保护）。
        因此，这里采用【按句柄查找删除】的方式，精准匹配我们需要的端口。
        """
        cmds = []
        for row in rows:
            port6 = (row.get("port6") or "").strip()
            if port6:
                # 查找包含 dport 的规则句柄并删除 (仅针对 dstnat 和 forward 链)
                cmds.append(f"nft -a list chain inet fw4 dstnat | grep 'dport {port6}' | awk '{{print $NF}}' | xargs -r -n1 nft delete rule inet fw4 dstnat handle")
                cmds.append(f"nft -a list chain inet fw4 forward | grep 'dport {port6}' | awk '{{print $NF}}' | xargs -r -n1 nft delete rule inet fw4 forward handle")

            port4 = (row.get("port4") or "").strip()
            if port4:
                cmds.append(f"nft -a list chain inet fw4 dstnat | grep 'dport {port4}' | awk '{{print $NF}}' | xargs -r -n1 nft delete rule inet fw4 dstnat handle")
                cmds.append(f"nft -a list chain inet fw4 forward | grep 'dport {port4}' | awk '{{print $NF}}' | xargs -r -n1 nft delete rule inet fw4 forward handle")
                
        return cmds

    @staticmethod
    def get_status_cmds() -> dict:
        """使用 OpenWrt 的标准查询语法"""
        return {
            "ipv6_forward": "nft list chain inet fw4 forward | head -10",
            "ipv6_nat": "nft list chain inet fw4 dstnat | head -10",
            "ipv4_forward": "nft list chain inet fw4 forward | head -10",
            "ipv4_nat": "nft list chain inet fw4 dstnat | head -10"
        }