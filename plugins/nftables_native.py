# plugins/nftables_native.py
from .base import BaseAdapter

class NativeNftablesAdapter(BaseAdapter):
    """
    【原生 nftables 适配插件（实验性）】
    适用场景：较新的华为、中兴光猫，或底层已全面转为 nftables 的 OpenWrt 系统。
    
    ⚠️ 重要提示：
    1. nftables 区分“族(family)”、“表(table)”和“链(chain)”。
    2. 不同品牌光猫的表名差异极大（例如 OpenWrt 的 fw4 是 `inet fw4`）。
    3. 本插件默认使用最标准的原生结构（ip/ip6 族），如果下发失败，建议用户手动在 Web 后台配置，或修改此插件中的表名。
    """
    
    NAME = "通用原生 nftables (实验性)"

    @staticmethod
    def build_rules(rows: list, ips: dict) -> list:
        """生成 nftables 下发规则"""
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
                    # nftables 的 NAT 和放行规则需分别针对 ip 族编写
                    cmds.append(f"nft add rule ip nat prerouting {p} dport {port4} dnat to {v4_target}:{port4}")
                    cmds.append(f"nft add rule ip filter forward {p} dport {port4} accept")

            # ---- 处理 IPv6 物理地址 ----
            v6_p_target = (row.get("ipv6_p") or "").strip()
            if v6_p_target in ("", "自动读取"): v6_p_target = ips.get("p6")
            
            port6 = (row.get("port6") or "").strip()
            proto6 = (row.get("proto6") or "TCP").upper()
            
            if v6_p_target and port6:
                protos = ["tcp", "udp"] if proto6 == "TCP+UDP" else [proto6.lower()]
                for p in protos:
                    # 注意：nftables 的 IPv6 DNAT 目标地址必须用方括号 [] 括起来
                    cmds.append(f"nft add rule ip6 nat prerouting {p} dport {port6} dnat to [{v6_p_target}]:{port6}")
                    cmds.append(f"nft add rule ip6 filter forward {p} dport {port6} accept")

            # ---- 处理 IPv6 临时地址 ----
            v6_t_target = (row.get("ipv6_t") or "").strip()
            if v6_t_target in ("", "自动读取"): v6_t_target = ips.get("t6")
            
            if v6_t_target and port6:
                protos = ["tcp", "udp"] if proto6 == "TCP+UDP" else [proto6.lower()]
                for p in protos:
                    cmds.append(f"nft add rule ip6 nat prerouting {p} dport {port6} dnat to [{v6_t_target}]:{port6}")
                    cmds.append(f"nft add rule ip6 filter forward {p} dport {port6} accept")
                    
        return cmds

    @staticmethod
    def purge_rules(rows: list) -> list:
        """
        生成 nftables 清理规则
        由于 nftables 按句柄删除极为繁琐，这里采用直接清空（flush）指定链的暴力方式。
        """
        cmds = []
        
        # 只要表格里填了 IPv6 端口，就清空对应的链
        for row in rows:
            if (row.get("port6") or "").strip():
                cmds.append("nft flush chain ip6 nat prerouting")
                cmds.append("nft flush chain ip6 filter forward")
                break 
                
        # 只要表格里填了 IPv4 端口，就清空对应的链
        for row in rows:
            if (row.get("port4") or "").strip():
                cmds.append("nft flush chain ip nat prerouting")
                cmds.append("nft flush chain ip filter forward")
                break
                
        return cmds

    @staticmethod
    def get_status_cmds() -> dict:
        """
        返回查询状态命令，用于主程序验证下发是否成功
        """
        return {
            "ipv6_forward": "nft list chain ip6 filter forward",
            "ipv6_nat": "nft list chain ip6 nat prerouting",
            "ipv4_forward": "nft list chain ip filter forward",
            "ipv4_nat": "nft list chain ip nat prerouting"
        }