# plugins/base.py

class BaseAdapter:
    """
    光猫插件基础接口规范
    所有光猫适配插件都必须继承此类，并实现对应的静态方法。
    """
    NAME = "Unknown Adapter"
    
    @staticmethod
    def build_rules(rows: list, ips: dict) -> list:
        """生成并返回需要下发的添加规则命令列表"""
        return []
        
    @staticmethod
    def purge_rules(rows: list) -> list:
        """生成并返回用于清理旧规则的命令列表"""
        return []
        
    @staticmethod
    def get_status_cmds() -> dict:
        """返回用于查询和验证规则是否生效的命令（供主程序验尸用）"""
        return {
            "ipv6_forward": "ip6tables -L FORWARD -n -v --line-numbers | head -6",
            "ipv6_nat": "ip6tables -t nat -L PREROUTING -n -v --line-numbers | head -6",
            "ipv4_forward": "iptables -L FORWARD -n -v --line-numbers | head -6",
            "ipv4_nat": "iptables -t nat -L PREROUTING -n -v --line-numbers | head -6"
        }