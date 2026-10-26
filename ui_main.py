# ui_main.py
import datetime
import sys
import time
import json
import urllib.request
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QIntValidator, QBrush, QColor, QAction, QIcon, QPixmap, QPainter
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QCheckBox, 
    QComboBox, QPushButton, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, 
    QMessageBox, QGroupBox, QPlainTextEdit, QAbstractItemView, QDialog, 
    QDialogButtonBox, QSpinBox, QSystemTrayIcon, QMenu, QApplication, QGridLayout,
    QFileDialog
)

from config import load_config, save_config, load_cached_ipv6
from core import get_all_ips, ping_host, apply_rules, clear_rules, load_plugins, diagnose_router, reboot_router, exec_custom_script
from mailer import send_mail
from autostart import set_autostart

AUTO_ROLE = Qt.UserRole + 1
CURRENT_VERSION = "v1.0.0"

# ---------- 软件更新检查线程 ----------
class UpdateChecker(QThread):
    update_found = Signal(str)
    def run(self):
        try:
            # TODO: 发布前请替换为你自己的 GitHub 仓库地址
            req = urllib.request.urlopen("https://api.github.com/repos/yourname/yourrepo/releases/latest", timeout=5)
            data = json.loads(req.read().decode())
            latest_version = data.get("tag_name", "")
            if latest_version and latest_version != CURRENT_VERSION:
                self.update_found.emit(latest_version)
        except Exception: 
            pass

# ---------- 邮件设置对话框 ----------
class SmtpDialog(QDialog):
    def __init__(self, cfg: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("邮件设置")
        self.setMinimumWidth(460)
        main_layout = QVBoxLayout(self)
        form = QGridLayout()
        form.setHorizontalSpacing(15); form.setVerticalSpacing(10)
        
        self.ed_host = QLineEdit(cfg.get("smtp_host", "smtp.qq.com"))
        self.sp_port = QSpinBox(); self.sp_port.setRange(1, 65535); self.sp_port.setValue(int(cfg.get("smtp_port", 465)))
        self.ed_user = QLineEdit(cfg.get("smtp_user", ""))
        self.ed_pass = QLineEdit(cfg.get("smtp_pass", "")); self.ed_pass.setEchoMode(QLineEdit.Password)
        self.ed_to = QLineEdit(cfg.get("mail_to", ""))
        
        form.addWidget(QLabel("SMTP 服务器:"), 0, 0); form.addWidget(self.ed_host, 0, 1)
        form.addWidget(QLabel("端口:"), 1, 0); form.addWidget(self.sp_port, 1, 1)
        form.addWidget(QLabel("发件账号:"), 2, 0); form.addWidget(self.ed_user, 2, 1)
        form.addWidget(QLabel("授权码:"), 3, 0); form.addWidget(self.ed_pass, 3, 1)
        form.addWidget(QLabel("接收邮箱:"), 4, 0); form.addWidget(self.ed_to, 4, 1)
        main_layout.addLayout(form)

        tip_label = QLabel(
            "提示说明：\n"
            "1. QQ邮箱：服务器填 smtp.qq.com，端口 465。授权码需在网页版QQ邮箱“设置->账号”中开启并获取。\n"
            "2. 163邮箱：服务器填 smtp.163.com，端口 465。授权码需在网页版163邮箱设置中获取。\n"
            "3. Outlook：服务器填 smtp.office365.com，端口 587。\n"
            "注意：授权码不是登录密码，必须去邮箱网页端单独生成！"
        )
        tip_label.setStyleSheet("color: #666666; font-size: 12px; background-color: #f5f5f5; padding: 8px; border-radius: 4px;")
        tip_label.setWordWrap(True); main_layout.addWidget(tip_label)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        main_layout.addWidget(btns)

    def get_values(self):
        return {
            "smtp_host": self.ed_host.text().strip(), 
            "smtp_port": self.sp_port.value(),
            "smtp_user": self.ed_user.text().strip(), 
            "smtp_pass": self.ed_pass.text(),
            "mail_to": self.ed_to.text().strip()
        }

# ---------- 后台工作线程 ----------
class ServiceWorker(QThread):
    log = Signal(str)
    ip_updated = Signal(dict)
    finished_ok = Signal(bool)

    def __init__(self, cfg: dict, adapter_class: type):
        super().__init__()
        self.cfg = cfg
        self.adapter_class = adapter_class
        self._running = True
        self._first_run = True
        self._router_was_offline = False
        self._offline_time = None
        self._just_recovered = False
        self._force_flag = False

    def stop(self): 
        self._running = False
    
    def request_refresh(self, new_cfg=None):
        if new_cfg: 
            self.cfg = new_cfg
        self._force_flag = True

    def run(self):
        self._tick()
        while self._running:
            interval_min = int(self.cfg.get("interval_min", 1))
            interval_sec = interval_min * 60
            start_time = time.time()
            end_time = start_time + interval_sec
            while time.time() < end_time:
                if not self._running: return
                if self._force_flag:
                    self._force_flag = False
                    self.log.emit("⚡ 收到刷新指令，跳过等待...")
                    break
                self.msleep(100)
            if self._running: 
                self._tick()

    def _send_mail(self, subject: str, body: str):
        if not self.cfg.get("send_mail") or not self.cfg.get("mail_to"): return
        ok = send_mail(self.cfg.get("smtp_host", ""), int(self.cfg.get("smtp_port", 465)),
                       self.cfg.get("smtp_user", ""), self.cfg.get("smtp_pass", ""),
                       self.cfg["mail_to"], subject, body)
        self.log.emit(f"📧 邮件已发送: {subject}" if ok else f"❌ 邮件发送失败: {subject}")

    def _tick(self):
        try:
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ips, _ = get_all_ips()
            self.ip_updated.emit(ips)

            current_logs = []
            def step_log(msg):
                self.log.emit(msg)
                current_logs.append(msg)

            recover_msg = ""
            # 光猫在线状态检测
            if self.cfg.get("check_online"):
                online = ping_host(self.cfg["router_ip"])
                step_log(f"{'✅' if online else '❌'} 路由器在线状态: {online}")
                if not online:
                    if not self._router_was_offline:
                        self._router_was_offline = True
                        self._offline_time = datetime.datetime.now()
                        step_log("⚠️ 光猫已掉线，等待恢复...")
                    self.finished_ok.emit(True)
                    return
                else:
                    if self._router_was_offline:
                        self._router_was_offline = False
                        offline_duration = ""
                        if self._offline_time:
                            delta = datetime.datetime.now() - self._offline_time
                            offline_duration = f"掉线时长: {int(delta.total_seconds() // 60)} 分钟\n"
                        step_log("🔄 光猫已恢复上线，准备重新下发规则...")
                        self._just_recovered = True
                        recover_msg = f"时间: {now_str}\n{offline_duration}光猫已恢复 Ping 通。"

            rows = self.cfg.get("rows", [])
            if not rows:
                step_log("⚠️ 端口表为空，跳过")
                self.finished_ok.emit(True)
                return

            step_log("🔧 开始应用规则...")
            res = apply_rules(self.cfg["router_ip"], self.cfg["username"], self.cfg["password"], 
                              rows, self.adapter_class, log=step_log)
            self.finished_ok.emit(res["ok"])

            # 邮件通知触发逻辑
            if res["ok"]:
                if self._just_recovered:
                    self._just_recovered = False
                    recover_body = f"{recover_msg}\n最新物理 IPv6: {ips.get('p6')}\n最新临时 IPv6: {ips.get('t6')}\n\n--- 恢复后的最新运行日志 ---\n" + "\n".join(current_logs)
                    self._send_mail("✅ 光猫已恢复上线并更新规则", recover_body)
                elif self._first_run:
                    self._first_run = False
                    body = (f"时间: {now_str}\n物理 IPv6: {ips.get('p6')}\n临时 IPv6: {ips.get('t6')}\n\n"
                            f"--- 详细日志 ---\n" + "\n".join(current_logs))
                    self._send_mail("🚀 服务已启动", body)
                elif res["changed_p6"] or res["changed_t6"]:
                    self._send_mail("🔄 IPv6 已更新",
                        f"时间: {now_str}\n物理变更: {res['old_p6']} -> {res['new_p6']}\n临时变更: {res['old_t6']} -> {res['new_t6']}")
        except Exception as e:
            self.log.emit(f"❌ 后台异常: {e}")
            self.finished_ok.emit(False)

# ---------- 表格控件 ----------
class PortTable(QTableWidget):
    HEADERS = ["物理/临时IPv4列表", "物理IPv6列表", "临时IPv6列表", "端口号", "协议"]

    def __init__(self, rows=None):
        super().__init__(0, 5)
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.verticalHeader().setVisible(False)
        
        self.setMinimumHeight(100) 
        self.setMaximumHeight(180) 

        if rows:
            for r in rows: self.add_row(r)
        else:
            for _ in range(3): self.add_row()

    def add_row(self, data: dict = None):
        data = data or {}
        r = self.rowCount(); self.insertRow(r)
        self.setRowHeight(r, 30)

        for col, key in enumerate(["ipv4", "ipv6_p", "ipv6_t"]):
            val = data.get(key, "自动读取") or "自动读取"
            item = QTableWidgetItem(val)
            if val == "自动读取": item.setData(AUTO_ROLE, True)
            self.setItem(r, col, item)

        port_str = data.get("port6", data.get("port4", ""))
        port = QLineEdit(str(port_str))
        port.setValidator(QIntValidator(1, 65535, self)); port.setPlaceholderText("端口")
        self.setCellWidget(r, 3, port)

        proto = QComboBox(); proto.addItems(["TCP", "UDP", "TCP+UDP"])
        proto.setCurrentText(data.get("proto6", data.get("proto4", "TCP+UDP")))
        self.setCellWidget(r, 4, proto)

    def get_rows(self) -> list:
        res = []
        for r in range(self.rowCount()):
            def txt(c):
                it = self.item(r, c)
                if not it: return ""
                return "自动读取" if it.data(AUTO_ROLE) else it.text()

            port_str = self.cellWidget(r, 3).text() if self.cellWidget(r, 3) else ""
            res.append({
                "ipv4": txt(0), "ipv6_p": txt(1), "ipv6_t": txt(2),
                "port4": port_str, "port6": port_str, "proto6": self.cellWidget(r, 4).currentText()
            })
        return res

    def refresh_auto_cells(self, ips: dict):
        brush = QBrush(QColor(120, 120, 120))
        map_val = {0: ips.get("p4"), 1: ips.get("p6"), 2: ips.get("t6")}
        for r in range(self.rowCount()):
            for c, val in map_val.items():
                it = self.item(r, c)
                if it and it.data(AUTO_ROLE):
                    it.setText(val or "无")
                    it.setForeground(brush)

# ---------- 主窗口 ----------
class MainWindow(QMainWindow):
    def __init__(self, startup_mode=False):
        super().__init__()
        self.setWindowTitle(f"光猫 IPv6 端口放行工具 (双栈插件版) {CURRENT_VERSION}")
        self.setMinimumSize(1100, 720) 

        self.cfg = load_config()
        self.worker = None
        self._force_quit = False
        self.plugins = load_plugins()

        self._init_ui()
        self._init_tray()
        QTimer.singleShot(100, self.refresh_local_ip)
        
        if startup_mode: 
            QTimer.singleShot(2000, self.start_service)
        else:
            if self.cfg.get("software_auto_update", True):
                self.updater = UpdateChecker()
                self.updater.update_found.connect(self._on_update_found)
                self.updater.start()

    def _on_update_found(self, ver: str):
        self.status.showMessage(f"🎉 发现新版本 {ver}，请前往 GitHub 下载更新！", 10000)
        self.log(f"🎉 发现新版本 {ver}，请前往 GitHub 下载更新！")

    def _init_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(5, 5, 5, 5)

        main_grid = QGridLayout()
        main_grid.setHorizontalSpacing(10)
        main_grid.setVerticalSpacing(8)
        root.addLayout(main_grid)

        def ro_le():
            le = QLineEdit(); le.setReadOnly(True); le.setPlaceholderText("自动读取"); return le

        # ================= 顶部：基础连接区 =================
        main_grid.addWidget(QLabel("路由器IP:"), 0, 0)
        self.ed_router = QLineEdit(self.cfg["router_ip"]); main_grid.addWidget(self.ed_router, 0, 1)
        main_grid.addWidget(QLabel("Telnet用户:"), 0, 2)
        self.ed_user = QLineEdit(self.cfg["username"]); main_grid.addWidget(self.ed_user, 0, 3)
        main_grid.addWidget(QLabel("Telnet密码:"), 0, 4)
        self.ed_pass = QLineEdit(self.cfg["password"]); self.ed_pass.setEchoMode(QLineEdit.Password); main_grid.addWidget(self.ed_pass, 0, 5)

        # ================= 中间：IP信息区 =================
        self.ed_cur_p4, self.ed_cur_t4 = ro_le(), ro_le()
        self.ed_cur_p6, self.ed_cur_t6 = ro_le(), ro_le()
        self.ed_last_p4, self.ed_last_t4 = ro_le(), ro_le()
        self.ed_last_p6, self.ed_last_t6 = ro_le(), ro_le()

        # 物理 IPv6 复制按钮
        self.btn_copy_p6 = QPushButton("📋")
        self.btn_copy_p6.setFixedWidth(25); self.btn_copy_p6.setStyleSheet("padding: 0px;")
        self.btn_copy_p6.setToolTip("复制当前物理 IPv6 地址")
        self.btn_copy_p6.clicked.connect(lambda: self.copy_ip(self.ed_cur_p6.text(), self.btn_copy_p6))
        
        layout_p6 = QHBoxLayout()
        layout_p6.setContentsMargins(0, 0, 0, 0); layout_p6.setSpacing(2)
        layout_p6.addWidget(self.ed_cur_p6)
        layout_p6.addWidget(self.btn_copy_p6)

        # 临时 IPv6 复制按钮
        self.btn_copy_t6 = QPushButton("📋")
        self.btn_copy_t6.setFixedWidth(25); self.btn_copy_t6.setStyleSheet("padding: 0px;")
        self.btn_copy_t6.setToolTip("复制当前临时 IPv6 地址")
        self.btn_copy_t6.clicked.connect(lambda: self.copy_ip(self.ed_cur_t6.text(), self.btn_copy_t6))
        
        layout_t6 = QHBoxLayout()
        layout_t6.setContentsMargins(0, 0, 0, 0); layout_t6.setSpacing(2)
        layout_t6.addWidget(self.ed_cur_t6)
        layout_t6.addWidget(self.btn_copy_t6)

        main_grid.addWidget(QLabel("当前物理IPv4:"), 1, 0); main_grid.addWidget(self.ed_cur_p4, 1, 1)
        main_grid.addWidget(QLabel("当前临时IPv4:"), 1, 2); main_grid.addWidget(self.ed_cur_t4, 1, 3)
        main_grid.addWidget(QLabel("当前物理IPv6:"), 2, 0); main_grid.addLayout(layout_p6, 2, 1)
        main_grid.addWidget(QLabel("当前临时IPv6:"), 2, 2); main_grid.addLayout(layout_t6, 2, 3)
        main_grid.addWidget(QLabel("上次记录物理IPv4:"), 3, 0); main_grid.addWidget(self.ed_last_p4, 3, 1)
        main_grid.addWidget(QLabel("上次记录临时IPv4:"), 3, 2); main_grid.addWidget(self.ed_last_t4, 3, 3)
        main_grid.addWidget(QLabel("上次记录物理IPv6:"), 4, 0); main_grid.addWidget(self.ed_last_p6, 4, 1)
        main_grid.addWidget(QLabel("上次记录临时IPv6:"), 4, 2); main_grid.addWidget(self.ed_last_t6, 4, 3)

        # ================= 右侧：选项与动作 =================
        self.chk_online = QCheckBox("检测路由在线状态"); self.chk_online.setChecked(self.cfg.get("check_online", False))
        self.chk_mail = QCheckBox("发送邮件"); self.chk_mail.setChecked(self.cfg.get("send_mail", False))
        self.chk_boot = QCheckBox("开机启动"); self.chk_boot.setChecked(self.cfg.get("autostart", False))
        
        self.chk_soft_update = QCheckBox("软件自动更新")
        self.chk_soft_update.setChecked(self.cfg.get("software_auto_update", True))
        self.chk_soft_update.setToolTip("开启后，每次启动软件会自动检查 GitHub 是否有新版本")

        main_grid.addWidget(self.chk_online, 1, 4)
        main_grid.addWidget(self.chk_mail, 2, 4)
        main_grid.addWidget(self.chk_boot, 3, 4)
        main_grid.addWidget(self.chk_soft_update, 4, 4)

        self.cb_plugin = QComboBox()
        for p in self.plugins: self.cb_plugin.addItem(p.NAME, p)
        saved_plugin = self.cfg.get("plugin_name", "")
        if saved_plugin:
            idx = self.cb_plugin.findText(saved_plugin)
            if idx >= 0: self.cb_plugin.setCurrentIndex(idx)
        
        main_grid.addWidget(QLabel("光猫适配插件:"), 1, 5); main_grid.addWidget(self.cb_plugin, 2, 5)

        h_layout = QHBoxLayout()
        self.btn_diagnose = QPushButton("🔍 提取环境")
        self.btn_diagnose.setToolTip("一键读取光猫底层的系统版本、iptables/nftables 路径及现有规则信息，用于排障")
        self.btn_diagnose.clicked.connect(self.run_diagnose)
        
        self.btn_smtp = QPushButton("⚙️ 邮箱设置"); self.btn_smtp.clicked.connect(self.open_smtp_dialog)
        self.btn_reboot = QPushButton("🔄 光猫重启"); self.btn_reboot.clicked.connect(self.reboot_router)
        
        h_layout.addWidget(self.btn_diagnose); 
        h_layout.addWidget(self.btn_smtp)
        h_layout.addWidget(self.btn_reboot)

        interval_layout = QHBoxLayout()
        interval_layout.addWidget(QLabel("巡检间隔(分钟):"))
        self.sp_interval = QSpinBox(); self.sp_interval.setRange(1, 1440); self.sp_interval.setValue(int(self.cfg.get("interval_min", 1)))
        self.sp_interval.setToolTip("程序每隔多少分钟自动检测一次网络状态（IP是否变化、光猫是否在线）。")
        self.sp_interval.valueChanged.connect(self._sync_interval_to_worker)
        interval_layout.addWidget(self.sp_interval)

        main_grid.addLayout(h_layout, 3, 5)
        main_grid.addLayout(interval_layout, 4, 5)

        # ================= 表格区 (左侧 4 列) =================
        table_group = QGroupBox("输入需要开启的端口")
        table_layout = QVBoxLayout(table_group)
        self.table = PortTable(self.cfg.get("rows"))
        table_layout.addWidget(self.table)
        
        btn_row = QHBoxLayout()
        btn_add = QPushButton("+ 增加一行"); btn_del = QPushButton("- 删除选中行")
        btn_add.clicked.connect(lambda: self.table.add_row()); btn_del.clicked.connect(self._del_row)
        btn_row.addWidget(btn_add); btn_row.addWidget(btn_del); btn_row.addStretch()
        table_layout.addLayout(btn_row)
        
        main_grid.addWidget(table_group, 5, 0, 1, 4)

        # ================= 右侧控制台 (右侧 2 列) =================
        console_layout = QVBoxLayout()
        console_layout.setSpacing(5)
        
        self.btn_start = QPushButton("启动服务")
        self.btn_stop = QPushButton("停止服务")
        self.btn_force = QPushButton("⚡ 立即刷新") 
        self.btn_clear = QPushButton("清理光猫配置")
        self.btn_quit = QPushButton("退出应用")
        
        self.btn_stop.setEnabled(False); self.btn_force.setEnabled(False)
        
        for btn in [self.btn_start, self.btn_stop, self.btn_force, self.btn_clear, self.btn_quit]:
            btn.setMinimumHeight(32)
            console_layout.addWidget(btn)
            
        main_grid.addLayout(console_layout, 5, 4, 1, 2)

        # ================= 底部区域：左侧日志 =================
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_group)
        log_top = QHBoxLayout()
        btn_copy_log = QPushButton("📋 复制"); btn_copy_log.clicked.connect(self.copy_log)
        btn_export = QPushButton("💾 导出"); btn_export.clicked.connect(self.export_log)
        btn_clear_log = QPushButton("🗑️ 清空"); btn_clear_log.clicked.connect(lambda: self.log_view.clear())
        log_top.addWidget(QLabel("操作:"))
        log_top.addWidget(btn_copy_log)
        log_top.addWidget(btn_export)
        log_top.addWidget(btn_clear_log)
        log_top.addStretch()
        log_layout.addLayout(log_top)
        
        self.log_view = QPlainTextEdit(); self.log_view.setReadOnly(True); self.log_view.setMaximumBlockCount(500)
        log_layout.addWidget(self.log_view)

        main_grid.addWidget(log_group, 6, 0, 1, 4)

        # ================= 底部区域：右侧自定义脚本 =================
        script_group = QGroupBox("自定义脚本")
        script_layout = QVBoxLayout(script_group)
        script_layout.setContentsMargins(5, 5, 5, 5)
        
        script_top = QHBoxLayout()
        self.btn_exec_script = QPushButton("▶ 执行脚本")
        self.btn_exec_script.setStyleSheet("background-color: #0078D7; color: white; font-weight: bold;")
        self.btn_exec_script.clicked.connect(self.exec_script)
        
        btn_import = QPushButton("📁 导入"); btn_import.clicked.connect(self.import_script)
        btn_export_script = QPushButton("💾 导出"); btn_export_script.clicked.connect(self.export_script)
        btn_clear_script = QPushButton("🗑️ 清空"); btn_clear_script.clicked.connect(lambda: self.txt_script.clear())
        btn_copy_script = QPushButton("📋 复制"); btn_copy_script.clicked.connect(self.copy_script)

        script_top.addWidget(self.btn_exec_script)
        script_top.addWidget(btn_import)
        script_top.addWidget(btn_export_script)
        script_top.addWidget(btn_clear_script)
        script_top.addWidget(btn_copy_script)
        script_layout.addLayout(script_top)
        
        self.txt_script = QPlainTextEdit()
        self.txt_script.setPlaceholderText("支持输入多条命令，每行一条。\n例如：\ncat /proc/cpuinfo\nip6tables -L -v -n")
        self.txt_script.setStyleSheet("background-color: #f9f9f9; font-family: Consolas, monospace;")
        script_layout.addWidget(self.txt_script)

        main_grid.addWidget(script_group, 6, 4, 1, 2)

        # 拉伸比例
        main_grid.setRowStretch(5, 2) 
        main_grid.setRowStretch(6, 3) 

        self.status = self.statusBar(); self.status.showMessage("🟢 就绪")
        
        self.btn_start.clicked.connect(self.start_service)
        self.btn_stop.clicked.connect(self.stop_service)
        self.btn_force.clicked.connect(self.force_refresh)
        self.btn_clear.clicked.connect(self.clear_config)
        self.btn_quit.clicked.connect(self.quit_app)
        self.chk_boot.toggled.connect(self._on_autostart_toggled)

    def _sync_interval_to_worker(self, val):
        """当用户修改巡检间隔时，实时更新后台线程的配置"""
        if self.worker and self.worker.isRunning():
            latest_cfg = self.collect_config()
            self.worker.request_refresh(latest_cfg)
            self.log(f"⚡ 巡检间隔已更新为 {val} 分钟，正在重新计时...")

    def _init_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        pixmap = QPixmap(32, 32); pixmap.fill(Qt.transparent)
        p = QPainter(pixmap); p.setBrush(QBrush(QColor("#0078D7"))); p.setPen(Qt.NoPen); p.drawEllipse(0, 0, 32, 32)
        p.setPen(Qt.white); f = p.font(); f.setBold(True); p.setFont(f); p.drawText(pixmap.rect(), Qt.AlignCenter, "IP"); p.end()
        self.tray_icon.setIcon(QIcon(pixmap)); self.tray_icon.setToolTip("光猫 IPv6 端口放行工具")

        menu = QMenu()
        act_show = QAction("显示主界面", self); act_show.triggered.connect(self.showNormal)
        act_quit = QAction("彻底退出", self); act_quit.triggered.connect(self.force_quit)
        menu.addAction(act_show); menu.addSeparator(); menu.addAction(act_quit)
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(lambda r: self.showNormal() if r == QSystemTrayIcon.DoubleClick else None)
        self.tray_icon.show()

    def exec_script(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "提示", "请先点击【停止服务】，然后再执行自定义脚本，以免连接冲突。")
            return

        cfg = self.collect_config()
        if not cfg["router_ip"] or not cfg["username"]: 
            QMessageBox.warning(self, "提示", "请先填写路由器 IP 和用户名")
            return
            
        script_text = self.txt_script.toPlainText()
        if not script_text.strip():
            QMessageBox.warning(self, "提示", "脚本内容为空")
            return

        self.log("\n" + "="*50)
        exec_custom_script(cfg["router_ip"], cfg["username"], cfg["password"], script_text, log=self.log)
        self.log("="*50 + "\n")

    def import_script(self):
        filename, _ = QFileDialog.getOpenFileName(self, "导入脚本", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    self.txt_script.setPlainText(f.read())
                self.status.showMessage("✅ 脚本导入成功", 3000)
            except Exception as e:
                QMessageBox.warning(self, "导入失败", f"无法读取文件: {e}")

    def export_script(self):
        text = self.txt_script.toPlainText()
        if not text: return
        filename, _ = QFileDialog.getSaveFileName(self, "导出脚本", "custom_script.txt", "Text Files (*.txt)")
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(text)
                self.status.showMessage("✅ 脚本导出成功", 3000)
            except Exception as e:
                QMessageBox.warning(self, "导出失败", f"无法保存文件: {e}")

    def copy_script(self):
        text = self.txt_script.toPlainText()
        if not text: return
        QApplication.clipboard().setText(text)
        self.status.showMessage("✅ 脚本已复制到剪贴板", 3000)

    def copy_ip(self, ip: str, btn: QPushButton):
        if not ip or ip == "无": return
        QApplication.clipboard().setText(ip)
        btn.setText("✅")
        QTimer.singleShot(1500, lambda: btn.setText("📋"))

    def copy_log(self):
        QApplication.clipboard().setText(self.log_view.toPlainText())
        self.status.showMessage("✅ 日志已复制到剪贴板", 3000)

    def export_log(self):
        text = self.log_view.toPlainText()
        if not text: return
        filename, _ = QFileDialog.getSaveFileName(self, "导出日志", "ipv6_port_log.txt", "Text Files (*.txt)")
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(text)
                QMessageBox.information(self, "成功", "日志导出成功！")
            except Exception as e:
                QMessageBox.warning(self, "失败", f"导出失败: {e}")

    def run_diagnose(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "提示", "请先点击【停止服务】，然后再执行一键诊断。")
            return
        cfg = self.collect_config()
        if not cfg["router_ip"] or not cfg["username"]: return
        self.log("\n" + "="*50)
        diagnose_router(cfg["router_ip"], cfg["username"], cfg["password"], log=self.log)
        self.log("="*50 + "\n")

    def reboot_router(self):
        reply = QMessageBox.warning(
            self, "⚠️ 重启确认", 
            "确定要重启光猫吗？\n\n"
            "重启期间网络会断开，当前运行的端口服务将被自动停止。\n"
            "重启完成后，您需要手动点击【启动服务】。",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes: return
            
        if self.worker and self.worker.isRunning():
            self.log("🛑 检测到服务正在运行，准备先行停止...")
            self.stop_service()
            
        cfg = self.collect_config()
        if not cfg["router_ip"] or not cfg["username"]: return
        
        if reboot_router(cfg["router_ip"], cfg["username"], cfg["password"], log=self.log):
            self.log("⏳ 光猫正在重启，请等待 1-2 分钟后重新点击【启动服务】。")

    def force_quit(self):
        self._force_quit = True
        if self.worker: self.worker.stop(); self.worker.wait(1000)
        self.tray_icon.hide(); QApplication.quit()

    def closeEvent(self, event):
        try:
            self.cfg = self.collect_config(); save_config(self.cfg)
        except: pass
        if self._force_quit: event.accept()
        else:
            event.ignore(); self.hide()
            self.tray_icon.showMessage("最小化", "后台运行中", QSystemTrayIcon.Information, 2000)

    def log(self, msg: str): self.log_view.appendPlainText(msg)
    def _del_row(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()}, reverse=True)
        for r in rows: self.table.removeRow(r)

    def refresh_local_ip(self):
        ips, _ = get_all_ips()
        self.ed_cur_p4.setText(ips.get("p4", "")); self.ed_cur_t4.setText(ips.get("t4", ""))
        self.ed_cur_p6.setText(ips.get("p6", "")); self.ed_cur_t6.setText(ips.get("t6", ""))
        self.table.refresh_auto_cells(ips); self._update_last_cache()

    def _update_last_cache(self):
        cached = load_cached_ipv6()
        self.ed_last_p4.setText(cached.get("p4", "（无）")); self.ed_last_t4.setText(cached.get("t4", "（无）"))
        self.ed_last_p6.setText(cached.get("p6", "（无）")); self.ed_last_t6.setText(cached.get("t6", "（无）"))

    def _on_autostart_toggled(self, checked: bool):
        if set_autostart(checked): self.log(f"{'✅ 已启用' if checked else '✅ 已取消'}开机启动")
        else: self.log("⚠️ 开机启动设置失败")

    def open_smtp_dialog(self):
        dlg = SmtpDialog(self.cfg, self)
        if dlg.exec() == QDialog.Accepted:
            self.cfg.update(dlg.get_values()); save_config(self.cfg); self.log("📮 邮件设置已保存")

    def collect_config(self) -> dict:
        cfg = dict(self.cfg)
        cfg.update({
            "router_ip": self.ed_router.text().strip(), "username": self.ed_user.text().strip(), "password": self.ed_pass.text(),
            "check_online": self.chk_online.isChecked(), "send_mail": self.chk_mail.isChecked(), "autostart": self.chk_boot.isChecked(),
            "software_auto_update": self.chk_soft_update.isChecked(), 
            "rows": self.table.get_rows(),
            "interval_min": self.sp_interval.value(), "plugin_name": self.cb_plugin.currentText(),
        })
        return cfg

    def _set_buttons(self, running: bool):
        self.btn_start.setEnabled(not running); self.btn_stop.setEnabled(running); self.btn_force.setEnabled(running)

    def start_service(self):
        cfg = self.collect_config()
        if not cfg["router_ip"] or not cfg["username"]:
            QMessageBox.warning(self, "提示", "请先填写路由器 IP 和用户名"); return
        if self.cb_plugin.count() == 0:
            QMessageBox.warning(self, "提示", "未找到任何光猫适配插件"); return
            
        self.cfg = cfg; save_config(cfg); self.log("💾 配置已保存")
        self.worker = ServiceWorker(cfg, self.cb_plugin.currentData())
        self.worker.log.connect(self.log); self.worker.ip_updated.connect(self._on_ip_updated)
        self.worker.finished_ok.connect(self._on_task_done)
        self.worker.start()
        self._set_buttons(True); self.status.showMessage("🟢 服务运行中")

    def _on_task_done(self, ok: bool):
        if ok: self.status.showMessage("✅ 规则应用成功")
        else:
            self.status.showMessage("❌ 规则应用失败，请检查日志")
            self.log("⚠️ 检测到服务失败，自动停止服务以恢复操作。")
            self.stop_service()

    def stop_service(self):
        if self.worker: self.worker.stop(); self.worker.wait(2000); self.worker = None
        self._set_buttons(False); self.status.showMessage("🔴 服务已停止"); self.log("🛑 服务已停止。")

    def force_refresh(self):
        if self.worker:
            self.worker.request_refresh(self.collect_config())
            self.log("⚡ 正在将最新配置同步至后台...")

    def clear_config(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "提示", "请先点击【停止服务】，然后再执行清理操作。")
            return
            
        reply = QMessageBox.warning(
            self, "⚠️ 危险操作确认", 
            "确定要清理光猫中的端口转发规则吗？\n\n"
            "【警告】清理后，外网玩家将【无法再连接】到你的游戏服务器！\n"
            "如果你只是暂时不想玩了，建议直接点击“退出应用”即可，无需清理配置。\n\n"
            "是否仍要继续清理？", 
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply != QMessageBox.Yes: return
            
        self.log("🧹 正在连接光猫执行清理...")
        cfg = self.collect_config()
        if clear_rules(cfg["router_ip"], cfg["username"], cfg["password"], cfg["rows"], self.cb_plugin.currentData(), log=self.log):
            QMessageBox.information(self, "成功", "光猫配置已清理完毕！")

    def quit_app(self):
        reply = QMessageBox.question(
            self, "确认退出", 
            "确定要直接退出应用吗？\n\n"
            "【提示】直接退出后，光猫端口放行规则将会【继续保留】，"
            "你的游戏服务器仍可正常联机。\n\n"
            "如果你不想保留这些规则（即彻底断开局域网外网访问），"
            "请先点击【清理光猫配置】。", 
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.force_quit()

    def _on_ip_updated(self, ips: dict):
        self.ed_cur_p4.setText(ips.get("p4", "")); self.ed_cur_t4.setText(ips.get("t4", ""))
        self.ed_cur_p6.setText(ips.get("p6", "")); self.ed_cur_t6.setText(ips.get("t6", ""))
        self.table.refresh_auto_cells(ips); self._update_last_cache()