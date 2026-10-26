# main.py
import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont
from ui_main import MainWindow

def main():
    app = QApplication(sys.argv)
    # 保持中文应用名
    app.setApplicationName("光猫 IPv6 端口放行工具")
    # 允许关闭窗口后程序继续在托盘运行
    app.setQuitOnLastWindowClosed(False)

    # 统一全局字体大小
    font = QFont()
    font.setPointSize(10)
    app.setFont(font)

    # 检查是否带 --startup 参数（用于开机自启静默启动）
    is_startup = "--startup" in sys.argv

    w = MainWindow(startup_mode=is_startup)
    
    if is_startup:
        w.hide()
    else:
        w.show()
        
    sys.exit(app.exec())

if __name__ == "__main__":
    main()