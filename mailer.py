# mailer.py
import smtplib
from email.mime.text import MIMEText
from email.header import Header

def send_mail(smtp_host: str, smtp_port: int, user: str, password: str,
              to_addr: str, subject: str, body: str) -> bool:
    """发送纯文本邮件，支持 SSL 和 STARTTLS"""
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["From"] = user
        msg["To"] = to_addr
        msg["Subject"] = Header(subject, "utf-8")

        # 465 端口使用 SSL 加密，其他端口（如 587）使用 STARTTLS
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.starttls()

        server.login(user, password)
        server.sendmail(user, [to_addr], msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"[SMTP 错误] {type(e).__name__}: {e}")
        return False