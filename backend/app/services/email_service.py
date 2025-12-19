import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    
    def __init__(self):
        self.smtp_host = settings.smtp_host
        self.smtp_port = settings.smtp_port
        self.smtp_user = settings.smtp_user
        self.smtp_password = settings.smtp_password
        self.from_email = settings.smtp_user or "noreply@pba-system.com"
        self.from_name = "PBA Security System"
    
    def is_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_user and self.smtp_password)
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        if not self.is_configured():
            logger.warning("Email not configured. Skipping email send.")
            return False
        
        try:
            message = MIMEMultipart("alternative")
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = to_email
            message["Subject"] = subject
            
            # Add plain text version
            if text_content:
                message.attach(MIMEText(text_content, "plain", "utf-8"))
            
            # Add HTML version
            message.attach(MIMEText(html_content, "html", "utf-8"))
            
            # Send email
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True
            )
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    async def send_password_reset(self, to_email: str, username: str, reset_token: str) -> bool:
        reset_url = f"http://localhost/reset-password?token={reset_token}"
        
        subject = "🔐 Скидання пароля - PBA System"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #0d6efd; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
                .button {{ display: inline-block; background: #0d6efd; color: white; padding: 12px 30px; 
                          text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; color: #6c757d; font-size: 12px; margin-top: 20px; }}
                .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Скидання пароля</h1>
                </div>
                <div class="content">
                    <p>Вітаємо, <strong>{username}</strong>!</p>
                    <p>Ми отримали запит на скидання пароля для вашого акаунту в системі 
                       Passive Biometric Authentication.</p>
                    
                    <p style="text-align: center;">
                        <a href="{reset_url}" class="button" style="color: white !important;">Скинути пароль</a>
                    </p>
                    
                    <p>Або скопіюйте це посилання у браузер:</p>
                    <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 5px;">
                        {reset_url}
                    </p>
                    
                    <div class="warning">
                        <strong>⚠️ Увага:</strong> Це посилання дійсне протягом 1 години.
                        Якщо ви не запитували скидання пароля, проігноруйте цей лист.
                    </div>
                </div>
                <div class="footer">
                    <p>PBA Security System | Smart Energy Lab</p>
                    <p>Цей лист згенеровано автоматично, не відповідайте на нього.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
        Скидання пароля - PBA System
        
        Вітаємо, {username}!
        
        Ми отримали запит на скидання пароля для вашого акаунту.
        
        Перейдіть за посиланням для скидання пароля:
        {reset_url}
        
        Посилання дійсне протягом 1 години.
        
        Якщо ви не запитували скидання пароля, проігноруйте цей лист.
        
        --
        PBA Security System | Smart Energy Lab
        """
        
        return await self.send_email(to_email, subject, html_content, text_content)
    
    async def send_email_verification(self, to_email: str, username: str, verification_token: str) -> bool:
        verify_url = f"http://localhost/verify-email/{verification_token}"
        
        subject = "✉️ Підтвердження email - PBA System"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #198754; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
                .button {{ display: inline-block; background: #198754; color: white; padding: 12px 30px; 
                          text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; color: #6c757d; font-size: 12px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✉️ Підтвердження email</h1>
                </div>
                <div class="content">
                    <p>Вітаємо, <strong>{username}</strong>!</p>
                    <p>Дякуємо за реєстрацію в системі Passive Biometric Authentication.</p>
                    <p>Будь ласка, підтвердіть вашу email адресу:</p>
                    
                    <p style="text-align: center;">
                        <a href="{verify_url}" class="button" style="color: white !important;">Підтвердити email</a>
                    </p>
                    
                    <p>Посилання дійсне протягом 24 годин.</p>
                </div>
                <div class="footer">
                    <p>PBA Security System | Smart Energy Lab</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return await self.send_email(to_email, subject, html_content)
    
    async def send_suspicious_activity_alert(
        self,
        to_email: str,
        username: str,
        trust_score: float,
        ip_address: str,
        user_agent: str,
        anomaly_details: dict = None
    ) -> bool:
        
        subject = "🚨 Виявлено підозрілу активність - PBA System"
        
        anomaly_info = ""
        if anomaly_details:
            anomaly_items = []
            for key, value in anomaly_details.items():
                anomaly_items.append(f"<li><strong>{key}:</strong> відхилення виявлено</li>")
            anomaly_info = f"<ul>{''.join(anomaly_items)}</ul>"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
                .alert-box {{ background: #f8d7da; border: 1px solid #f5c6cb; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .info-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                .info-table td {{ padding: 10px; border-bottom: 1px solid #dee2e6; }}
                .info-table td:first-child {{ font-weight: bold; width: 40%; }}
                .footer {{ text-align: center; color: #6c757d; font-size: 12px; margin-top: 20px; }}
                .button {{ display: inline-block; background: #dc3545; color: white; padding: 12px 30px; 
                          text-decoration: none; border-radius: 5px; margin: 10px 5px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 Виявлено підозрілу активність</h1>
                </div>
                <div class="content">
                    <div class="alert-box">
                        <p><strong>Увага!</strong> Наша система біометричної автентифікації виявила 
                           незвичну поведінку у вашому акаунті.</p>
                    </div>
                    
                    <p>Шановний(а) <strong>{username}</strong>,</p>
                    <p>Система Passive Biometric Authentication зафіксувала активність, 
                       що відрізняється від вашого типового профілю поведінки.</p>
                    
                    <table class="info-table">
                        <tr>
                            <td>Trust Score:</td>
                            <td><span style="color: #dc3545; font-weight: bold;">{trust_score:.1%}</span> 
                                (поріг: 70%)</td>
                        </tr>
                        <tr>
                            <td>IP адреса:</td>
                            <td>{ip_address or 'Невідомо'}</td>
                        </tr>
                        <tr>
                            <td>Пристрій:</td>
                            <td style="font-size: 12px;">{user_agent or 'Невідомо'}</td>
                        </tr>
                    </table>
                    
                    {f'<p><strong>Виявлені аномалії:</strong></p>{anomaly_info}' if anomaly_info else ''}
                    
                    <p><strong>Що робити?</strong></p>
                    <ul>
                        <li>Якщо це були ви — проігноруйте це повідомлення</li>
                        <li>Якщо це не ви — негайно змініть пароль та перевірте активні сесії</li>
                        <li>Рекомендуємо увімкнути двофакторну автентифікацію (TOTP)</li>
                    </ul>
                    
                    <p style="text-align: center;">
                        <a href="http://localhost" class="button" style="color: white !important;">Перевірити акаунт</a>
                    </p>
                </div>
                <div class="footer">
                    <p>PBA Security System | Smart Energy Lab</p>
                    <p>Цей лист згенеровано автоматично системою безпеки.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
        🚨 ВИЯВЛЕНО ПІДОЗРІЛУ АКТИВНІСТЬ - PBA System
        
        Шановний(а) {username},
        
        Наша система біометричної автентифікації виявила незвичну поведінку у вашому акаунті.
        
        Деталі:
        - Trust Score: {trust_score:.1%} (поріг: 70%)
        - IP адреса: {ip_address or 'Невідомо'}
        - Пристрій: {user_agent or 'Невідомо'}
        
        Що робити?
        - Якщо це були ви — проігноруйте це повідомлення
        - Якщо це не ви — негайно змініть пароль
        - Рекомендуємо увімкнути двофакторну автентифікацію (TOTP)
        
        --
        PBA Security System | Smart Energy Lab
        """
        
        return await self.send_email(to_email, subject, html_content, text_content)
    
    async def send_mfa_triggered_alert(
        self,
        to_email: str,
        username: str,
        ip_address: str,
        reason: str = "anomaly"
    ) -> bool:
        
        subject = "🔒 Запит додаткової автентифікації - PBA System"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #ffc107; color: #333; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
                .info-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .footer {{ text-align: center; color: #6c757d; font-size: 12px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Запит додаткової автентифікації</h1>
                </div>
                <div class="content">
                    <p>Вітаємо, <strong>{username}</strong>!</p>
                    
                    <div class="info-box">
                        <p>Під час вашого входу в систему було запрошено додаткову верифікацію 
                           через TOTP код.</p>
                    </div>
                    
                    <p><strong>Деталі:</strong></p>
                    <ul>
                        <li>IP адреса: {ip_address or 'Невідомо'}</li>
                        <li>Причина: Виявлено відхилення в поведінковому профілі</li>
                    </ul>
                    
                    <p>Якщо це були не ви, рекомендуємо негайно змінити пароль.</p>
                </div>
                <div class="footer">
                    <p>PBA Security System | Smart Energy Lab</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return await self.send_email(to_email, subject, html_content)


# Global instance
email_service = EmailService()
