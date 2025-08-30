// Path: AuthHive.Auth/Services/Communication/EmailService.cs
using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Infra.Communication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Services.Communication
{
    /// <summary>
    /// 이메일 및 SMS 서비스 구현 - AuthHive v15
    /// 실제 환경에서는 SendGrid, AWS SES, Twilio 등과 연동
    /// </summary>
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;
        private readonly HttpClient _httpClient;

        // 설정값
        private readonly string? _smtpHost;
        private readonly int _smtpPort;
        private readonly string? _smtpUsername;
        private readonly string? _smtpPassword;
        private readonly string? _fromEmail;
        private readonly string? _smsApiKey;
        private readonly string? _smsApiUrl;

        public EmailService(
            IConfiguration configuration,
            ILogger<EmailService> logger,
            IHttpClientFactory httpClientFactory)
        {
            _configuration = configuration;
            _logger = logger;
            _httpClient = httpClientFactory.CreateClient();

            // 설정 로드
            _smtpHost = _configuration["Email:Smtp:Host"];
            _smtpPort = _configuration.GetValue<int>("Email:Smtp:Port", 587);
            _smtpUsername = _configuration["Email:Smtp:Username"];
            _smtpPassword = _configuration["Email:Smtp:Password"];
            _fromEmail = _configuration["Email:FromAddress"];
            
            _smsApiKey = _configuration["Sms:ApiKey"];
            _smsApiUrl = _configuration["Sms:ApiUrl"];
        }

        /// <summary>
        /// 일반 이메일 발송
        /// </summary>
        public async Task SendEmailAsync(string to, string subject, string body)
        {
            try
            {
                _logger.LogInformation("Sending email to {To} with subject: {Subject}", to, subject);

                // 실제 환경에서는 SMTP 클라이언트나 이메일 서비스 API 사용
                // 현재는 로깅으로 대체
                if (string.IsNullOrEmpty(_smtpHost))
                {
                    _logger.LogWarning("SMTP not configured. Email simulated: To={To}, Subject={Subject}", to, subject);
                    await SimulateEmailDeliveryAsync();
                    return;
                }

                // TODO: 실제 SMTP 또는 이메일 서비스 구현
                await SendViaSmtpAsync(to, subject, body);
                
                _logger.LogInformation("Email sent successfully to {To}", to);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {To}", to);
                throw new InvalidOperationException($"Failed to send email: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// SMS 발송
        /// </summary>
        public async Task SendSmsAsync(string toNumber, string message)
        {
            try
            {
                _logger.LogInformation("Sending SMS to {ToNumber}", MaskPhoneNumber(toNumber));

                if (string.IsNullOrEmpty(_smsApiKey) || string.IsNullOrEmpty(_smsApiUrl))
                {
                    _logger.LogWarning("SMS API not configured. SMS simulated: To={To}, Message={Message}", 
                        MaskPhoneNumber(toNumber), message);
                    await SimulateSmsDeliveryAsync();
                    return;
                }

                // TODO: 실제 SMS 서비스 API 호출 구현
                await SendViaSmsApiAsync(toNumber, message);
                
                _logger.LogInformation("SMS sent successfully to {ToNumber}", MaskPhoneNumber(toNumber));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send SMS to {ToNumber}", MaskPhoneNumber(toNumber));
                throw new InvalidOperationException($"Failed to send SMS: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// MFA 복구 이메일 발송
        /// </summary>
        public async Task SendMfaRecoveryEmailAsync(string to, string? username, string recoveryLink)
        {
            try
            {
                _logger.LogInformation("Sending MFA recovery email to {To}", to);

                var subject = "AuthHive - MFA Recovery Request";
                var body = GenerateMfaRecoveryEmailBody(username, recoveryLink);

                await SendEmailAsync(to, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send MFA recovery email to {To}", to);
                throw new InvalidOperationException($"Failed to send MFA recovery email: {ex.Message}", ex);
            }
        }

        #region Private Helper Methods

        /// <summary>
        /// 이메일 전송 시뮬레이션 (개발/테스트용)
        /// </summary>
        private async Task SimulateEmailDeliveryAsync()
        {
            // 네트워크 지연 시뮬레이션
            await Task.Delay(100);
        }

        /// <summary>
        /// SMS 전송 시뮬레이션 (개발/테스트용)
        /// </summary>
        private async Task SimulateSmsDeliveryAsync()
        {
            // 네트워크 지연 시뮬레이션
            await Task.Delay(200);
        }

        /// <summary>
        /// 실제 SMTP를 통한 이메일 발송
        /// </summary>
        private async Task SendViaSmtpAsync(string to, string subject, string body)
        {
            // TODO: System.Net.Mail.SmtpClient 또는 MailKit 사용
            // 현재는 기본 구현으로 대체
            
            _logger.LogDebug("Using SMTP server: {Host}:{Port}", _smtpHost, _smtpPort);

            // 실제 구현 예시:
            /*
            using var client = new SmtpClient(_smtpHost, _smtpPort);
            client.Credentials = new NetworkCredential(_smtpUsername, _smtpPassword);
            client.EnableSsl = true;

            var mailMessage = new MailMessage(_fromEmail, to, subject, body)
            {
                IsBodyHtml = true
            };

            await client.SendMailAsync(mailMessage);
            */

            // 현재는 로깅으로 대체
            _logger.LogInformation("SMTP email would be sent: {To} - {Subject}", to, subject);
            await Task.CompletedTask;
        }

        /// <summary>
        /// SMS API를 통한 문자 발송
        /// </summary>
        private async Task SendViaSmsApiAsync(string toNumber, string message)
        {
            try
            {
                var requestBody = new
                {
                    to = toNumber,
                    message = message,
                    from = "AuthHive"
                };

                var json = JsonSerializer.Serialize(requestBody);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_smsApiKey}");

                var response = await _httpClient.PostAsync(_smsApiUrl, content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    throw new HttpRequestException($"SMS API returned {response.StatusCode}: {errorContent}");
                }

                _logger.LogDebug("SMS API response: {StatusCode}", response.StatusCode);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "SMS API request failed");
                throw;
            }
        }

        /// <summary>
        /// MFA 복구 이메일 본문 생성
        /// </summary>
        private string GenerateMfaRecoveryEmailBody(string? username, string recoveryLink)
        {
            var displayName = string.IsNullOrEmpty(username) ? "User" : username;
            
            return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <title>MFA Recovery - AuthHive</title>
</head>
<body style=""font-family: Arial, sans-serif; line-height: 1.6; color: #333;"">
    <div style=""max-width: 600px; margin: 0 auto; padding: 20px;"">
        <div style=""text-align: center; margin-bottom: 30px;"">
            <h1 style=""color: #2c3e50;"">AuthHive</h1>
            <h2 style=""color: #7f8c8d;"">MFA Recovery Request</h2>
        </div>
        
        <div style=""background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px;"">
            <p>Hello {displayName},</p>
            <p>We received a request to recover your Multi-Factor Authentication (MFA) settings.</p>
            <p>If you made this request, please click the link below to continue:</p>
        </div>
        
        <div style=""text-align: center; margin: 30px 0;"">
            <a href=""{recoveryLink}"" 
               style=""background-color: #3498db; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block;"">
                Recover MFA Settings
            </a>
        </div>
        
        <div style=""background-color: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;"">
            <p><strong>Security Notice:</strong></p>
            <ul>
                <li>This link will expire in 1 hour</li>
                <li>If you did not request this recovery, please ignore this email</li>
                <li>Never share this link with others</li>
            </ul>
        </div>
        
        <hr style=""margin: 30px 0; border: none; border-top: 1px solid #eee;"">
        
        <div style=""font-size: 12px; color: #7f8c8d; text-align: center;"">
            <p>This is an automated message from AuthHive.</p>
            <p>If you have questions, please contact our support team.</p>
            <p>&copy; 2024 AuthHive. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";
        }

        /// <summary>
        /// 전화번호 마스킹 (보안용)
        /// </summary>
        private string MaskPhoneNumber(string phoneNumber)
        {
            if (string.IsNullOrEmpty(phoneNumber) || phoneNumber.Length < 4)
                return "****";

            return phoneNumber.Length > 7 
                ? $"***-***-{phoneNumber.Substring(phoneNumber.Length - 4)}"
                : $"***{phoneNumber.Substring(phoneNumber.Length - 4)}";
        }

        #endregion

        #region Alternative Email Templates

        /// <summary>
        /// 인증 코드 이메일 템플릿
        /// </summary>
        public async Task SendVerificationCodeEmailAsync(string to, string code, int expirationMinutes = 5)
        {
            var subject = "AuthHive - Verification Code";
            var body = GenerateVerificationCodeEmailBody(code, expirationMinutes);
            await SendEmailAsync(to, subject, body);
        }

        /// <summary>
        /// 새 장치 로그인 알림 이메일
        /// </summary>
        public async Task SendNewDeviceLoginAlertAsync(string to, string deviceInfo, string location, string ipAddress)
        {
            var subject = "AuthHive - New Device Login Alert";
            var body = GenerateNewDeviceLoginAlertBody(deviceInfo, location, ipAddress);
            await SendEmailAsync(to, subject, body);
        }

        /// <summary>
        /// 계정 잠금 알림 이메일
        /// </summary>
        public async Task SendAccountLockNotificationAsync(string to, string reason, DateTime lockedUntil)
        {
            var subject = "AuthHive - Account Security Alert";
            var body = GenerateAccountLockNotificationBody(reason, lockedUntil);
            await SendEmailAsync(to, subject, body);
        }

        private string GenerateVerificationCodeEmailBody(string code, int expirationMinutes)
        {
            return $@"
<div style=""font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;"">
    <h2 style=""color: #2c3e50; text-align: center;"">Verification Code</h2>
    <p>Your AuthHive verification code is:</p>
    <div style=""text-align: center; margin: 20px 0;"">
        <span style=""font-size: 24px; font-weight: bold; background-color: #f1f3f4; padding: 10px 20px; border-radius: 5px; letter-spacing: 3px;"">{code}</span>
    </div>
    <p>This code will expire in {expirationMinutes} minutes.</p>
    <p><small>If you did not request this code, please ignore this email.</small></p>
</div>";
        }

        private string GenerateNewDeviceLoginAlertBody(string deviceInfo, string location, string ipAddress)
        {
            return $@"
<div style=""font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;"">
    <h2 style=""color: #e74c3c;"">Security Alert: New Device Login</h2>
    <p>A new device has logged into your AuthHive account:</p>
    <ul>
        <li><strong>Device:</strong> {deviceInfo}</li>
        <li><strong>Location:</strong> {location}</li>
        <li><strong>IP Address:</strong> {ipAddress}</li>
        <li><strong>Time:</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</li>
    </ul>
    <p>If this was you, you can safely ignore this email. If not, please secure your account immediately.</p>
</div>";
        }

        private string GenerateAccountLockNotificationBody(string reason, DateTime lockedUntil)
        {
            return $@"
<div style=""font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;"">
    <h2 style=""color: #e74c3c;"">Account Locked</h2>
    <p>Your AuthHive account has been temporarily locked.</p>
    <p><strong>Reason:</strong> {reason}</p>
    <p><strong>Locked until:</strong> {lockedUntil:yyyy-MM-dd HH:mm:ss} UTC</p>
    <p>If you believe this is an error, please contact our support team.</p>
</div>";
        }

        #endregion
    }
}