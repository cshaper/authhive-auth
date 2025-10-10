using Amazon.SimpleEmail;
using Amazon.SimpleEmail.Model;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Enums.Auth;
using AuthHive.Core.Enums.Infra.Communication;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.UserExperience;
using AuthHive.Core.Models.Base;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.External;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Infrastructure.Services.UserExperience
{
    /// <summary>
    /// AWS SES를 사용하여 이메일 발송을 처리하는 서비스 구현체입니다.
    /// </summary>
    public class EmailService : IEmailService
    {
        private readonly IAmazonSimpleEmailService _sesClient;
        private readonly ILogger<EmailService> _logger;
        private readonly string _defaultFromAddress;

        public EmailService(IAmazonSimpleEmailService sesClient, ILogger<EmailService> logger, IConfiguration configuration)
        {
            _sesClient = sesClient ?? throw new ArgumentNullException(nameof(sesClient));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _defaultFromAddress = configuration["EmailSettings:DefaultFromAddress"] ?? "no-reply@authhive.com";
        }

        #region IExternalService 구현

        public string ServiceName => "Amazon SES";
        public string Provider => "Amazon Web Services";
        public string? ApiVersion => "2010-12-01";
        public RetryPolicy RetryPolicy { get; set; } = new();
        public int TimeoutSeconds { get; set; } = 30;
        public bool EnableCircuitBreaker { get; set; } = false;
        public IExternalService? FallbackService { get; set; }

        public event EventHandler<ExternalServiceCalledEventArgs>? ServiceCalled;
        public event EventHandler<ExternalServiceFailedEventArgs>? ServiceFailed;
        public event EventHandler<ExternalServiceRecoveredEventArgs>? ServiceRecovered;

        public Task<ServiceHealthStatus> CheckHealthAsync()
        {
            bool isServiceHealthy = _sesClient != null;
            var result = new ServiceHealthStatus
            {
                ServiceName = this.ServiceName,
                IsHealthy = isServiceHealthy,
                Status = isServiceHealthy ? "Healthy" : "Unhealthy",
                CheckedAt = DateTime.UtcNow
            };
            return Task.FromResult(result);
        }

        public Task<ServiceResult> TestConnectionAsync() => throw new NotImplementedException();
        public Task<ServiceResult> ValidateConfigurationAsync() => throw new NotImplementedException();
        public Task<ServiceResult<ExternalServiceUsage>> GetUsageAsync(DateTime startDate, DateTime endDate, Guid? organizationId = null) => throw new NotImplementedException();
        public Task RecordMetricsAsync(ExternalServiceMetrics metrics) => throw new NotImplementedException();

        #endregion

        #region IEmailService 구현

        /// <summary>
        /// [개선] 조직 초대 이메일의 본문을 동적으로 생성하고 브랜딩 푸터를 추가합니다.
        /// </summary>
        public async Task<ServiceResult<string>> SendInvitationEmailAsync(Invitation invitation, string redirectUrl, CancellationToken cancellationToken = default)
        {
            // 초대 엔티티에 연결된 조직 이름을 안전하게 가져옵니다.
            // Organization 객체가 로드되지 않았을 경우를 대비하여 Null 조건부 연산자(?.)와 Null 병합 연산자(??)를 사용합니다.
            var organizationName = invitation.Organization?.Name ?? "an organization";

            var subject = $"[AuthHive] You're invited to join {organizationName}";
            var link = $"{redirectUrl}?invitationCode={invitation.InviteCode}";

            // [개선] 조직 이름을 본문에 포함시키고, 하단에 푸터를 추가하여 이메일 내용을 개선합니다.
            var htmlBody = $@"
                <html>
                <body style='font-family: Arial, sans-serif; color: #333;'>
                    <h2>You have been invited!</h2>
                    <p>You have been invited to join <strong>{organizationName}</strong> on the AuthHive platform.</p>
                    <p>Please click the button below to accept your invitation:</p>
                    <p style='margin: 20px 0;'>
                        <a href='{link}' style='background-color: #007bff; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;'>
                            <strong>Accept Invitation Now</strong>
                        </a>
                    </p>
                    <p>If you cannot click the button, please copy and paste this URL into your browser:</p>
                    <p>{link}</p>
                    <hr style='border: none; border-top: 1px solid #eee;' />
                    <p style='font-size: 0.8em; color: #777;'>
                        If you did not expect this invitation, you can safely ignore this email.
                    </p>
                    <br />
                    <p style='font-size: 0.7em; color: #aaa; text-align: center;'>
                        Powered by Authhive.com
                    </p>
                </body>
                </html>";

            var emailMessage = new EmailMessageDto
            {
                To = invitation.InviteeEmail,
                Subject = subject,
                Body = htmlBody,
                IsHtml = true,
                From = _defaultFromAddress // 발신자 주소 명시
            };

            return await SendEmailAsync(emailMessage, cancellationToken);
        }

        public async Task<ServiceResult<string>> SendEmailAsync(EmailMessageDto message, CancellationToken cancellationToken = default)
        {
            ServiceCalled?.Invoke(this, new ExternalServiceCalledEventArgs { ServiceName = this.ServiceName, Operation = nameof(SendEmailAsync), CalledAt = DateTime.UtcNow });
            try
            {
                var emailBody = new Body();
                if (message.IsHtml)
                {
                    emailBody.Html = new Content(message.Body);
                }
                else
                {
                    emailBody.Text = new Content(message.Body);
                }

                var request = new SendEmailRequest
                {
                    Source = message.From ?? _defaultFromAddress,
                    Destination = new Destination { ToAddresses = new List<string> { message.To } },
                    Message = new Message
                    {
                        Subject = new Content(message.Subject),
                        Body = emailBody
                    }
                };

                var response = await _sesClient.SendEmailAsync(request, cancellationToken);
                _logger.LogInformation("Email successfully sent to {Email}. MessageId: {MessageId}", message.To, response.MessageId);

                ServiceRecovered?.Invoke(this, new ExternalServiceRecoveredEventArgs { ServiceName = this.ServiceName, Operation = nameof(SendEmailAsync), RecoveredAt = DateTime.UtcNow });
                return ServiceResult<string>.Success(response.MessageId, "Email sent successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email}", message.To);
                ServiceFailed?.Invoke(this, new ExternalServiceFailedEventArgs { ServiceName = this.ServiceName, Operation = nameof(SendEmailAsync), Exception = ex, FailedAt = DateTime.UtcNow });
                return ServiceResult<string>.Failure("Failed to send email.", "EMAIL_SEND_FAILED");
            }
        }

        // ... (나머지 미구현 메서드들은 그대로 둠)
        public Task<ServiceResult<string>> SendOrganizationEmailAsync(Guid organizationId, EmailMessageDto message, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<string>> SendMfaRecoveryEmailAsync(string email, string userName, string recoveryLink, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<string>> SendVerificationEmailAsync(string email, string verificationCode, Guid? organizationId = null, string? userName = null, int expirationMinutes = 10, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<string>> SendPasswordResetEmailAsync(string email, string resetToken, Guid? organizationId = null, string? userName = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<string>> SendSecurityAlertEmailAsync(string email, SecurityAlertType alertType, Dictionary<string, string> details, Guid? connectedId = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<string>> SendTemplateEmailAsync(string email, string templateId, Dictionary<string, object> variables, Guid? organizationId = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<List<EmailTemplateDto>>> GetAvailableTemplatesAsync(Guid? organizationId = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<EmailTemplateDto?> GetCachedTemplateAsync(string templateId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<BulkEmailResultDto>> SendBulkEmailAsync(List<EmailRecipientDto> recipients, EmailMessageDto message, BulkEmailOptionsDto? options = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<BulkEmailStatusDto>> GetBulkEmailStatusAsync(string batchId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<EmailValidationResultDto>> ValidateEmailAddressAsync(string email, Guid? organizationId = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> IsEmailDomainBlockedAsync(string domain, Guid? organizationId = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> AddToUnsubscribeListAsync(string email, Guid? organizationId = null, string? reason = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> RemoveFromUnsubscribeListAsync(string email, Guid? organizationId = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<bool>> IsUnsubscribedAsync(string email, Guid? organizationId = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<EmailTrackingInfoDto>> GetEmailStatusAsync(string messageId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult<string>> SendWelcomeEmailAsync(string email, string userName, Guid organizationId, WelcomeEmailOptionsDto? options = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> ScheduleOnboardingSeriesAsync(string email, Guid organizationId, Guid connectedId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<ServiceResult> ProcessEmailWebhookAsync(string provider, Dictionary<string, object> webhookData) => throw new NotImplementedException();

        #endregion
    }
}

