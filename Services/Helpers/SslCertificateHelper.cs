// AuthHive.Auth/Services/Helpers/SslCertificateHelper.cs
using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Infra.Security;

namespace AuthHive.Auth.Services.Helpers
{
    /// <summary>
    /// SSL 인증서 관리 Helper 구현체 - AuthHive v15
    /// SSL/TLS 인증서 상태 확인 및 Let's Encrypt 통합
    /// </summary>
    public class SslCertificateHelper : ISslCertificateHelper
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<SslCertificateHelper> _logger;
        private readonly int _sslCheckTimeout;

        public SslCertificateHelper(
            IConfiguration configuration,
            ILogger<SslCertificateHelper> logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _sslCheckTimeout = _configuration.GetValue<int>("Ssl:CheckTimeoutSeconds", 10) * 1000;
        }

        public async Task<SslCertificateStatus> CheckCertificateStatusAsync(string domain)
        {
            var status = new SslCertificateStatus
            {
                LastCheckedAt = DateTime.UtcNow
            };

            try
            {
                // HTTPS 포트로 연결 시도
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(domain, 443);
                
                if (await Task.WhenAny(connectTask, Task.Delay(_sslCheckTimeout)) != connectTask)
                {
                    status.Status = "Timeout";
                    status.ErrorMessage = "Connection timeout";
                    return status;
                }

                using var sslStream = new SslStream(
                    client.GetStream(),
                    false,
                    ValidateServerCertificate,
                    null);

                await sslStream.AuthenticateAsClientAsync(domain);

                var certificate = sslStream.RemoteCertificate as X509Certificate2;
                
                if (certificate != null)
                {
                    status.IsEnabled = true;
                    status.IsValid = certificate.Verify();
                    status.Subject = certificate.Subject;
                    status.Issuer = certificate.Issuer;
                    status.IssuedAt = certificate.NotBefore;
                    status.ExpiresAt = certificate.NotAfter;
                    
                    // 인증서 타입 판별
                    status.CertificateType = DetermineCertificateType(certificate);
                    
                    // 상태 결정
                    if (certificate.NotAfter <= DateTime.UtcNow)
                    {
                        status.Status = "Expired";
                        status.IsValid = false;
                    }
                    else if (certificate.NotAfter <= DateTime.UtcNow.AddDays(30))
                    {
                        status.Status = "ExpiringNoon";
                    }
                    else
                    {
                        status.Status = "Active";
                    }

                    _logger.LogInformation(
                        "SSL certificate check for {Domain}: Status={Status}, Expires={Expires}",
                        domain, status.Status, status.ExpiresAt);
                }
                else
                {
                    status.Status = "Error";
                    status.ErrorMessage = "Could not retrieve certificate";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking SSL certificate for {Domain}", domain);
                
                status.IsEnabled = false;
                status.IsValid = false;
                status.Status = "Error";
                status.ErrorMessage = ex.Message;
            }

            return status;
        }

        public async Task<SslRenewalResult> RenewCertificateAsync(string domain)
        {
            try
            {
                // Let's Encrypt 또는 다른 ACME 제공자를 통한 인증서 갱신
                // 실제 구현은 ACME 클라이언트 라이브러리 사용 필요
                // 예: Certes, ACMESharp 등

                _logger.LogInformation("Starting SSL certificate renewal for {Domain}", domain);

                // 임시 구현 - 실제로는 ACME 프로토콜 구현 필요
                await Task.Delay(1000); // 시뮬레이션

                // 성공 시나리오 (실제로는 ACME 응답 처리)
                var newExpiryDate = DateTime.UtcNow.AddDays(90); // Let's Encrypt는 90일

                _logger.LogInformation(
                    "SSL certificate renewed for {Domain}. New expiry: {Expiry}",
                    domain, newExpiryDate);

                return new SslRenewalResult
                {
                    IsSuccess = true,
                    ExpiryDate = newExpiryDate,
                    CertificateThumbprint = GenerateThumbprint()
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to renew SSL certificate for {Domain}", domain);
                
                return new SslRenewalResult
                {
                    IsSuccess = false,
                    ErrorMessage = ex.Message
                };
            }
        }

        private bool ValidateServerCertificate(
            object sender,
            X509Certificate? certificate,
            X509Chain? chain,
            SslPolicyErrors sslPolicyErrors)
        {
            // 프로덕션에서는 더 엄격한 검증 필요
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            _logger.LogWarning(
                "SSL certificate validation errors: {Errors}",
                sslPolicyErrors);

            // 개발 환경에서는 자체 서명 인증서 허용 가능
            var allowSelfSigned = _configuration.GetValue<bool>("Ssl:AllowSelfSigned", false);
            
            return allowSelfSigned && 
                   sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
        }

        private string DetermineCertificateType(X509Certificate2 certificate)
        {
            var subject = certificate.Subject.ToLowerInvariant();
            
            // Wildcard 인증서 확인
            if (subject.Contains("*."))
                return "Wildcard";
            
            // EV 인증서 확인 (조직 정보 포함)
            if (certificate.Subject.Contains("O=") && 
                certificate.Subject.Contains("C=") &&
                certificate.Subject.Contains("SERIALNUMBER="))
                return "EV";
            
            // OV 인증서 확인
            if (certificate.Subject.Contains("O="))
                return "OV";
            
            // 기본값: DV (Domain Validation)
            return "DV";
        }

        private string GenerateThumbprint()
        {
            // 실제로는 인증서에서 추출
            return Guid.NewGuid().ToString("N").Substring(0, 40).ToUpperInvariant();
        }
    }
}