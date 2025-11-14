// [AuthHive.Auth] TotpService.cs
using AuthHive.Core.Interfaces.Infra.Security;
using AuthHive.Core.Interfaces.Security; // Core의 인터페이스 참조
using AuthHive.Core.Models.Auth.Authentication.Responses;
using Google.Authenticator;
using QRCoder; // (라이브러리가 내부적으로 사용)
using System; // [v17 추가]
using System.Security.Cryptography; // [v17 추가] RandomNumberGenerator

namespace AuthHive.Auth.Services.Security
{
    /// <summary>
    /// [v17 수정] TOTP (Google Authenticator) 전문가 서비스 구현체
    /// </summary>
    public class TotpService : ITotpService
    {
        public EnrollMfaMethodResponse GenerateTotpSetup(string issuer, string userEmail)
        {
            var authenticator = new TwoFactorAuthenticator();

            // 1. [v17 수정] v17 전문가가 비밀 키를 직접 생성 (160비트 / 20바이트)
            var secretKeyBytes = GenerateRandomSecretKey();

            // 2. [v17 수정] 소스 코드의 정확한 시그니처 호출 
            var setupInfo = authenticator.GenerateSetupCode(
                issuer: issuer,
                accountTitleNoSpaces: userEmail, // [CS1739 해결] 'account:' -> 'accountTitleNoSpaces:'
                accountSecretKey: secretKeyBytes, // [v17 수정] 'secret: null' -> 'accountSecretKey: ...'
                qrPixelsPerModule: 10, // (GDI+ 오류 방지) [cite: 109-122]
                generateQrCode: true
            );

            // 3. v17 EnrollMfaMethodResponse DTO로 직접 반환
            // (라이브러리가 반환한 SecretKey와 QR 이미지를 사용) 
            return new EnrollMfaMethodResponse(
                success: true,
                method: "TOTP",
                secretKey: setupInfo.ManualEntryKey, // Base32 인코딩된 비밀 키
                qrCodeImageUrl: setupInfo.QrCodeSetupImageUrl // "data:image/png;base64,..."
            );
        }

        public bool ValidateCode(string secretKey, string userCode)
        {
            var authenticator = new TwoFactorAuthenticator();

            // [CS0103 해결] DefaultClockDriftTolerance는 private 멤버이므로 접근 불가.
            // (string, string, bool) 시그니처를 가진 public 오버로드 는
            // 라이브러리 내부적으로 기본 시간 오차(private DefaultClockDriftTolerance)를 사용합니다.
            return authenticator.ValidateTwoFactorPIN(
                accountSecretKey: secretKey,
                twoFactorCodeFromClient: userCode,
                secretIsBase32: true
            );
        }

        /// <summary>
        /// 암호학적으로 안전한 160비트(20바이트) 비밀 키를 생성합니다.
        /// </summary>
        private byte[] GenerateRandomSecretKey(int length = 20)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var secretKey = new byte[length];
                rng.GetBytes(secretKey);
                return secretKey;
            }
        }
    }
}