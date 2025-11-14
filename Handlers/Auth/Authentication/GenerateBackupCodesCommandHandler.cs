// [AuthHive.Auth] Handlers/Auth/Authentication/GenerateBackupCodesCommandHandler.cs
// v17 CQRS "본보기": 'GenerateBackupCodesCommand' (MFA 백업 코드 생성)를 처리합니다.
// (SOP 2-Write-U)
//
// 1. v17 전문가 위임: IPasswordHashProvider를 사용하여 생성된 코드를 '해시'합니다.
// 2. Entity: User.BackupCodes에 '해시된' 코드 목록을 덮어씁니다.
// 3. Repository/UnitOfWork: 변경된 엔티티를 DB에 저장(Commit)합니다.
// 4. Mediator (Publish): 'BackupCodesGeneratedEvent'를 발행합니다.
// 5. Response: '원본(Plaintext)' 코드를 BackupCodesResult DTO로 반환합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.Security; // IPasswordHashProvider
using AuthHive.Core.Models.Auth.Authentication.Commands;
using AuthHive.Core.Models.Auth.Authentication.Common; // BackupCodesResult
using AuthHive.Core.Models.Auth.Authentication.Events; // BackupCodesGeneratedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography; // RandomNumberGenerator
using System.Text; // Encoding
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.Infra;

namespace AuthHive.Auth.Handlers.Auth.Authentication
{
    /// <summary>
    /// [v17] "MFA 백업 코드 생성" 유스케이스 핸들러 (SOP 2-Write-U)
    /// </summary>
    public class GenerateBackupCodesCommandHandler : IRequestHandler<GenerateBackupCodesCommand, BackupCodesResult>
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordHashProvider _passwordHashProvider;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<GenerateBackupCodesCommandHandler> _logger;
        private readonly IDateTimeProvider _dateTimeProvider;

        public GenerateBackupCodesCommandHandler(
            IUserRepository userRepository,
            IPasswordHashProvider passwordHashProvider,
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<GenerateBackupCodesCommandHandler> logger,
            IDateTimeProvider dateTimeProvider)
        {
            _userRepository = userRepository;
            _passwordHashProvider = passwordHashProvider;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
            _dateTimeProvider = dateTimeProvider;
        }

        public async Task<BackupCodesResult> Handle(GenerateBackupCodesCommand command, CancellationToken cancellationToken)
        {
            // 1. [SOP 2.3.2] 엔티티 조회
            var user = await _userRepository.GetByIdAsync(command.AggregateId, cancellationToken); // AggregateId는 UserId
            if (user == null)
            {
                throw new ValidationException($"User not found: {command.AggregateId}");
            }

            // 2. [SOP 2.3.1] 유효성 검증
            if (!user.IsTwoFactorEnabled)
            {
                _logger.LogWarning("GenerateBackupCodes failed: 2FA is not enabled for User {UserId}", user.Id);
                throw new ValidationException("2FA must be enabled before generating backup codes.");
            }

            // 3. [SOP 2.3.3] 비즈니스 로직 (v17 보안 원칙)
            var plaintextCodes = new List<string>();
            var hashedCodes = new List<string>();
            var generatedAt = _dateTimeProvider.UtcNow;

            for (int i = 0; i < command.Count; i++)
            {
                string newCode = GenerateNewBackupCode();
                plaintextCodes.Add(newCode);

                // [v17 전문가 위임] 원본 코드를 해시하여 저장
                string hashedCode = await _passwordHashProvider.HashPasswordAsync(newCode);
                hashedCodes.Add(hashedCode);
            }

            // 4. [SOP 2.3.3] 엔티티 상태 변경
            // [v17] 기존 코드를 모두 무효화하고 새 해시 목록으로 덮어씀
            user.BackupCodes = hashedCodes;
            // (추론) 백업 코드 생성 시간 업데이트 (User 엔티티에 관련 필드 필요시)
            // user.BackupCodesGeneratedAt = generatedAt;

            // 5. [SOP 2.3.4, 2.3.5] 저장 (v17 "본보기" 적용)
            await _userRepository.UpdateAsync(user, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            // 6. [SOP 2.3.6] 이벤트 발행
            var generatedEvent = new BackupCodesGeneratedEvent(
                userId: user.Id,
                organizationId: command.OrganizationId ?? user.OrganizationId,
                codesGeneratedCount: hashedCodes.Count,
                triggeredBy: command.TriggeredBy ?? user.Id
            );
            await _mediator.Publish(generatedEvent, cancellationToken);

            _logger.LogInformation("Generated {Count} new backup codes for User {UserId}", hashedCodes.Count, user.Id);

            // 7. [SOP 2.3.7] 응답 반환
            // [v17 보안] "원본(Plaintext)" 코드를 응답 DTO로만 반환 (저장X)
            return new BackupCodesResult(
                codes: plaintextCodes,
                generatedAt: generatedAt,
                remainingCount: hashedCodes.Count,
                downloadUrl: null // (파일 생성은 별도 핸들러 책임)
            );
        }

        /// <summary>
        /// 10자리 (숫자 + 대문자)의 암호학적으로 안전한 백업 코드를 생성합니다.
        /// (O, 0, I, 1 등 혼동되는 문자 제외)
        /// </summary>
        private string GenerateNewBackupCode(int length = 10)
        {
            const string chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
            var result = new StringBuilder(length);
            var buffer = new byte[sizeof(uint)];

            for (int i = 0; i < length; i++)
            {
                RandomNumberGenerator.Fill(buffer);
                uint num = BitConverter.ToUInt32(buffer, 0);
                result.Append(chars[(int)(num % (uint)chars.Length)]);
            }
            
            // 형식: XXXX-XXXXX
            if (length == 10)
            {
                result.Insert(5, '-');
            }

            return result.ToString();
        }
    }
}