using System;
using System.Linq; 
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;
using FluentValidation; // ✅ v18 표준: Validator 추가

// [Core Interfaces]
using AuthHive.Core.Interfaces.User.Repositories.Profile; // ✅ Repository Interface 추가
using AuthHive.Core.Interfaces.Infra.Storage; 
using AuthHive.Core.Exceptions;

// [Models & Entities]
using AuthHive.Core.Entities.User; // UserProfile Entity가 필요합니다.
using AuthHive.Core.Models.User.Commands.Profile;
using AuthHive.Core.Models.User.Events.Profile;

namespace AuthHive.Core.Handlers.User.Profile;

/// <summary>
/// [v18] "프로필 이미지 삭제" 핸들러 (Refactored)
/// </summary>
public class DeleteProfileImageCommandHandler : IRequestHandler<DeleteProfileImageCommand, Unit>
{
 
    private readonly IUserProfileRepository _repository; // ✅ Repository 사용
    private readonly IStorageService _storageService; 
    private readonly IPublisher _publisher; 
    private readonly ILogger<DeleteProfileImageCommandHandler> _logger;
    private readonly IValidator<DeleteProfileImageCommand> _validator; // ✅ v18 표준: Validator 추가

    public DeleteProfileImageCommandHandler(
        IUserProfileRepository repository, // ✅ DbContext -> Repository 변경
        IStorageService storageService,
        IPublisher publisher,
        ILogger<DeleteProfileImageCommandHandler> logger,
        IValidator<DeleteProfileImageCommand> validator) // ✅ Validator 주입
    {
        _repository = repository;
        _storageService = storageService;
        _publisher = publisher;
        _logger = logger;
        _validator = validator;
    }

    public async Task<Unit> Handle(DeleteProfileImageCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling DeleteProfileImageCommand for User {UserId}", command.UserId);

        // 0. 유효성 검사 (v18 표준 추가)
        var validationResult = await _validator.ValidateAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
            throw new DomainValidationException("Profile image deletion validation failed.", errorMessages);
        }

        // 1. 엔티티 조회 (Repository 사용)
        // ✅ _context.UserProfiles.FirstOrDefaultAsync(...) 대체
        var profile = await _repository.GetByUserIdAsync(command.UserId, cancellationToken);

        // 2. 멱등성(Idempotency) 체크 및 유효성 검증
        // 프로필이 없거나, 이미 이미지가 없는 경우 성공으로 간주하고 종료
        if (profile == null) 
        {
            // 프로필 엔티티 자체가 없으면 삭제할 것도 없으므로 성공 처리
             _logger.LogWarning("UserProfile not found for deletion. Skipping. User {UserId}", command.UserId);
            return Unit.Value;
        }

        if (string.IsNullOrEmpty(profile.ProfileImageUrl))
        {
             _logger.LogWarning("Profile image already empty. Skipping. User {UserId}", command.UserId);
            return Unit.Value;
        }

        string oldImageUrl = profile.ProfileImageUrl;

        // 3. [Domain Logic] 상태 변경
        profile.DeleteProfileImage(); // ProfileImageUrl = null 처리

        // 4. [Persistence] DB 저장
        // ✅ _context.SaveChangesAsync(...) 대체
        await _repository.UpdateAsync(profile, cancellationToken); // Repository Update 호출

        _logger.LogInformation("Profile image reset to default in DB. User {UserId}", command.UserId);

        // 5. [Infra] 실제 파일 삭제 (GCS)
        // DB 커밋 후에 실행 (트랜잭션 정합성 우선)
        // 이 로직은 IStorageService를 사용하므로 Core 레이어에서 Infra에 의존하지 않습니다.
        try
        {
            string objectName = ExtractObjectNameFromUrl(oldImageUrl);
            await _storageService.DeleteAsync(objectName, cancellationToken);
            _logger.LogInformation("Deleted GCS object: {ObjectName}", objectName);
        }
        catch (Exception ex)
        {
            // GCS 실패는 롤백하지 않음 (고아 파일은 배치로 처리)
            _logger.LogError(ex, "Failed to delete GCS object. User {UserId}, Url {Url}", command.UserId, oldImageUrl);
        }

        // 6. [Event] 이벤트 발행
        var imageDeletedEvent = new ProfileImageDeletedEvent
        {
            // BaseEvent Required
            AggregateId = profile.UserId,
            OccurredOn = DateTime.UtcNow,
            
            // Context
            EventId = Guid.NewGuid(),
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,
            CorrelationId = command.CorrelationId?.ToString(),

            // Payload
            UserId = profile.UserId,
            DeletedImageUrl = oldImageUrl,
            DeletedAt = DateTime.UtcNow,
            DeletedByConnectedId = command.TriggeredBy,
            IpAddress = command.IpAddress
        };

        await _publisher.Publish(imageDeletedEvent, cancellationToken);

        return Unit.Value;
    }

    /// <summary>
    /// URL에서 GCS Object Key를 추출하는 헬퍼 메서드
    /// (정적 유틸리티 로직이므로 핸들러 내부에 두는 것이 허용됨)
    /// </summary>
    private static string ExtractObjectNameFromUrl(string url)
    {
        try
        {
            var uri = new Uri(url);
            // URL 파싱 로직은 그대로 유지
            return string.Join("", uri.Segments.Skip(2)); 
        }
        catch
        {
            return url; 
        }
    }
}