using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

// [Core & Infra]
using AuthHive.Infra.Persistence.Context; // [v18] AuthDbContext 직접 사용
using AuthHive.Core.Interfaces.Infra.Storage; // GCS 서비스
using AuthHive.Core.Exceptions;

// [Models]
using AuthHive.Core.Models.User.Commands.Profile;
using AuthHive.Core.Models.User.Events.Profile;

namespace AuthHive.Core.Handlers.User.Profile;

/// <summary>
/// [v18] "프로필 이미지 삭제" 핸들러
/// 프로필 이미지를 제거(기본 이미지로 변경)하고, 실제 스토리지(GCS)에서도 파일을 삭제합니다.
/// </summary>
public class DeleteProfileImageCommandHandler : IRequestHandler<DeleteProfileImageCommand, Unit>
{
    private readonly AuthDbContext _context;          // [변경] Repository -> DbContext
    private readonly IStorageService _storageService; // [유지] 외부 스토리지 서비스
    private readonly IPublisher _publisher;           // [변경] IMediator -> IPublisher
    private readonly ILogger<DeleteProfileImageCommandHandler> _logger;

    public DeleteProfileImageCommandHandler(
        AuthDbContext context,
        IStorageService storageService,
        IPublisher publisher,
        ILogger<DeleteProfileImageCommandHandler> logger)
    {
        _context = context;
        _storageService = storageService;
        _publisher = publisher;
        _logger = logger;
    }

    public async Task<Unit> Handle(DeleteProfileImageCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Handling DeleteProfileImageCommand for User {UserId}", command.UserId);

        // 1. 엔티티 조회 (DbContext 직접 사용)
        // UserProfiles 테이블에서 조회 (User와 1:1 관계이므로 Profile이 없을 수도 있음을 고려)
        var profile = await _context.UserProfiles
            .FirstOrDefaultAsync(p => p.UserId == command.UserId, cancellationToken);

        // 2. 멱등성(Idempotency) 체크
        // 프로필이 없거나, 이미 이미지가 없는 경우 성공으로 간주하고 종료
        if (profile == null || string.IsNullOrEmpty(profile.ProfileImageUrl))
        {
            _logger.LogWarning("Profile not found or image already empty. User {UserId}", command.UserId);
            return Unit.Value;
        }

        string oldImageUrl = profile.ProfileImageUrl;

        // 3. [Domain Logic] 상태 변경 (Entity 메서드 호출)
        profile.DeleteProfileImage(); // ProfileImageUrl = null 처리

        // 4. [Persistence] DB 저장
        // EF Core Change Tracking이 작동하므로 Update 호출 불필요
        await _context.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Profile image reset to default in DB. User {UserId}", command.UserId);

        // 5. [Infra] 실제 파일 삭제 (GCS)
        // DB 커밋 후에 실행하여, DB 실패 시 파일이 지워지는 것을 방지 (정합성)
        if (!string.IsNullOrEmpty(oldImageUrl))
        {
            try
            {
                // URL에서 Object Name 추출 (간단한 파싱)
                string objectName = ExtractObjectNameFromUrl(oldImageUrl);
                
                await _storageService.DeleteAsync(objectName, cancellationToken);
                _logger.LogInformation("Deleted GCS object: {ObjectName}", objectName);
            }
            catch (Exception ex)
            {
                // 파일 삭제 실패는 비즈니스 로직(DB 갱신)을 롤백시키지 않음 (로그만 남김)
                // 추후 "GCS 고아 파일 정리 배치" 등이 처리할 영역
                _logger.LogError(ex, "Failed to delete GCS object. User {UserId}, Url {Url}", command.UserId, oldImageUrl);
            }
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
    /// </summary>
    private static string ExtractObjectNameFromUrl(string url)
    {
        try
        {
            // 예: https://storage.googleapis.com/bucket/profiles/user-1/img.png
            // -> profiles/user-1/img.png
            var uri = new Uri(url);
            // 경로의 첫 번째 세그먼트(버킷명 등)를 제외하고 나머지 경로 조합
            // (실제 스토리지 구조에 따라 조정 필요)
            return string.Join("", uri.Segments.Skip(2)); 
        }
        catch
        {
            return url; // 파싱 실패 시 원본 반환 시도
        }
    }
}