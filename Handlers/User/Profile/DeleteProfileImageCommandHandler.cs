// [AuthHive.Auth] DeleteProfileImageCommandHandler.cs
// v17 CQRS "본보기": 'UserProfile'의 프로필 이미지를 삭제(GCS)하고
// 엔티티는 '기본 이미지'로 되돌리는 'DeleteProfileImageCommand'를 처리합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Interfaces.Infra.Storage; // [v17] GCS 서비스 주입
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Profile; // ProfileImageDeletedEvent
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17] "프로필 이미지 삭제" 유스케이스 핸들러 (SOP 1-Write-H)
    /// v17 CQRS 철학에 따라 데이터를 반환하지 않습니다 (Unit).
    /// </summary>
    public class DeleteProfileImageCommandHandler : IRequestHandler<DeleteProfileImageCommand, Unit>
    {
        private readonly IUserProfileRepository _profileRepository;
        private readonly IStorageService _storageService; // [v17] GCS 전문가
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMediator _mediator;
        private readonly ILogger<DeleteProfileImageCommandHandler> _logger;

        public DeleteProfileImageCommandHandler(
            IUserProfileRepository profileRepository,
            IStorageService storageService, // [v17] GCS 전문가 주입
            IUnitOfWork unitOfWork,
            IMediator mediator,
            ILogger<DeleteProfileImageCommandHandler> logger)
        {
            _profileRepository = profileRepository;
            _storageService = storageService;
            _unitOfWork = unitOfWork;
            _mediator = mediator;
            _logger = logger;
        }

        public async Task<Unit> Handle(DeleteProfileImageCommand command, CancellationToken cancellationToken)
        {
            _logger.LogInformation("Handling DeleteProfileImageCommand for User {UserId}", command.UserId);

            // 1. 엔티티 조회
            var profile = await _profileRepository.GetByIdAsync(command.UserId, cancellationToken);
            if (profile == null || string.IsNullOrEmpty(profile.ProfileImageUrl))
            {
                _logger.LogWarning("Profile not found or image already empty for User {UserId}. Skipping.", command.UserId);
                return Unit.Value; // 멱등성(Idempotency): 이미 삭제된 상태이므로 성공 처리
            }
            
            // [v17 로직] v16 Validator는 별도 로직이 없었으므로 검증 단계 생략
            
            string oldImageUrl = profile.ProfileImageUrl;

            // 2. [철학 적용] 엔티티 도메인 메서드 호출 (상태 변경)
            // (v16 UserProfileService.DeleteProfileImageAsync 로직 이관)
            profile.DeleteProfileImage(); // ProfileImageUrl을 "기본 아바타"로 설정

            // 3. 데이터베이스 저장 (Update)
            await _profileRepository.UpdateAsync(profile, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);

            _logger.LogInformation("Profile image URL reset to default for User {UserId}", command.UserId);

            // 4. 인프라 작업 (GCS 파일 삭제)
            // [정합성] DB 트랜잭션이 성공한 후에 실제 파일을 삭제 (실패 시 롤백 방지)
            try
            {
                // TODO: oldImageUrl이 "기본 아바타" URL이 아닐 경우에만 삭제하는 로직 필요
                if (oldImageUrl != profile.ProfileImageUrl) // profile.ProfileImageUrl은 이제 기본 URL
                {
                    // objectName 추출 (URL -> GCS 경로)
                    // (이 로직은 IStorageService 또는 헬퍼가 담당해야 함)
                    string objectName = ExtractObjectNameFromUrl(oldImageUrl); 
                    
                    await _storageService.DeleteAsync(objectName, cancellationToken);
                    _logger.LogInformation("Old image deleted from GCS: {ObjectName}", objectName);
                }
            }
            catch (Exception ex)
            {
                // [정합성] GCS 삭제에 실패해도 DB는 이미 롤백되었으므로, 로깅만 하고 에러를 던지지 않음
                // (또는 이 이벤트를 구독하는 별도 핸들러가 GCS 삭제를 재시도하도록 큐에 넣음)
                _logger.LogError(ex, "Failed to delete old image from GCS for User {UserId}: {OldUrl}", command.UserId, oldImageUrl);
            }

            // 5. 이벤트 발행 (Notify)
            var imageDeletedEvent = new ProfileImageDeletedEvent(
                userId: profile.UserId,
                deletedByConnectedId: command.TriggeredBy ?? command.UserId,
                deletedImageUrl: oldImageUrl, // [정합성] 삭제된 URL을 이벤트에 전달
                organizationId: command.OrganizationId,
                correlationId: command.CorrelationId,
                ipAddress: command.IpAddress, // BaseCommand에서 상속
                source: "UserProfileHandler" // v17 표준
            );
            await _mediator.Publish(imageDeletedEvent, cancellationToken);
            
            // 6. 응답 DTO 반환 (데이터 반환 안 함)
            return Unit.Value;
        }
        
        /// <summary>
        /// (임시 헬퍼) Public URL에서 GCS Object Name을 추출합니다.
        /// 이 로직은 IStorageService로 이동해야 합니다.
        /// </summary>
        private string ExtractObjectNameFromUrl(string url)
        {
            // 예: "https://storage.googleapis.com/BUCKET_NAME/profiles/user-123/avatar.png"
            // -> "profiles/user-123/avatar.png"
            try
            {
                var uri = new Uri(url);
                return string.Join("/", uri.Segments.Skip(2)); // "BUCKET_NAME/" 스킵
            }
            catch { return url; } // URL 형식이 아닐 경우
        }
    }
}