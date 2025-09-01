// using AuthHive.Core.Interfaces.Auth.Service;
// using AuthHive.Core.Interfaces.Auth.Repository;
// using AutoMapper; // AutoMapper 사용을 강력히 권장합니다.

using AuthHive.Auth.Data.Context;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.ConnectedId.Requests;
using AuthHive.Core.Models.Auth.ConnectedId.Responses;
using AuthHive.Core.Models.Common;
using AutoMapper;
using static AuthHive.Core.Enums.Auth.ConnectedIdEnums;

namespace AuthHive.Auth.Services
{
    public class ConnectedIdService : IConnectedIdService
    {
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly ILogger<ConnectedIdService> _logger;
        private readonly IMapper _mapper; // AutoMapper 주입
        private readonly AuthDbContext _context;
        public ConnectedIdService(
            IConnectedIdRepository connectedIdRepository,
            ILogger<ConnectedIdService> logger,
            IMapper mapper,
            AuthDbContext context)
        {
            _connectedIdRepository = connectedIdRepository;
            _logger = logger;
            _mapper = mapper;
            _context = context; 
        }
        #region IService Implementation

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                // DB 연결 가능 여부와 Repository 기본 동작 여부 확인
                return await _context.Database.CanConnectAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ConnectedIdService health check failed");
                return false;
            }
        }

        public Task InitializeAsync()
        {
            _logger.LogInformation("ConnectedIdService initialized.");
            return Task.CompletedTask;
        }

        #endregion
        // --- CRUD 작업 ---
        public async Task<ServiceResult<ConnectedIdResponse>> CreateAsync(CreateConnectedIdRequest request)
        {
            // ... 검증 및 생성 로직 ...
            var existing = await _connectedIdRepository.GetByUserAndOrganizationAsync(request.UserId, request.OrganizationId);
            if (existing != null) return ServiceResult<ConnectedIdResponse>.Failure("User is already a member.");

            var newEntity = _mapper.Map<AuthHive.Core.Entities.Auth.ConnectedId>(request);
            // ... 추가 로직 (상태 설정 등) ...

            await _connectedIdRepository.AddAsync(newEntity);
            var response = _mapper.Map<ConnectedIdResponse>(newEntity);
            return ServiceResult<ConnectedIdResponse>.Success(response);
        }

        public async Task<ServiceResult<ConnectedIdDetailResponse>> GetByIdAsync(Guid id)
        {
            // GetWithRelatedDataAsync를 사용하여 관련 데이터 한번에 조회
            var entity = await _connectedIdRepository.GetWithRelatedDataAsync(id, includeUser: true, includeOrganization: true);
            if (entity == null) return ServiceResult<ConnectedIdDetailResponse>.Failure("ConnectedId not found.");

            var response = _mapper.Map<ConnectedIdDetailResponse>(entity);
            return ServiceResult<ConnectedIdDetailResponse>.Success(response);
        }

        public async Task<ServiceResult<ConnectedIdResponse>> UpdateAsync(Guid id, UpdateConnectedIdRequest request)
        {
            var entity = await _connectedIdRepository.GetByIdAsync(id);
            if (entity == null) return ServiceResult<ConnectedIdResponse>.Failure("ConnectedId not found.");

            _mapper.Map(request, entity); // AutoMapper로 업데이트
            await _connectedIdRepository.UpdateAsync(entity);

            var response = _mapper.Map<ConnectedIdResponse>(entity);
            return ServiceResult<ConnectedIdResponse>.Success(response);
        }

        public async Task<ServiceResult> DeleteAsync(Guid id)
        {
            var entity = await _connectedIdRepository.GetByIdAsync(id);
            if (entity == null) return ServiceResult.Failure("ConnectedId not found.");

            // 소프트 삭제 로직 (상태 변경 등)
            await _connectedIdRepository.DeleteAsync(entity);
            return ServiceResult.Success();
        }

        // --- 조회 작업 ---
        public Task<ServiceResult<ConnectedIdListResponse>> GetByOrganizationAsync(Guid organizationId, SearchConnectedIdsRequest request)
        {
            // Repository를 통해 페이징된 데이터 조회 로직 구현
            // ...
            return Task.FromResult(ServiceResult<ConnectedIdListResponse>.Success(new ConnectedIdListResponse()));
        }

        public async Task<ServiceResult<IEnumerable<ConnectedIdResponse>>> GetByUserAsync(Guid userId)
        {
            var entities = await _connectedIdRepository.GetByUserIdAsync(userId);
            var response = _mapper.Map<IEnumerable<ConnectedIdResponse>>(entities);
            return ServiceResult<IEnumerable<ConnectedIdResponse>>.Success(response);
        }

        // --- 활동 추적 및 검증 ---
        public Task<ServiceResult> UpdateLastActivityAsync(Guid id)
        {
            // ExecuteUpdateAsync 사용 최적화 고려
            // ...
            return Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<bool>> ValidateAsync(Guid id)
        {
            var entity = await _connectedIdRepository.GetByIdAsync(id);
            var isValid = entity != null && !entity.IsDeleted && entity.Status == ConnectedIdStatus.Active;
            return ServiceResult<bool>.Success(isValid);
        }

        public async Task<ServiceResult<bool>> IsMemberOfOrganizationAsync(Guid userId, Guid organizationId)
        {
            var isMember = await _connectedIdRepository.IsMemberOfOrganizationAsync(userId, organizationId);
            return ServiceResult<bool>.Success(isMember);
        }
    }
}