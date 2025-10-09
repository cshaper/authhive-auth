// Path: AuthHive.Auth/Services/Session/SessionService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Auth.Repository;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Authentication.Common;
using AuthHive.Core.Models.Auth.Session;
using AuthHive.Core.Models.Auth.Session.Cache;
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Models.Auth.Session.Responses;
using AuthHive.Core.Models.Auth.Session.Views;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Cache;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Auth.Services.Session
{
    public class SessionService : ISessionService
    {
        private readonly ISessionRepository _sessionRepository;
        private readonly ISessionActivityLogRepository _activityLogRepository;
        private readonly IConnectedIdRepository _connectedIdRepository;
        private readonly IMemoryCache _cache;
        private readonly IConfiguration _configuration;
        private readonly ILogger<SessionService> _logger;
        // 캐시 키 상수
        private const string SESSION_CACHE_PREFIX = "session:";
        private const string SESSION_TOKEN_CACHE_PREFIX = "session_token:";
        public SessionService(
            ISessionRepository sessionRepository,
            ISessionActivityLogRepository activityLogRepository,
            IConnectedIdRepository connectedIdRepository,
            IMemoryCache cache,
            IConfiguration configuration,
            ILogger<SessionService> logger)
        {
            _sessionRepository = sessionRepository;
            _activityLogRepository = activityLogRepository;
            _connectedIdRepository = connectedIdRepository;
            _cache = cache;
            _configuration = configuration;
            _logger = logger;
        }

        #region IService Implementation
        public Task InitializeAsync(CancellationToken cancellationToken = default)
            => Task.CompletedTask;
        public async Task<bool> IsHealthyAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await _sessionRepository.CountAsync(cancellationToken: cancellationToken); // ◀◀ Named parameter 사용
                return true;
            }
            catch (OperationCanceledException)
            {
                // 취소 요청 시에는 비정상 상태로 간주
                return false;
            }
            catch (Exception ex)
            {
                // DB 연결 실패 등의 일반적인 예외 처리
                _logger.LogWarning(ex, "SessionService health check failed.");
                return false;
            }
        }
        #endregion

        #region 세션 생성 및 종료
        // Helper method
        private string GenerateSecureToken()
        {
            var bytes = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return Convert.ToBase64String(bytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }

        public async Task<ServiceResult> EndSessionAsync(Guid sessionId, SessionEndReason reason)
        {
            try
            {
                // 1. 세션 조회
                var session = await _sessionRepository.GetByIdAsync(sessionId);
                if (session == null)
                {
                    return ServiceResult.Failure($"Session {sessionId} not found");
                }

                // 2. 이미 종료된 세션인지 확인
                if (session.Status == SessionStatus.Terminated ||
                    session.Status == SessionStatus.Expired)
                {
                    return ServiceResult.Success(); // 이미 종료됨
                }

                // 3. 세션 종료 처리
                await _sessionRepository.EndSessionAsync(sessionId, reason, DateTime.UtcNow);

                // 4. 캐시에서 제거
                var cacheKey = $"session:{sessionId}";
                _cache.Remove(cacheKey);

                if (!string.IsNullOrEmpty(session.SessionToken))
                {
                    var tokenCacheKey = $"session_token:{session.SessionToken}";
                    _cache.Remove(tokenCacheKey);
                }

                // 5. 활동 로그 기록
                var activityLog = new SessionActivityLog
                {
                    Id = Guid.NewGuid(),
                    SessionId = sessionId,
                    ActivityType = SessionActivityType.Logout, // Terminated가 없으므로 Logout 사용
                    Details = $"Session terminated. Reason: {reason}",
                    OccurredAt = DateTime.UtcNow
                };
                await _activityLogRepository.AddAsync(activityLog);

                // 6. 자식 세션이 있는 경우 함께 종료 (전역 세션이 종료되면 하위 조직 세션도 종료)
                if (session.Level == SessionLevel.Global)
                {
                    var childSessions = await _sessionRepository.GetChildSessionsAsync(sessionId, true);
                    foreach (var child in childSessions)
                    {
                        await EndSessionAsync(child.Id, SessionEndReason.ParentSessionTerminated);
                    }
                }

                _logger.LogInformation("Session {SessionId} ended. Reason: {Reason}", sessionId, reason);
                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to end session {SessionId}", sessionId);
                return ServiceResult.Failure($"Failed to end session: {ex.Message}");
            }
        }

        public async Task<ServiceResult> EndAllSessionsAsync(Guid connectedId, SessionEndReason reason)
        {
            try
            {
                // 1. ConnectedId의 모든 활성 세션 조회
                var activeSessions = await _sessionRepository.GetActiveSessionsAsync(connectedId);

                if (!activeSessions.Any())
                {
                    return ServiceResult.Success(); // 활성 세션 없음
                }

                // 2. 각 세션 종료
                var failedSessions = new List<Guid>();

                foreach (var session in activeSessions)
                {
                    var result = await EndSessionAsync(session.Id, reason);
                    if (!result.IsSuccess)
                    {
                        failedSessions.Add(session.Id);
                    }
                }

                // 3. 결과 반환
                if (failedSessions.Any())
                {
                    _logger.LogWarning("Failed to end some sessions for ConnectedId {ConnectedId}: {FailedSessions}",
                        connectedId, string.Join(", ", failedSessions));
                    return ServiceResult.Failure($"Failed to end {failedSessions.Count} sessions");
                }

                _logger.LogInformation("All sessions ended for ConnectedId {ConnectedId}. Total: {Count}",
                    connectedId, activeSessions.Count());

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to end all sessions for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult.Failure($"Failed to end all sessions: {ex.Message}");
            }
        }

        public async Task<ServiceResult<int>> EndOrganizationSessionsAsync(Guid organizationId, SessionEndReason reason)
        {
            try
            {
                // 1. 조직의 모든 활성 세션 조회
                var orgSessions = await _sessionRepository.GetByOrganizationAsync(organizationId, activeOnly: true);

                if (!orgSessions.Any())
                {
                    _logger.LogInformation("No active sessions found for organization {OrganizationId}", organizationId);
                    return ServiceResult<int>.Success(0);
                }

                // 2. 일괄 종료 처리
                var sessionIds = orgSessions.Select(s => s.Id).ToList();
                var endedCount = await _sessionRepository.BulkEndSessionsAsync(sessionIds, reason);

                // 3. 캐시에서 제거
                foreach (var session in orgSessions)
                {
                    var cacheKey = $"session:{session.Id}";
                    _cache.Remove(cacheKey);

                    if (!string.IsNullOrEmpty(session.SessionToken))
                    {
                        var tokenCacheKey = $"session_token:{session.SessionToken}";
                        _cache.Remove(tokenCacheKey);
                    }
                }

                // 4. 활동 로그 기록
                var activityLogs = sessionIds.Select(id => new SessionActivityLog
                {
                    Id = Guid.NewGuid(),
                    SessionId = id,
                    ActivityType = SessionActivityType.Logout,
                    Details = $"Organization sessions terminated. Reason: {reason}",
                    OccurredAt = DateTime.UtcNow,
                    OrganizationId = organizationId
                }).ToList();

                foreach (var log in activityLogs)
                {
                    await _activityLogRepository.AddAsync(log);
                }

                _logger.LogInformation("Ended {Count} sessions for organization {OrganizationId}. Reason: {Reason}",
                    endedCount, organizationId, reason);

                return ServiceResult<int>.Success(endedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to end organization sessions for {OrganizationId}", organizationId);
                return ServiceResult<int>.Failure($"Failed to end organization sessions: {ex.Message}");
            }
        }

        public async Task<ServiceResult<int>> EndOtherDeviceSessionsAsync(Guid connectedId, Guid currentSessionId)
        {
            try
            {
                // 1. ConnectedId의 모든 활성 세션 조회
                var activeSessions = await _sessionRepository.GetActiveSessionsAsync(connectedId);

                if (!activeSessions.Any())
                {
                    return ServiceResult<int>.Success(0);
                }

                // 2. 현재 세션을 제외한 다른 세션들 필터링
                var otherSessions = activeSessions
                    .Where(s => s.Id != currentSessionId)
                    .ToList();

                if (!otherSessions.Any())
                {
                    _logger.LogInformation("No other device sessions found for ConnectedId {ConnectedId}", connectedId);
                    return ServiceResult<int>.Success(0);
                }

                // 3. 다른 디바이스 세션들 종료
                var sessionIds = otherSessions.Select(s => s.Id).ToList();
                var endedCount = await _sessionRepository.BulkEndSessionsAsync(
                    sessionIds,
                    SessionEndReason.Other); // 다른 디바이스에서 로그아웃됨

                // 4. 캐시에서 제거
                foreach (var session in otherSessions)
                {
                    var cacheKey = $"session:{session.Id}";
                    _cache.Remove(cacheKey);

                    if (!string.IsNullOrEmpty(session.SessionToken))
                    {
                        var tokenCacheKey = $"session_token:{session.SessionToken}";
                        _cache.Remove(tokenCacheKey);
                    }
                }

                // 5. 활동 로그 기록
                var activityLogs = sessionIds.Select(id => new SessionActivityLog
                {
                    Id = Guid.NewGuid(),
                    SessionId = id,
                    ActivityType = SessionActivityType.Logout,
                    Details = "Session ended due to logout from other device",
                    OccurredAt = DateTime.UtcNow
                }).ToList();

                foreach (var log in activityLogs)
                {
                    await _activityLogRepository.AddAsync(log);
                }

                _logger.LogInformation("Ended {Count} other device sessions for ConnectedId {ConnectedId}, keeping session {CurrentSessionId}",
                    endedCount, connectedId, currentSessionId);

                return ServiceResult<int>.Success(endedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to end other device sessions for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult<int>.Failure($"Failed to end other device sessions: {ex.Message}");
            }
        }
        #endregion

        public async Task<ServiceResult<CreateSessionResponse>> CreateSessionAsync(CreateSessionRequest request)
        {
            try
            {
                // 1. 요청 검증 - ConnectedId는 nullable이므로 체크 수정
                if (!request.ConnectedId.HasValue || request.ConnectedId.Value == Guid.Empty)
                {
                    // ConnectedId가 없으면 UserId 사용
                    if (request.UserId == Guid.Empty)
                    {
                        return ServiceResult<CreateSessionResponse>.Failure("UserId is required");
                    }
                }

                // 2. ConnectedId 존재 확인 (ConnectedId가 있는 경우에만)
                Guid effectiveConnectedId = request.ConnectedId ?? request.UserId;
                var connectedId = await _connectedIdRepository.GetByIdAsync(effectiveConnectedId);
                if (connectedId == null || connectedId.IsDeleted)
                {
                    return ServiceResult<CreateSessionResponse>.Failure("Invalid ConnectedId");
                }

                // 3. 기존 활성 세션 수 확인
                var activeSessions = await _sessionRepository.GetActiveSessionsAsync(effectiveConnectedId);
                var maxSessions = _configuration.GetValue<int>("Session:MaxPerUser", 5);

                if (activeSessions.Count() >= maxSessions)
                {
                    // 가장 오래된 세션 종료
                    var oldestSession = activeSessions.OrderBy(s => s.CreatedAt).First();
                    await EndSessionAsync(oldestSession.Id, SessionEndReason.Other);
                    _logger.LogInformation("Terminated oldest session {SessionId} due to max sessions limit", oldestSession.Id);
                }

                // 4. 새 세션 생성
                var session = new SessionEntity
                {
                    Id = Guid.NewGuid(),
                    SessionToken = GenerateSecureToken(),
                    UserId = request.UserId,
                    ConnectedId = effectiveConnectedId,
                    OrganizationId = request.OrganizationId,
                    ParentSessionId = null, // CreateSessionRequest에 SessionId 속성이 없음
                    SessionType = request.SessionType,
                    Level = request.Level,
                    Status = request.InitialStatus,
                    IpAddress = request.IpAddress,
                    UserAgent = request.UserAgent,
                    ExpiresAt = request.ExpiresAt,
                    LastActivityAt = DateTime.UtcNow,
                    RiskScore = request.InitialRiskScore,
                    GrpcEnabled = false, // CreateSessionRequest에 EnableGrpc가 없음, 기본값 사용
                    PubSubNotifications = false, // CreateSessionRequest에 EnablePubSubNotifications가 없음, 기본값 사용
                    CreatedAt = DateTime.UtcNow,
                    CreatedByConnectedId = effectiveConnectedId
                };

                // 5. 세션 저장
                await _sessionRepository.AddAsync(session);

                // 6. 캐시에 저장
                var cacheKey = $"session:{session.Id}";
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = session.ExpiresAt,
                    SlidingExpiration = TimeSpan.FromMinutes(5)
                };
                _cache.Set(cacheKey, session, cacheOptions);

                // 7. 활동 로그 기록
                var activityLog = new SessionActivityLog
                {
                    Id = Guid.NewGuid(),
                    SessionId = session.Id,
                    ActivityType = SessionActivityType.Login, // Created가 없으므로 Login 사용
                    Details = $"Session created from IP: {request.IpAddress}",
                    OccurredAt = DateTime.UtcNow
                };
                await _activityLogRepository.AddAsync(activityLog);

                // 8. SessionDto 매핑
                var sessionDto = new SessionDto
                {
                    Id = session.Id,
                    SessionToken = session.SessionToken,
                    UserId = session.UserId,
                    OrganizationId = session.OrganizationId,
                    ConnectedId = session.ConnectedId,
                    ParentSessionId = session.ParentSessionId,
                    SessionType = session.SessionType,
                    Level = session.Level,
                    Status = session.Status,
                    IpAddress = session.IpAddress,
                    UserAgent = session.UserAgent,
                    DeviceInfo = request.DeviceInfo != null ? request.DeviceInfo.ToString() : null, // object를 string으로 변환
                    ExpiresAt = session.ExpiresAt,
                    LastActivityAt = session.LastActivityAt,
                    RiskScore = session.RiskScore,
                    GrpcEnabled = session.GrpcEnabled,
                    PubSubNotifications = session.PubSubNotifications,
                    PermissionCacheEnabled = false, // CreateSessionRequest에 EnablePermissionCache가 없음, 기본값 사용
                    PageViews = 0,
                    ApiCalls = 0,
                    IsLocked = false,
                    CreatedAt = session.CreatedAt,
                    CreatedByConnectedId = session.CreatedByConnectedId,
                    UserName = connectedId.User?.Email,
                    OrganizationName = connectedId.Organization?.Name
                };

                // 9. 응답 생성
                var response = new CreateSessionResponse
                {
                    IsSuccess = true,
                    SessionId = session.Id,
                    SessionDto = sessionDto,
                    SessionToken = session.SessionToken,
                    SessionIdentifier = $"sid_{session.Id}",
                    SessionType = session.SessionType,
                    ExpiresAt = session.ExpiresAt,
                    RequiresTwoFactor = false,
                    IsTrustedDevice = false // CreateSessionRequest에 MarkAsTrustedDevice가 없음, 기본값 사용
                };

                _logger.LogInformation("Session {SessionId} created for UserId {UserId}",
                    session.Id, request.UserId);

                return ServiceResult<CreateSessionResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create session for UserId {UserId}", request.UserId);
                return ServiceResult<CreateSessionResponse>.Failure($"Failed to create session: {ex.Message}");
            }
        }

        #region 세션 조회
        public async Task<ServiceResult<SessionDetailResponse>> GetSessionAsync(Guid sessionId)
        {
            try
            {
                // 1. 캐시에서 먼저 조회
                var cacheKey = $"{SESSION_CACHE_PREFIX}{sessionId}";
                if (_cache.TryGetValue<SessionEntity>(cacheKey, out var cachedSession) && cachedSession != null)
                {
                    return ServiceResult<SessionDetailResponse>.Success(MapToDetailResponse(cachedSession));
                }

                // 2. DB에서 조회 (관련 데이터 포함)
                var session = await _sessionRepository.GetWithRelatedDataAsync(
                    sessionId,
                    includeUser: true,
                    includeOrganization: true,
                    includeConnectedId: true,
                    includeParentSession: true,
                    includeChildSessions: false);

                if (session == null)
                {
                    return ServiceResult<SessionDetailResponse>.Failure($"Session {sessionId} not found");
                }

                // 3. 캐시에 저장
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = session.ExpiresAt,
                    SlidingExpiration = TimeSpan.FromMinutes(5)
                };
                _cache.Set(cacheKey, session, cacheOptions);

                // 4. 응답 매핑
                var response = MapToDetailResponse(session);
                return ServiceResult<SessionDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get session {SessionId}", sessionId);
                return ServiceResult<SessionDetailResponse>.Failure($"Failed to get session: {ex.Message}");
            }
        }

        public async Task<ServiceResult<SessionDetailResponse>> GetSessionByTokenAsync(string sessionToken)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sessionToken))
                {
                    return ServiceResult<SessionDetailResponse>.Failure("Session token is required");
                }

                // 1. 캐시에서 토큰으로 세션 ID 조회
                var tokenCacheKey = $"session_token:{sessionToken}";
                SessionEntity? session = null;

                if (_cache.TryGetValue<Guid>(tokenCacheKey, out var cachedSessionId))
                {
                    var sessionCacheKey = $"session:{cachedSessionId}";
                    if (_cache.TryGetValue<SessionEntity>(sessionCacheKey, out var cachedSession) && cachedSession != null)
                    {
                        return ServiceResult<SessionDetailResponse>.Success(MapToDetailResponse(cachedSession));
                    }
                }

                // 2. DB에서 토큰으로 세션 조회
                session = await _sessionRepository.GetByTokenAsync(sessionToken);
                if (session == null)
                {
                    return ServiceResult<SessionDetailResponse>.Failure("Session not found");
                }

                // 3. 관련 데이터 포함하여 다시 조회
                session = await _sessionRepository.GetWithRelatedDataAsync(
                    session.Id,
                    includeUser: true,
                    includeOrganization: true,
                    includeConnectedId: true,
                    includeParentSession: false,
                    includeChildSessions: false);

                if (session == null)
                {
                    return ServiceResult<SessionDetailResponse>.Failure("Session not found");
                }

                // 4. 캐시에 저장
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = session.ExpiresAt,
                    SlidingExpiration = TimeSpan.FromMinutes(5)
                };
                _cache.Set($"session:{session.Id}", session, cacheOptions);
                _cache.Set(tokenCacheKey, session.Id, cacheOptions);

                // 5. 응답 매핑
                var response = MapToDetailResponse(session);
                return ServiceResult<SessionDetailResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get session by token");
                return ServiceResult<SessionDetailResponse>.Failure($"Failed to get session: {ex.Message}");
            }
        }

        public async Task<ServiceResult<SessionListResponse>> GetSessionsAsync(Guid connectedId, SearchSessionsRequest request)
        {
            try
            {
                // 1. ConnectedId 검증
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null || connectedIdEntity.IsDeleted)
                {
                    return ServiceResult<SessionListResponse>.Failure("Invalid ConnectedId");
                }

                // 2. 요청 파라미터 검증 및 기본값 설정
                if (request == null)
                {
                    request = new SearchSessionsRequest
                    {
                        PageNumber = 1,
                        PageSize = 10,
                        OrganizationId = connectedIdEntity.OrganizationId
                    };
                }

                // 3. 권한 확인 - 자신의 ConnectedId가 아니면 Admin 권한 필요
                if (request.ConnectedId.HasValue && request.ConnectedId != connectedId)
                {
                    // TODO: Admin 권한 확인 로직 필요
                    _logger.LogWarning("User {ConnectedId} attempted to access sessions of another ConnectedId", connectedId);
                }

                // 4. 쿼리 빌드
                var query = _sessionRepository.GetQueryable(includeDeleted: false);

                // ConnectedId 필터
                if (request.ConnectedId.HasValue)
                {
                    query = query.Where(s => s.ConnectedId == request.ConnectedId.Value);
                }
                else
                {
                    // ConnectedId가 지정되지 않으면 현재 ConnectedId의 세션만
                    query = query.Where(s => s.ConnectedId == connectedId);
                }

                // OrganizationId 필터
                if (request.OrganizationId != Guid.Empty)
                {
                    query = query.Where(s => s.OrganizationId == request.OrganizationId);
                }

                // UserId 필터
                if (request.UserId.HasValue)
                {
                    query = query.Where(s => s.UserId == request.UserId.Value);
                }

                // SessionType 필터
                if (request.SessionTypes != null && request.SessionTypes.Any())
                {
                    query = query.Where(s => request.SessionTypes.Contains(s.SessionType));
                }

                // Status 필터
                if (request.Statuses != null && request.Statuses.Any())
                {
                    query = query.Where(s => request.Statuses.Contains(s.Status));
                }
                else if (!request.IncludeTerminated)
                {
                    // 기본값: Active 세션만
                    query = query.Where(s => s.Status == SessionStatus.Active);
                }

                // IP 주소 필터
                if (!string.IsNullOrWhiteSpace(request.IpAddress))
                {
                    query = query.Where(s => s.IpAddress != null && s.IpAddress.Contains(request.IpAddress));
                }

                // 디바이스 타입 필터
                if (request.DeviceTypes != null && request.DeviceTypes.Any())
                {
                    var deviceTypeStrings = request.DeviceTypes.Select(d => d.ToString()).ToList();
                    query = query.Where(s => s.DeviceInfo != null && deviceTypeStrings.Any(dt => s.DeviceInfo.Contains(dt)));
                }

                // 브라우저 필터
                if (request.BrowserTypes != null && request.BrowserTypes.Any())
                {
                    var browserStrings = request.BrowserTypes.Select(b => b.ToString()).ToList();
                    query = query.Where(s => s.Browser != null && browserStrings.Any(b => s.Browser.Contains(b)));
                }

                // OS 필터
                if (request.OSTypes != null && request.OSTypes.Any())
                {
                    var osStrings = request.OSTypes.Select(o => o.ToString()).ToList();
                    query = query.Where(s => s.OperatingSystem != null && osStrings.Any(os => s.OperatingSystem.Contains(os)));
                }

                // 위치 필터
                if (!string.IsNullOrWhiteSpace(request.Location))
                {
                    query = query.Where(s => s.Location != null && s.Location.Contains(request.Location));
                }

                // 날짜 범위 필터
                if (request.CreatedAfter.HasValue)
                {
                    query = query.Where(s => s.CreatedAt >= request.CreatedAfter.Value);
                }

                if (request.CreatedBefore.HasValue)
                {
                    query = query.Where(s => s.CreatedAt <= request.CreatedBefore.Value);
                }

                if (request.LastActiveAfter.HasValue)
                {
                    query = query.Where(s => s.LastActivityAt >= request.LastActiveAfter.Value);
                }

                if (request.LastActiveBefore.HasValue)
                {
                    query = query.Where(s => s.LastActivityAt <= request.LastActiveBefore.Value);
                }

                if (request.ExpiringBefore.HasValue)
                {
                    query = query.Where(s => s.ExpiresAt <= request.ExpiringBefore.Value);
                }

                // 위험도 점수 필터
                if (request.MinRiskScore.HasValue)
                {
                    query = query.Where(s => s.RiskScore >= request.MinRiskScore.Value);
                }

                if (request.MaxRiskScore.HasValue)
                {
                    query = query.Where(s => s.RiskScore <= request.MaxRiskScore.Value);
                }

                // 잠긴 세션 필터
                if (request.LockedOnly.HasValue)
                {
                    query = request.LockedOnly.Value
                        ? query.Where(s => s.IsLocked)
                        : query.Where(s => !s.IsLocked);
                }

                // 유휴 시간 필터
                if (request.IdleMinutesThreshold.HasValue)
                {
                    var idleThreshold = DateTime.UtcNow.AddMinutes(-request.IdleMinutesThreshold.Value);
                    query = query.Where(s => s.LastActivityAt <= idleThreshold);
                }

                // 현재 세션 제외 옵션
                if (!request.IncludeCurrentSession && request.CurrentSessionId.HasValue)
                {
                    query = query.Where(s => s.Id != request.CurrentSessionId.Value);
                }

                // 5. 전체 개수 조회 (페이징 전)
                var totalCount = await query.CountAsync();

                // CountOnly 옵션 처리
                if (request.CountOnly)
                {
                    return ServiceResult<SessionListResponse>.Success(new SessionListResponse
                    {
                        TotalCount = totalCount,
                        PageNumber = 1,
                        PageSize = 1,
                        Items = new List<SessionResponse>()
                    });
                }

                // 6. 정렬
                query = request.SortBy?.ToLower() switch
                {
                    "lastactivityat" => request.SortDirection == "desc"
                        ? query.OrderByDescending(s => s.LastActivityAt)
                        : query.OrderBy(s => s.LastActivityAt),
                    "expiresat" => request.SortDirection == "desc"
                        ? query.OrderByDescending(s => s.ExpiresAt)
                        : query.OrderBy(s => s.ExpiresAt),
                    "riskscore" => request.SortDirection == "desc"
                        ? query.OrderByDescending(s => s.RiskScore)
                        : query.OrderBy(s => s.RiskScore),
                    _ => request.SortDirection == "desc"
                        ? query.OrderByDescending(s => s.CreatedAt)
                        : query.OrderBy(s => s.CreatedAt)
                };

                // 7. 페이징
                var pagedSessions = await query
                    .Skip((request.PageNumber - 1) * request.PageSize)
                    .Take(request.PageSize)
                    .ToListAsync();

                // 8. 통계 정보 생성
                var statistics = new AuthHive.Core.Models.Auth.Session.Responses.SessionStatistics
                {
                    TotalSessions = totalCount,
                    ActiveSessions = pagedSessions.Count(s => s.Status == SessionStatus.Active),
                    ExpiredSessions = pagedSessions.Count(s => s.Status == SessionStatus.Expired),
                    LockedSessions = pagedSessions.Count(s => s.IsLocked),
                    GrpcEnabledSessions = pagedSessions.Count(s => s.GrpcEnabled),
                    PubSubEnabledSessions = pagedSessions.Count(s => s.PubSubNotifications),
                    AverageRiskScore = pagedSessions.Any() ? pagedSessions.Average(s => s.RiskScore) : 0,
                    TotalPageViews = pagedSessions.Sum(s => s.PageViews),
                    TotalApiCalls = pagedSessions.Sum(s => s.ApiCalls)
                };

                // 9. 조직별 분포 (GroupBy 처리)
                // 9. 조직별 분포 (GroupBy 처리)
                var organizationDistribution = new OrganizationDistribution();
                if (request.GroupBy?.ToLower() == "organization" && pagedSessions.Any())
                {
                    var groupedByOrg = pagedSessions
                        .Where(s => s.OrganizationId.HasValue)
                        .GroupBy(s => s.OrganizationId!.Value)
                        .Select(g => new
                        {
                            OrganizationId = g.Key,
                            Count = g.Count(),
                            ActiveCount = g.Count(s => s.Status == SessionStatus.Active),
                            AvgRiskScore = g.Average(s => s.RiskScore)
                        })
                        .ToList();

                    organizationDistribution.SessionsByOrganization = groupedByOrg
                        .ToDictionary(g => g.OrganizationId.ToString(), g => g.Count);

                    organizationDistribution.ActiveSessionsByOrganization = groupedByOrg
                        .ToDictionary(g => g.OrganizationId.ToString(), g => g.ActiveCount);

                    var mostActive = groupedByOrg.OrderByDescending(g => g.Count).FirstOrDefault();
                    if (mostActive != null)
                    {
                        organizationDistribution.MostActiveSessions = new TopOrganization
                        {
                            OrganizationId = mostActive.OrganizationId,
                            OrganizationName = "Unknown", // TODO: Organization 정보 조회 필요
                            SessionCount = mostActive.Count,
                            AverageRiskScore = mostActive.AvgRiskScore
                        };
                    }

                    var highestRisk = groupedByOrg.OrderByDescending(g => g.AvgRiskScore).FirstOrDefault();
                    if (highestRisk != null && highestRisk.AvgRiskScore > 0)
                    {
                        organizationDistribution.HighestRiskOrganization = new TopOrganization
                        {
                            OrganizationId = highestRisk.OrganizationId,
                            OrganizationName = "Unknown", // TODO: Organization 정보 조회 필요
                            SessionCount = highestRisk.Count,
                            AverageRiskScore = highestRisk.AvgRiskScore
                        };
                    }
                }
                // 10. SessionResponse 매핑
                var sessionResponses = pagedSessions.Select(s => new SessionResponse
                {
                    Id = s.Id,
                    ConnectedId = s.ConnectedId ?? Guid.Empty,
                    OrganizationId = s.OrganizationId ?? Guid.Empty,
                    OrganizationName = s.Organization?.Name ?? string.Empty,
                    SessionType = s.SessionType,
                    Status = s.Status,
                    IpAddress = s.IpAddress,
                    Browser = s.Browser,
                    OperatingSystem = s.OperatingSystem,
                    Location = s.Location,
                    ExpiresAt = s.ExpiresAt,
                    LastActivityAt = s.LastActivityAt,
                    RiskScore = s.RiskScore,
                    PageViews = s.PageViews,
                    ApiCalls = s.ApiCalls,
                    EnableGrpc = s.GrpcEnabled,
                    EnablePubSubNotifications = s.PubSubNotifications,
                    EnablePermissionCache = s.PermissionCacheEnabled,
                    LockReason = s.LockReason,
                    CreatedAt = s.CreatedAt
                }).ToList();

                // 11. 응답 생성
                var response = new SessionListResponse
                {
                    Items = sessionResponses,
                    TotalCount = totalCount,
                    PageNumber = request.PageNumber,
                    PageSize = request.PageSize,
                    Statistics = statistics,
                    OrganizationDistribution = organizationDistribution
                };

                _logger.LogInformation(
                    "Retrieved {Count} sessions for ConnectedId {ConnectedId} (Page {Page}/{TotalPages})",
                    sessionResponses.Count, connectedId, request.PageNumber, response.TotalPages);

                return ServiceResult<SessionListResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get sessions for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult<SessionListResponse>.Failure($"Failed to get sessions: {ex.Message}");
            }
        }

        public async Task<ServiceResult<IEnumerable<SessionResponse>>> GetActiveSessionsAsync(Guid connectedId)
        {
            try
            {
                // 1. ConnectedId 검증
                var connectedIdEntity = await _connectedIdRepository.GetByIdAsync(connectedId);
                if (connectedIdEntity == null || connectedIdEntity.IsDeleted)
                {
                    return ServiceResult<IEnumerable<SessionResponse>>.Failure("Invalid ConnectedId");
                }

                // 2. 활성 세션 조회
                var activeSessions = await _sessionRepository.GetActiveSessionsAsync(connectedId);

                if (!activeSessions.Any())
                {
                    _logger.LogInformation("No active sessions found for ConnectedId {ConnectedId}", connectedId);
                    return ServiceResult<IEnumerable<SessionResponse>>.Success(new List<SessionResponse>());
                }

                // 3. SessionResponse로 매핑
                var sessionResponses = activeSessions.Select(session => MapToSessionResponse(session)).ToList();

                _logger.LogInformation("Found {Count} active sessions for ConnectedId {ConnectedId}",
                    sessionResponses.Count, connectedId);

                return ServiceResult<IEnumerable<SessionResponse>>.Success(sessionResponses);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get active sessions for ConnectedId {ConnectedId}", connectedId);
                return ServiceResult<IEnumerable<SessionResponse>>.Failure($"Failed to get active sessions: {ex.Message}");
            }
        }

        /// <summary>
        /// SessionEntity를 SessionResponse로 매핑
        /// </summary>
        private SessionResponse MapToSessionResponse(SessionEntity session)
        {
            return new SessionResponse
            {
                Id = session.Id,
                ConnectedId = session.ConnectedId ?? Guid.Empty,
                OrganizationId = session.OrganizationId ?? Guid.Empty,
                OrganizationName = session.Organization?.Name ?? string.Empty,
                SessionType = session.SessionType,
                Status = session.Status,
                IpAddress = session.IpAddress,
                Browser = session.Browser,
                OperatingSystem = session.OperatingSystem,
                Location = session.Location,
                ExpiresAt = session.ExpiresAt,
                LastActivityAt = session.LastActivityAt,
                RiskScore = session.RiskScore,
                PageViews = session.PageViews,
                ApiCalls = session.ApiCalls,
                EnableGrpc = session.GrpcEnabled,
                EnablePubSubNotifications = session.PubSubNotifications,
                EnablePermissionCache = session.PermissionCacheEnabled,
                LockReason = session.LockReason,
                CreatedAt = session.CreatedAt
            };
        }

        public async Task<ServiceResult<IEnumerable<SessionResponse>>> GetOrganizationActiveSessionsAsync(Guid organizationId, bool includeInactive = false)
        {
            try
            {
                // 1. 조직 존재 여부 확인 (Organization 검증은 보통 Auth 서비스에서 수행)
                // TODO: IOrganizationRepository가 있다면 여기서 확인
                // 일단 조직 ID가 비어있지 않은지만 확인
                if (organizationId == Guid.Empty)
                {
                    return ServiceResult<IEnumerable<SessionResponse>>.Failure("Invalid OrganizationId");
                }

                // 2. 조직의 세션 조회
                var sessions = await _sessionRepository.GetByOrganizationAsync(
                    organizationId,
                    activeOnly: !includeInactive);

                if (!sessions.Any())
                {
                    _logger.LogInformation("No sessions found for Organization {OrganizationId}", organizationId);
                    return ServiceResult<IEnumerable<SessionResponse>>.Success(new List<SessionResponse>());
                }

                // 3. 추가 필터링 (필요시)
                IEnumerable<SessionEntity> filteredSessions = sessions;

                if (!includeInactive)
                {
                    // 만료된 세션도 제외 (Status는 Active지만 시간이 지난 경우)
                    filteredSessions = sessions.Where(s =>
                        s.Status == SessionStatus.Active &&
                        s.ExpiresAt > DateTime.UtcNow);
                }

                // 4. SessionResponse로 매핑
                var sessionResponses = filteredSessions
                    .OrderByDescending(s => s.LastActivityAt)
                    .Select(session => MapToSessionResponse(session))
                    .ToList();

                // 5. 캐시 업데이트 (선택적)
                if (sessionResponses.Count > 0 && sessionResponses.Count <= 100) // 적정 크기일 때만 캐싱
                {
                    var cacheKey = $"org_sessions:{organizationId}:{includeInactive}";
                    var cacheOptions = new MemoryCacheEntryOptions
                    {
                        SlidingExpiration = TimeSpan.FromMinutes(2) // 짧은 시간 캐싱
                    };
                    _cache.Set(cacheKey, sessionResponses, cacheOptions);
                }

                _logger.LogInformation(
                    "Found {Count} {Status} sessions for Organization {OrganizationId}",
                    sessionResponses.Count,
                    includeInactive ? "all" : "active",
                    organizationId);

                return ServiceResult<IEnumerable<SessionResponse>>.Success(sessionResponses);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get organization sessions for {OrganizationId}", organizationId);
                return ServiceResult<IEnumerable<SessionResponse>>.Failure(
                    $"Failed to get organization sessions: {ex.Message}");
            }
        }
        #endregion
        public async Task<ServiceResult<IEnumerable<SessionResponse>>> GetApplicationSessionsAsync(Guid applicationId, bool activeOnly = true)
        {
            try
            {
                if (applicationId == Guid.Empty)
                {
                    return ServiceResult<IEnumerable<SessionResponse>>.Failure("Invalid ApplicationId");
                }

                // Application별 세션 조회
                var sessions = await _sessionRepository.GetByApplicationAsync(applicationId, activeOnly);

                if (!sessions.Any())
                {
                    _logger.LogInformation("No sessions found for Application {ApplicationId}", applicationId);
                    return ServiceResult<IEnumerable<SessionResponse>>.Success(new List<SessionResponse>());
                }

                // 추가 필터링 (activeOnly가 true면 만료된 세션도 제외)
                IEnumerable<SessionEntity> filteredSessions = sessions;
                if (activeOnly)
                {
                    filteredSessions = sessions.Where(s =>
                        s.Status == SessionStatus.Active &&
                        s.ExpiresAt > DateTime.UtcNow);
                }

                // SessionResponse로 매핑
                var sessionResponses = filteredSessions
                    .OrderByDescending(s => s.LastActivityAt)
                    .Select(session => MapToSessionResponse(session))
                    .ToList();

                _logger.LogInformation(
                    "Found {Count} {Status} sessions for Application {ApplicationId}",
                    sessionResponses.Count,
                    activeOnly ? "active" : "all",
                    applicationId);

                return ServiceResult<IEnumerable<SessionResponse>>.Success(sessionResponses);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get application sessions for {ApplicationId}", applicationId);
                return ServiceResult<IEnumerable<SessionResponse>>.Failure(
                    $"Failed to get application sessions: {ex.Message}");
            }
        }

        #region 세션 관리
        public async Task<ServiceResult<SessionResponse>> RefreshSessionAsync(Guid sessionId)
        {
            try
            {
                // 1. 세션 조회
                var session = await _sessionRepository.GetByIdAsync(sessionId);
                if (session == null)
                {
                    return ServiceResult<SessionResponse>.Failure($"Session {sessionId} not found");
                }

                // 2. 세션 상태 확인
                if (session.Status != SessionStatus.Active)
                {
                    return ServiceResult<SessionResponse>.Failure($"Cannot refresh inactive session. Current status: {session.Status}");
                }

                // 3. 이미 만료된 세션인지 확인
                if (session.ExpiresAt < DateTime.UtcNow)
                {
                    // 만료된 세션은 상태 업데이트 후 실패 반환
                    session.Status = SessionStatus.Expired;
                    await _sessionRepository.UpdateAsync(session);
                    return ServiceResult<SessionResponse>.Failure("Session has already expired");
                }

                // 4. 세션 갱신
                var now = DateTime.UtcNow;
                var sessionDuration = _configuration.GetValue<int>(
                    $"Session:{session.SessionType}TimeoutMinutes",
                    30); // 기본값 30분

                session.ExpiresAt = now.AddMinutes(sessionDuration);
                session.LastActivityAt = now;
                session.UpdatedAt = now;

                await _sessionRepository.UpdateAsync(session);

                // 5. 캐시 업데이트
                var cacheKey = $"{SESSION_CACHE_PREFIX}{sessionId}";
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = session.ExpiresAt,
                    SlidingExpiration = TimeSpan.FromMinutes(5)
                };
                _cache.Set(cacheKey, session, cacheOptions);

                // 6. 활동 로그 기록
                var activityLog = new SessionActivityLog
                {
                    Id = Guid.NewGuid(),
                    SessionId = sessionId,
                    ActivityType = SessionActivityType.SessionRefresh,
                    Details = $"Session refreshed. New expiry: {session.ExpiresAt:yyyy-MM-dd HH:mm:ss} UTC",
                    OccurredAt = now
                };
                await _activityLogRepository.AddAsync(activityLog);

                // 7. Response 생성
                var response = MapToSessionResponse(session);

                _logger.LogInformation("Session {SessionId} refreshed. New expiry: {ExpiresAt}",
                    sessionId, session.ExpiresAt);

                return ServiceResult<SessionResponse>.Success(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to refresh session {SessionId}", sessionId);
                return ServiceResult<SessionResponse>.Failure($"Failed to refresh session: {ex.Message}");
            }
        }


        /// <summary>
        /// 의심스러운 활동 체크 (Helper)
        /// </summary>
        private async Task CheckSuspiciousActivityAsync(Guid sessionId, SessionActivityType activityType, string? details)
        {
            // 최근 5분간 활동 조회
            var recentLogs = await _activityLogRepository.GetBySessionIdAsync(
                sessionId,
                DateTime.UtcNow.AddMinutes(-5));

            // 짧은 시간 내 과도한 권한 변경 시도
            if (activityType == SessionActivityType.PermissionChange)
            {
                var permissionChanges = recentLogs.Count(l =>
                    l.ActivityType == SessionActivityType.PermissionChange);

                if (permissionChanges > 5)
                {
                    _logger.LogWarning(
                        "Suspicious activity detected: Multiple permission changes in session {SessionId}",
                        sessionId);
                    // 알림 발송 또는 세션 위험도 점수 증가 로직
                }
            }
        }

        public async Task<ServiceResult> UpdateActivityAsync(Guid sessionId, SessionActivityType activityType, string? details = null)
        {
            try
            {
                // 1. 세션 조회
                var session = await _sessionRepository.GetByIdAsync(sessionId);
                if (session == null)
                {
                    return ServiceResult.Failure($"Session {sessionId} not found");
                }

                // 2. 세션 상태 확인
                if (session.Status != SessionStatus.Active)
                {
                    return ServiceResult.Failure($"Cannot update activity for inactive session. Status: {session.Status}");
                }

                // 3. 세션 만료 확인
                if (session.ExpiresAt < DateTime.UtcNow)
                {
                    session.Status = SessionStatus.Expired;
                    await _sessionRepository.UpdateAsync(session);
                    return ServiceResult.Failure("Session has expired");
                }

                var now = DateTime.UtcNow;

                // 4. 세션의 마지막 활동 시간 업데이트
                session.LastActivityAt = now;

                // 5. 활동 타입별 메트릭 업데이트
                switch (activityType)
                {
                    case SessionActivityType.PageView:
                        session.PageViews++;
                        break;
                    case SessionActivityType.ApiCall:
                        session.ApiCalls++;
                        break;
                    case SessionActivityType.Login:
                    case SessionActivityType.Logout:
                    case SessionActivityType.SessionRefresh:
                        // 이런 활동들은 카운터를 증가시키지 않음
                        break;
                    default:
                        // 기타 활동은 ApiCalls로 카운트
                        session.ApiCalls++;
                        break;
                }

                await _sessionRepository.UpdateAsync(session);

                // 6. 활동 로그 생성
                var activityLog = new SessionActivityLog
                {
                    Id = Guid.NewGuid(),
                    SessionId = sessionId,
                    UserId = session.UserId,
                    ConnectedId = session.ConnectedId ?? Guid.Empty,
                    OrganizationId = session.OrganizationId ?? Guid.Empty,
                    ApplicationId = session.ApplicationId,
                    ActivityType = activityType,
                    Details = details ?? $"Activity: {activityType}",
                    IpAddress = session.IpAddress,
                    UserAgent = session.UserAgent,
                    OccurredAt = now,
                    CreatedAt = now
                };

                await _activityLogRepository.AddAsync(activityLog);

                // 7. 캐시 업데이트
                var cacheKey = $"{SESSION_CACHE_PREFIX}{sessionId}";
                if (_cache.TryGetValue<SessionEntity>(cacheKey, out _))
                {
                    var cacheOptions = new MemoryCacheEntryOptions
                    {
                        AbsoluteExpiration = session.ExpiresAt,
                        SlidingExpiration = TimeSpan.FromMinutes(5)
                    };
                    _cache.Set(cacheKey, session, cacheOptions);
                }

                // 8. 의심스러운 활동 감지 (선택적)
                if (activityType == SessionActivityType.PermissionChange ||
                    activityType == SessionActivityType.SecurityChange)
                {
                    await CheckSuspiciousActivityAsync(sessionId, activityType, details);
                }

                _logger.LogDebug("Activity {ActivityType} recorded for session {SessionId}",
                    activityType, sessionId);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update activity for session {SessionId}", sessionId);
                return ServiceResult.Failure($"Failed to update activity: {ex.Message}");
            }
        }

        /// <summary>
        /// UpdateMetadataAsync는 세션의 메타데이터(디바이스 정보, 위치, 브라우저 등)를 업데이트하는 메서드입니다.
        /// </summary>
        /// <param name="sessionId"></param>
        /// <param name="request"></param>
        /// <returns></returns>
        public async Task<ServiceResult> UpdateMetadataAsync(Guid sessionId, UpdateSessionRequest request)
        {
            try
            {
                var session = await _sessionRepository.GetByIdAsync(sessionId);
                if (session == null)
                {
                    return ServiceResult.Failure($"Session {sessionId} not found");
                }

                if (session.Status != SessionStatus.Active)
                {
                    return ServiceResult.Failure($"Cannot update metadata for inactive session. Status: {session.Status}");
                }

                var isUpdated = false;

                // UpdateSessionRequest에 있는 필드들만 업데이트
                if (request.Status.HasValue)
                {
                    session.Status = request.Status.Value;
                    isUpdated = true;
                }

                if (request.IsLocked.HasValue)
                {
                    session.IsLocked = request.IsLocked.Value;
                    session.LockedAt = request.IsLocked.Value ? DateTime.UtcNow : null;
                    isUpdated = true;
                }

                if (!string.IsNullOrWhiteSpace(request.LockReason))
                {
                    session.LockReason = request.LockReason;
                    isUpdated = true;
                }

                if (request.RiskScore.HasValue)
                {
                    session.RiskScore = request.RiskScore.Value;
                    isUpdated = true;
                }

                if (request.GrpcEnabled.HasValue)
                {
                    session.GrpcEnabled = request.GrpcEnabled.Value;
                    isUpdated = true;
                }

                if (request.PubSubNotifications.HasValue)
                {
                    session.PubSubNotifications = request.PubSubNotifications.Value;
                    isUpdated = true;
                }

                if (request.PermissionCacheEnabled.HasValue)
                {
                    session.PermissionCacheEnabled = request.PermissionCacheEnabled.Value;
                    isUpdated = true;
                }

                if (request.ExtendSessionMinutes.HasValue)
                {
                    session.ExpiresAt = session.ExpiresAt.AddMinutes(request.ExtendSessionMinutes.Value);
                    isUpdated = true;
                }

                if (!isUpdated)
                {
                    return ServiceResult.Success();
                }

                session.UpdatedAt = DateTime.UtcNow;
                session.LastActivityAt = DateTime.UtcNow;

                await _sessionRepository.UpdateAsync(session);

                // 캐시 업데이트
                var cacheKey = $"{SESSION_CACHE_PREFIX}{sessionId}";
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = session.ExpiresAt,
                    SlidingExpiration = TimeSpan.FromMinutes(5)
                };
                _cache.Set(cacheKey, session, cacheOptions);

                // 활동 로그 기록
                if (!string.IsNullOrWhiteSpace(request.UpdateReason))
                {
                    var activityLog = new SessionActivityLog
                    {
                        Id = Guid.NewGuid(),
                        SessionId = sessionId,
                        ActivityType = SessionActivityType.DataAccess,
                        Details = request.UpdateReason,
                        OccurredAt = DateTime.UtcNow
                    };
                    await _activityLogRepository.AddAsync(activityLog);
                }

                _logger.LogInformation("Session {SessionId} metadata updated", sessionId);

                return ServiceResult.Success();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update metadata for session {SessionId}", sessionId);
                return ServiceResult.Failure($"Failed to update metadata: {ex.Message}");
            }
        }
        public async Task<ServiceResult> ExtendSessionAsync(Guid sessionId, TimeSpan extension)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> UpdateDeviceInfoAsync(Guid sessionId, DeviceInfo deviceInfo)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }
        #endregion

        #region 세션 보안
        public async Task<ServiceResult> UpdateRiskScoreAsync(Guid sessionId, int riskScore, string reason)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> LockSessionAsync(Guid sessionId, string reason, TimeSpan? lockDuration = null)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> UnlockSessionAsync(Guid sessionId, string unlockedBy)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<IEnumerable<SessionResponse>>> DetectSuspiciousSessionsAsync(Guid organizationId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<IEnumerable<SessionResponse>>.Success(new List<SessionResponse>()));
        }

        public async Task<ServiceResult<SessionSecurityCheck>> CheckSessionSecurityAsync(Guid sessionId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionSecurityCheck>.Success(new SessionSecurityCheck()));
        }

        public async Task<ServiceResult<bool>> DetectIpChangeAsync(Guid sessionId, string newIpAddress)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<bool>.Success(false));
        }

        public async Task<ServiceResult<AnomalyDetectionResult>> DetectAnomaliesAsync(Guid sessionId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<AnomalyDetectionResult>.Success(new AnomalyDetectionResult()));
        }
        #endregion

        #region 실시간 통신
        public async Task<ServiceResult> EnableWebSocketAsync(Guid sessionId, string connectionId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> EnableGrpcStreamAsync(Guid sessionId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> SubscribeToPubSubAsync(Guid sessionId, List<string> topics)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> PublishEventAsync(Guid sessionId, string eventType, object eventData)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<ConnectionStatus>> GetConnectionStatusAsync(Guid sessionId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<ConnectionStatus>.Success(new ConnectionStatus()));
        }
        #endregion

        public async Task<ServiceResult<IEnumerable<SessionResponse>>> GetUserActiveSessionsAsync(
            Guid userId,
            Guid? organizationId = null)
        {
            try
            {
                // Repository 패턴 사용 (context 직접 접근 대신)
                var sessions = await _sessionRepository.GetByUserIdAsync(userId);

                // 활성 세션만 필터링
                sessions = sessions.Where(s => s.Status == SessionStatus.Active);

                // organizationId가 지정된 경우 추가 필터링
                if (organizationId.HasValue)
                {
                    sessions = sessions.Where(s => s.OrganizationId == organizationId);
                }

                // 최근 활동 순으로 정렬
                sessions = sessions.OrderByDescending(s => s.LastActivityAt);

                // Entity를 Response DTO로 매핑
                var responses = sessions.Select(s => new SessionResponse
                {
                    Id = s.Id,
                    UserId = s.UserId,
                    ConnectedId = s.ConnectedId ?? Guid.Empty,
                    OrganizationId = s.OrganizationId ?? Guid.Empty,
                    OrganizationName = s.Organization?.Name ?? string.Empty,
                    SessionType = s.SessionType,
                    Status = s.Status,
                    IpAddress = s.IpAddress,
                    Browser = s.Browser,
                    OperatingSystem = s.OperatingSystem,
                    Location = s.Location,
                    ExpiresAt = s.ExpiresAt,
                    LastActivityAt = s.LastActivityAt,
                    RiskScore = s.RiskScore,
                    PageViews = s.PageViews,
                    ApiCalls = s.ApiCalls,
                    EnableGrpc = s.GrpcEnabled,
                    EnablePubSubNotifications = s.PubSubNotifications,
                    EnablePermissionCache = s.PermissionCacheEnabled,
                    LockReason = s.LockReason,
                    CreatedAt = s.CreatedAt
                }).ToList();

                return ServiceResult<IEnumerable<SessionResponse>>.Success(responses);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user active sessions for UserId: {UserId}", userId);
                return ServiceResult<IEnumerable<SessionResponse>>.Failure("Failed to get user active sessions");
            }
        }


        #region 세션 통계 및 분석
        public async Task<ServiceResult<SessionStatisticsData>> GetStatisticsAsync(Guid organizationId, DateTime? from = null, DateTime? to = null)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionStatisticsData>.Success(new SessionStatisticsData()));
        }

        public async Task<ServiceResult<SessionUsagePatternData>> AnalyzeUsagePatternsAsync(Guid connectedId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionUsagePatternData>.Success(new SessionUsagePatternData()));
        }

        public async Task<ServiceResult<int>> GetConcurrentSessionCountAsync(Guid organizationId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<int>.Success(0));
        }

        public async Task<ServiceResult<SessionDashboardView>> GetDashboardAsync(Guid organizationId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionDashboardView>.Success(new SessionDashboardView()));
        }

        public async Task<ServiceResult<SessionActivityView>> GetActivityHeatmapAsync(Guid organizationId, DateTime? from = null, DateTime? to = null)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionActivityView>.Success(new SessionActivityView()));
        }
        #endregion

        #region 세션 정리 및 유지보수
        public async Task<ServiceResult<int>> CleanupExpiredSessionsAsync(Guid? organizationId = null)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<int>.Success(0));
        }

        public async Task<ServiceResult<int>> CleanupInactiveSessionsAsync(Guid? organizationId = null, TimeSpan? inactiveDuration = null)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<int>.Success(0));
        }

        public async Task<ServiceResult<int>> CleanupZombieSessionsAsync()
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<int>.Success(0));
        }

        public async Task<ServiceResult> ArchiveSessionAsync(Guid sessionId, string archiveReason)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }
        #endregion

        #region 검증 및 권한
        public async Task<ServiceResult<SessionValidationData>> ValidateSessionTokenAsync(string sessionToken)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionValidationData>.Success(new SessionValidationData()));
        }

        public async Task<ServiceResult<bool>> IsSessionOwnerAsync(Guid sessionId, Guid connectedId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<bool>.Success(false));
        }

        public async Task<ServiceResult<bool>> HasSessionPermissionAsync(Guid sessionId, string requiredPermission)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<bool>.Success(false));
        }

        public async Task<ServiceResult<bool>> CanAccessSessionAsync(Guid sessionId, Guid requesterId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<bool>.Success(false));
        }
        #endregion

        #region 다중 디바이스 관리
        public async Task<ServiceResult> RegisterTrustedDeviceAsync(Guid sessionId, TrustedDeviceRequest request)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<IEnumerable<TrustedDeviceDto>>> GetTrustedDevicesAsync(Guid connectedId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<IEnumerable<TrustedDeviceDto>>.Success(new List<TrustedDeviceDto>()));
        }

        public async Task<ServiceResult> RevokeTrustedDeviceAsync(Guid deviceId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<bool>> CheckDeviceLimitAsync(Guid connectedId, string deviceId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<bool>.Success(true));
        }
        #endregion

        #region 세션 정책
        public async Task<ServiceResult> ApplySessionPolicyAsync(Guid sessionId, SessionPolicy policy)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> SetOrganizationSessionPolicyAsync(Guid organizationId, OrganizationSessionPolicy policy)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<SessionLimitCheck>> CheckSessionLimitsAsync(Guid connectedId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionLimitCheck>.Success(new SessionLimitCheck()));
        }
        #endregion

        #region 캐싱 및 성능
        public async Task<ServiceResult> EnableSessionCacheAsync(Guid sessionId, CacheOptions options)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> EnablePermissionCacheAsync(Guid sessionId, TimeSpan? ttl = null)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult> ClearSessionCacheAsync(Guid sessionId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }

        public async Task<ServiceResult<SessionCacheStatistics>> GetCacheStatisticsAsync(Guid? sessionId = null)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionCacheStatistics>.Success(new SessionCacheStatistics()));
        }

        public async Task<ServiceResult> WarmupCacheAsync(Guid sessionId, List<string> preloadKeys)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }
        #endregion

        #region 내보내기 및 감사
        public async Task<ServiceResult<SessionExportData>> ExportSessionLogsAsync(Guid organizationId, SessionExportRequest request)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionExportData>.Success(new SessionExportData()));
        }

        public async Task<ServiceResult<SessionAuditTrail>> GetAuditTrailAsync(Guid sessionId)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<SessionAuditTrail>.Success(new SessionAuditTrail()));
        }

        public async Task<ServiceResult> LogSessionEventAsync(Guid sessionId, SessionEventType eventType, string details)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult.Success());
        }
        #endregion

        #region 일괄 작업
        public async Task<ServiceResult<BulkOperationResult>> BulkLockSessionsAsync(List<Guid> sessionIds, string reason)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<BulkOperationResult>.Success(new BulkOperationResult()));
        }

        public async Task<ServiceResult<BulkOperationResult>> BulkEndSessionsAsync(List<Guid> sessionIds, SessionEndReason reason)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<BulkOperationResult>.Success(new BulkOperationResult()));
        }

        public async Task<ServiceResult<BulkOperationResult>> BulkRefreshSessionsAsync(List<Guid> sessionIds)
        {
            // TODO: Implementation
            return await Task.FromResult(ServiceResult<BulkOperationResult>.Success(new BulkOperationResult()));
        }
        #endregion
        private SessionDetailResponse MapToDetailResponse(SessionEntity session)
        {
            return new SessionDetailResponse
            {
                Id = session.Id,
                ConnectedId = session.ConnectedId ?? Guid.Empty,
                ConnectedIdDisplayName = string.Empty, // ConnectedId에 DisplayName 필드가 없으므로
                OrganizationId = session.OrganizationId ?? Guid.Empty,
                Organization = session.Organization != null ? new OrganizationInfo
                {
                    Id = session.Organization.Id,
                    Name = session.Organization.Name,
                    Domain = string.Empty // Organization에 Domain 필드 확인 필요
                } : new OrganizationInfo(),
                SessionTokenMasked = MaskToken(session.SessionToken),
                SessionType = session.SessionType,
                Status = session.Status,
                Client = new ClientInfo
                {
                    IpAddress = session.IpAddress,
                    UserAgent = session.UserAgent,
                    DeviceInfo = session.DeviceInfo,
                    OperatingSystem = session.OperatingSystem,
                    Browser = session.Browser,
                    Location = session.Location
                },
                Communications = new CommunicationSettings
                {
                    GrpcEnabled = session.GrpcEnabled,
                    PubSubNotifications = session.PubSubNotifications,
                    PermissionCacheEnabled = session.PermissionCacheEnabled
                },
                Metrics = new ActivityMetrics
                {
                    PageViews = session.PageViews,
                    ApiCalls = session.ApiCalls,
                    LastActivityAt = session.LastActivityAt
                },
                Security = new SecurityState
                {
                    RiskScore = session.RiskScore,
                    IsLocked = session.IsLocked,
                    LockedAt = session.LockedAt,
                    LockReason = session.LockReason
                },
                Timing = new SessionTiming
                {
                    CreatedAt = session.CreatedAt,
                    ExpiresAt = session.ExpiresAt,
                    LastActivityAt = session.LastActivityAt
                },
                Contexts = new List<ContextInfo>(), // 별도 조회 필요
                Audit = new AuditInformation
                {
                    CreatedByConnectedId = session.CreatedByConnectedId,
                    CreatedAt = session.CreatedAt,
                    UpdatedByConnectedId = session.UpdatedByConnectedId,
                    UpdatedAt = session.UpdatedAt
                }
            };
        }

        /// <summary>
        /// 토큰 마스킹
        /// </summary>
        private string MaskToken(string token)
        {
            if (string.IsNullOrEmpty(token) || token.Length < 8)
                return "****";

            return $"{token.Substring(0, 4)}...{token.Substring(token.Length - 4)}";
        }
    }
}