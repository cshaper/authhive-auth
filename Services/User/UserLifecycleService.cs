using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Service;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Interfaces.Audit;
using AuthHive.Core.Interfaces.Platform.Service;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Common.Requests;
using AuthHive.Core.Models.User;
using AuthHive.Core.Models.User.Requests;
using AuthHive.Core.Models.PlatformApplication;
using AuthHive.Core.Models.Organization;
using AuthHive.Core.Models.Organization.Common;
using AuthHive.Core.Models.Organization.Requests;
using AuthHive.Core.Models.Auth.Session;
using AuthHive.Core.Models.Infra.UserExperience;
using AuthHive.Core.Models.Infra.UserExperience.Requests;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Enums.Audit;
using AuthHive.Core.Enums.Infra.UserExperience;
using static AuthHive.Core.Enums.Core.UserEnums;
using static AuthHive.Core.Enums.Auth.SessionEnums;
using AuthHive.Core.Models.PlatformApplication.Requests;
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Services.User
{
    /// <summary>
    /// 사용자 생명주기 관리 서비스 구현체 - AuthHive v15
    /// 사용자의 전체 생명주기(활성화, 비활성화, 정지, 삭제)를 관리하고
    /// 다른 도메인 서비스들과 통합하여 일관된 상태 관리를 제공합니다.
    /// UserSuspension 엔티티를 통해 정지 이력을 별도 관리합니다.
    /// </summary>
    public class UserLifecycleService : IUserLifecycleService
    {
        private readonly IUserRepository _userRepository;
        private readonly IUserSuspensionRepository _userSuspensionRepository;
        private readonly IUserService _userService;
        private readonly IOrganizationMembershipService _membershipService;
        private readonly IUserApplicationAccessService _applicationAccessService;
        private readonly IPermissionService _permissionService;
        private readonly ISessionService _sessionService;
        private readonly INotificationService _notificationService;
        private readonly IAuditService _auditService;
        private readonly IUserActivityLogService _activityLogService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly ILogger<UserLifecycleService> _logger;

        public UserLifecycleService(
            IUserRepository userRepository,
            IUserSuspensionRepository userSuspensionRepository,
            IUserService userService,
            IOrganizationMembershipService membershipService,
            IUserApplicationAccessService applicationAccessService,
            IPermissionService permissionService,
            ISessionService sessionService,
            INotificationService notificationService,
            IAuditService auditService,
            IUserActivityLogService activityLogService,
            IUnitOfWork unitOfWork,
            ILogger<UserLifecycleService> logger)
        {
            _userRepository = userRepository;
            _userSuspensionRepository = userSuspensionRepository;
            _userService = userService;
            _membershipService = membershipService;
            _applicationAccessService = applicationAccessService;
            _permissionService = permissionService;
            _sessionService = sessionService;
            _notificationService = notificationService;
            _auditService = auditService;
            _activityLogService = activityLogService;
            _unitOfWork = unitOfWork;
            _logger = logger;
        }

        #region 상태 관리

        /// <summary>
        /// 사용자 상태 변경 - 모든 관련 시스템과 동기화
        /// </summary>
        public async Task<ServiceResult> ChangeStatusAsync(
            Guid id,
            UserStatus status,
            string? reason = null,
            Guid? updatedByConnectedId = null)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // 1. 사용자 존재 여부 확인
                var user = await _userRepository.GetByIdAsync(id);
                if (user == null)
                {
                    return ServiceResult.NotFound("User not found");
                }

                var oldStatus = user.Status;

                // 2. 상태 변경 가능 여부 검증
                if (!IsValidStatusTransition(oldStatus, status))
                {
                    return ServiceResult.Failure($"Invalid status transition from {oldStatus} to {status}");
                }

                // 3. 사용자 상태 업데이트
                user.Status = status;
                user.UpdatedAt = DateTime.UtcNow;
                await _userRepository.UpdateAsync(user);

                // 4. Suspended에서 다른 상태로 변경 시 Suspension 기록 종료
                if (oldStatus == UserStatus.Suspended && status != UserStatus.Suspended)
                {
                    await EndActiveSuspensionAsync(id, $"Status changed to {status}");
                }

                // 5. 관련 서비스들과 상태 동기화
                await SynchronizeRelatedServicesAsync(user, status, reason);

                // 6. 감사 로그 기록
                await _auditService.LogAsync(new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = updatedByConnectedId ?? id,
                    ResourceType = "User",
                    ResourceId = id.ToString(),
                    Action = $"Status changed from {oldStatus} to {status}",
                    ActionType = AuditActionType.Update,
                    Success = true,
                    Timestamp = DateTime.UtcNow,
                    Severity = AuditEventSeverity.Info,
                    Metadata = reason != null ? $"{{\"reason\": \"{reason}\"}}" : null
                });

                // 7. 활동 로그 기록
                await LogUserActivityAsync(id, UserActivityType.SettingsChange,
                    $"Status changed from {oldStatus} to {status}", reason);

                // 8. 알림 발송
                await SendStatusChangeNotificationAsync(user, oldStatus, status, reason);

                await _unitOfWork.CommitTransactionAsync();

                _logger.LogInformation(
                    "User status changed: UserId={UserId}, OldStatus={OldStatus}, NewStatus={NewStatus}, Reason={Reason}",
                    id, oldStatus, status, reason);

                return ServiceResult.Success($"User status changed to {status}");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error changing user status for UserId={UserId}", id);
                return ServiceResult.Failure("Failed to change user status");
            }
        }

        /// <summary>
        /// 사용자 활성화
        /// </summary>
        public async Task<ServiceResult> ActivateAsync(Guid id)
        {
            // 활성화 시 진행 중인 Suspension 기록 종료
            var activeSuspension = await _userSuspensionRepository.GetActiveByUserIdAsync(id);
            if (activeSuspension != null)
            {
                await EndActiveSuspensionAsync(id, "User activated");
            }

            return await ChangeStatusAsync(id, UserStatus.Active, "User activated");
        }

        /// <summary>
        /// 사용자 비활성화
        /// </summary>
        public async Task<ServiceResult> DeactivateAsync(Guid id, string? reason = null)
        {
            var result = await ChangeStatusAsync(id, UserStatus.Inactive, reason ?? "User deactivated");

            if (result.IsSuccess)
            {
                // 추가: 모든 활성 세션 종료
                await _sessionService.EndAllSessionsAsync(id, SessionEndReason.AdminTerminated);
            }

            return result;
        }

        /// <summary>
        /// 사용자 정지 (일시적 또는 영구적)
        /// UserSuspension 엔티티를 사용하여 정지 이력 관리
        /// </summary>
        public async Task<ServiceResult> SuspendAsync(
            Guid id,
            string reason,
            DateTime? suspendedUntil = null)
        {
            try
            {
                await _unitOfWork.BeginTransactionAsync();

                // 1. 사용자 확인
                var user = await _userRepository.GetByIdAsync(id);
                if (user == null)
                {
                    return ServiceResult.NotFound("User not found");
                }

                // 2. 이미 정지 상태인지 확인
                var existingSuspension = await _userSuspensionRepository.GetActiveByUserIdAsync(id);
                if (existingSuspension != null)
                {
                    return ServiceResult.Failure("User is already suspended");
                }

                // 3. UserSuspension 엔티티 생성
                var suspension = new UserSuspension
                {
                    Id = Guid.NewGuid(),
                    UserId = id,
                    SuspendedAt = DateTime.UtcNow,
                    SuspendedUntil = suspendedUntil,
                    SuspensionReason = reason
                };
                await _userSuspensionRepository.AddAsync(suspension);

                // 4. User 상태를 Suspended로 변경
                user.Status = UserStatus.Suspended;
                user.UpdatedAt = DateTime.UtcNow;
                await _userRepository.UpdateAsync(user);

                // 5. 모든 활성 세션 즉시 종료
                await _sessionService.EndAllSessionsAsync(id, SessionEndReason.SecurityViolation);

                // 6. 모든 애플리케이션 접근 권한 일시 정지
                var userAccesses = await _applicationAccessService.GetUserAccessesAsync(id, false);
                if (userAccesses.IsSuccess && userAccesses.Data != null)
                {
                    foreach (var access in userAccesses.Data)
                    {
                        var updateRequest = new UpdateUserApplicationAccessRequest
                        {
                            IsActive = false
                        };

                        await _applicationAccessService.UpdateAccessAsync(
                            access.Id,
                            updateRequest,
                            id);
                    }
                }

                // 7. 감사 로그
                await _auditService.LogAsync(new AuditLog
                {
                    Id = Guid.NewGuid(),
                    PerformedByConnectedId = id,
                    ResourceType = "User",
                    ResourceId = id.ToString(),
                    Action = $"User suspended: {reason}",
                    ActionType = AuditActionType.Update,
                    Success = true,
                    Severity = AuditEventSeverity.Warning,
                    Timestamp = DateTime.UtcNow,
                    Metadata = $"{{\"suspensionId\": \"{suspension.Id}\", \"suspendedUntil\": \"{suspendedUntil?.ToString() ?? "Indefinite"}\", \"reason\": \"{reason}\"}}"
                });

                // 8. 이메일 알림
                await _notificationService.SendImmediateNotificationAsync(new NotificationSendRequest
                {
                    RecipientConnectedIds = new List<Guid> { id },
                    Subject = "Account Suspended",
                    Body = $"Your account has been suspended. Reason: {reason}",
                    ChannelOverride = NotificationChannel.Email,
                    Priority = NotificationPriority.High,
                    SendImmediately = true,
                    TemplateVariables = new Dictionary<string, string>
                    {
                        ["Reason"] = reason,
                        ["SuspendedUntil"] = suspendedUntil?.ToString() ?? "Indefinite"
                    }
                });

                await _unitOfWork.CommitTransactionAsync();

                _logger.LogWarning(
                    "User suspended: UserId={UserId}, SuspensionId={SuspensionId}, Reason={Reason}, Until={SuspendedUntil}",
                    id, suspension.Id, reason, suspendedUntil);

                return ServiceResult.Success("User suspended successfully");
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Error suspending user: UserId={UserId}", id);
                return ServiceResult.Failure("Failed to suspend user");
            }
        }

        /// <summary>
        /// 활성 Suspension 종료
        /// </summary>
        private async Task EndActiveSuspensionAsync(Guid userId, string endReason)
        {
            var activeSuspension = await _userSuspensionRepository.GetActiveByUserIdAsync(userId);
            if (activeSuspension != null)
            {
                // Suspension을 논리적으로 종료 (DeletedAt 설정)
                activeSuspension.IsDeleted = true;
                activeSuspension.DeletedAt = DateTime.UtcNow;
                await _userSuspensionRepository.UpdateAsync(activeSuspension);

                _logger.LogInformation(
                    "Suspension ended: UserId={UserId}, SuspensionId={SuspensionId}, EndReason={EndReason}",
                    userId, activeSuspension.Id, endReason);
            }
        }

        #endregion

        #region 일괄 작업

        /// <summary>
        /// 비활성 사용자 일괄 처리
        /// </summary>
        public async Task<ServiceResult<int>> ProcessInactiveUsersAsync(
            int inactiveDays,
            UserStatus action)
        {
            try
            {
                // 비활성 사용자 조회
                var inactiveUsers = await _userRepository.GetInactiveUsersAsync(inactiveDays);
                int processedCount = 0;
                var errors = new List<string>();

                foreach (var user in inactiveUsers)
                {
                    // 이미 정지 상태인 사용자는 건너뜀
                    if (user.Status == UserStatus.Suspended)
                    {
                        var isSuspended = await _userSuspensionRepository.IsUserSuspendedAsync(user.Id);
                        if (isSuspended)
                        {
                            continue;
                        }
                    }

                    var result = await ChangeStatusAsync(
                        user.Id,
                        action,
                        $"Inactive for {inactiveDays} days");

                    if (result.IsSuccess)
                    {
                        processedCount++;
                    }
                    else
                    {
                        errors.Add($"Failed to process user {user.Id}: {result.ErrorMessage}");
                    }
                }

                // 만료된 Suspension 자동 해제
                var liftedCount = await _userSuspensionRepository.LiftExpiredSuspensionsAsync();
                if (liftedCount > 0)
                {
                    _logger.LogInformation("Lifted {Count} expired suspensions", liftedCount);
                }

                _logger.LogInformation(
                    "Processed inactive users: Total={Total}, Processed={Processed}, Errors={Errors}",
                    inactiveUsers.Count(), processedCount, errors.Count);

                if (errors.Any())
                {
                    return ServiceResult<int>.FailureWithData(
                        $"Partially completed with {errors.Count} errors",
                        processedCount,
                        "PARTIAL_SUCCESS");
                }

                return ServiceResult<int>.Success(processedCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing inactive users");
                return ServiceResult<int>.Failure("Failed to process inactive users");
            }
        }

        /// <summary>
        /// 사용자 상태 일괄 변경
        /// </summary>
        public async Task<ServiceResult<BulkOperationResult>> BulkChangeStatusAsync(
            UserBulkStatusChangeRequest request)
        {
            var result = new BulkOperationResult();

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                foreach (var userId in request.EntityIds)
                {
                    try
                    {
                        // Suspended 상태로 변경 시 UserSuspension 생성
                        if (request.NewStatus == UserStatus.Suspended)
                        {
                            var suspendResult = await SuspendAsync(
                                userId,
                                request.Reason ?? "Bulk suspension",
                                request.SuspendedUntil);

                            if (suspendResult.IsSuccess)
                            {
                                result.SuccessCount++;
                            }
                            else
                            {
                                result.FailureCount++;
                                result.Errors.Add(new BulkOperationError
                                {
                                    EntityId = userId,
                                    ErrorCode = suspendResult.ErrorMessage ?? "Failed to suspend user"
                                });
                            }
                        }
                        else
                        {
                            var changeResult = await ChangeStatusAsync(
                                userId,
                                request.NewStatus,
                                request.Reason,
                                request.UpdatedByConnectedId);

                            if (changeResult.IsSuccess)
                            {
                                result.SuccessCount++;

                                // 세션 처리
                                if (request.SessionHandling == SessionHandlingOption.InvalidateAll)
                                {
                                    await _sessionService.EndAllSessionsAsync(
                                        userId,
                                        SessionEndReason.AdminTerminated);
                                }

                                // 이메일 알림
                                if (request.SendEmailNotification)
                                {
                                    await SendStatusChangeEmailAsync(userId, request.NewStatus, request.Reason);
                                }
                            }
                            else
                            {
                                result.Errors.Add(new BulkOperationError
                                {
                                    EntityId = userId,
                                    ErrorCode = changeResult.ErrorMessage ?? "Failed to change status"
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        result.FailureCount++;
                        result.Errors.Add(new BulkOperationError
                        {
                            EntityId = userId,
                            ErrorCode = ex.Message  // ErrorCode로 변경
                        });

                        if (!request.ContinueOnError)
                        {
                            throw;
                        }
                    }
                }

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Bulk status change failed");
                return ServiceResult<BulkOperationResult>.Failure("Bulk operation failed");
            }
            finally
            {
                stopwatch.Stop();
                result.ElapsedTime = stopwatch.Elapsed;
            }

            _logger.LogInformation(
                "Bulk status change completed: Total={Total}, Success={Success}, Failed={Failed}, Time={Time}ms",
                result.TotalCount, result.SuccessCount, result.FailureCount, result.ElapsedTime.TotalMilliseconds);

            return ServiceResult<BulkOperationResult>.Success(result);
        }

        /// <summary>
        /// 사용자 일괄 삭제
        /// </summary>
        public async Task<ServiceResult<BulkOperationResult>> BulkDeleteAsync(
            BulkDeleteRequest request)
        {
            var result = new BulkOperationResult();
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                await _unitOfWork.BeginTransactionAsync();

                foreach (var userId in request.EntityIds)
                {
                    try
                    {
                        // Soft delete 또는 Hard delete 결정
                        if (request.CascadeDelete)
                        {
                            // 관련 데이터도 모두 삭제
                            await DeleteUserWithRelatedDataAsync(userId, request.Reason);
                        }
                        else
                        {
                            // 사용자만 soft delete
                            await _userRepository.SoftDeleteAsync(userId);
                        }

                        // Suspension 이력도 삭제 처리
                        var suspensions = await _userSuspensionRepository.GetHistoryByUserIdAsync(userId);
                        foreach (var suspension in suspensions)
                        {
                            suspension.IsDeleted = true;
                            suspension.DeletedAt = DateTime.UtcNow;
                            await _userSuspensionRepository.UpdateAsync(suspension);
                        }

                        result.SuccessCount++;

                        // 감사 로그
                        await _auditService.LogAsync(new AuditLog
                        {
                            Id = Guid.NewGuid(),
                            PerformedByConnectedId = request.DeletedByConnectedId ?? userId,
                            ResourceType = "User",
                            ResourceId = userId.ToString(),
                            Action = $"User deleted (Cascade: {request.CascadeDelete})",
                            ActionType = AuditActionType.Delete,
                            Success = true,
                            Timestamp = DateTime.UtcNow,
                            Severity = AuditEventSeverity.Info,
                            Metadata = $"{{\"reason\": \"{request.Reason}\", \"cascadeDelete\": {request.CascadeDelete.ToString().ToLower()}, \"bulkOperation\": true}}"
                        });
                    }
                    catch (Exception ex)
                    {
                        result.FailureCount++;
                        result.Errors.Add(new BulkOperationError
                        {
                            EntityId = userId,
                            ErrorCode = ex.Message  // ErrorCode로 변경
                        });


                        if (!request.ContinueOnError)
                        {
                            throw;
                        }
                    }
                }

                await _unitOfWork.CommitTransactionAsync();
            }
            catch (Exception ex)
            {
                await _unitOfWork.RollbackTransactionAsync();
                _logger.LogError(ex, "Bulk delete failed");
                return ServiceResult<BulkOperationResult>.Failure("Bulk delete operation failed");
            }
            finally
            {
                stopwatch.Stop();
                result.ElapsedTime = stopwatch.Elapsed;
            }

            _logger.LogInformation(
                "Bulk delete completed: Total={Total}, Success={Success}, Failed={Failed}, Time={Time}ms",
                result.TotalCount, result.SuccessCount, result.FailureCount, result.ElapsedTime.TotalMilliseconds);

            return ServiceResult<BulkOperationResult>.Success(result);
        }

        /// <summary>
        /// 사용자 데이터 내보내기
        /// </summary>
        public async Task<ServiceResult<byte[]>> ExportUsersAsync(UserExportRequest request)
        {
            try
            {
                var users = new List<Core.Entities.User.User>();

                // 사용자 목록 가져오기
                if (request.UserIds != null && request.UserIds.Any())
                {
                    foreach (var userId in request.UserIds)
                    {
                        var user = await _userRepository.GetByIdAsync(userId);
                        if (user != null)
                        {
                            users.Add(user);
                        }
                    }
                }
                else
                {
                    users = (await _userRepository.GetAllAsync()).ToList();
                }

                // 데이터 수집
                var exportData = new List<Dictionary<string, object>>();

                foreach (var user in users)
                {
                    var userData = new Dictionary<string, object>
                    {
                        ["Id"] = user.Id,
                        ["Email"] = user.Email,
                        ["Username"] = user.Username ?? "",
                        ["DisplayName"] = user.DisplayName ?? "",
                        ["Status"] = user.Status.ToString(),
                        ["EmailVerified"] = user.IsEmailVerified,
                        ["TwoFactorEnabled"] = user.IsTwoFactorEnabled,
                        ["CreatedAt"] = user.CreatedAt,
                        ["UpdatedAt"] = user.UpdatedAt ?? user.CreatedAt,
                        ["LastLoginAt"] = user.LastLoginAt?.ToString() ?? "Never"
                    };

                    // Suspension 정보 추가
                    var suspension = await _userSuspensionRepository.GetActiveByUserIdAsync(user.Id);
                    if (suspension != null)
                    {
                        userData["IsSuspended"] = true;
                        userData["SuspendedAt"] = suspension.SuspendedAt;
                        userData["SuspendedUntil"] = suspension.SuspendedUntil?.ToString() ?? "Indefinite";
                        userData["SuspensionReason"] = suspension.SuspensionReason ?? "";
                    }
                    else
                    {
                        userData["IsSuspended"] = false;
                    }

                    // 프로필 정보 추가 (한 번만 조회하여 재사용)
                    UserEntity? userWithProfile = null;
                    if (request.IncludeProfiles || request.IncludeFeatureProfiles)
                    {
                        userWithProfile = await _userRepository.GetByIdWithProfileAsync(user.Id);

                        // 일반 프로필 정보
                        if (request.IncludeProfiles && userWithProfile?.UserProfile != null)
                        {
                            var profile = userWithProfile.UserProfile;
                            userData["PhoneNumber"] = profile.PhoneNumber ?? "";
                            userData["TimeZone"] = profile.TimeZone ?? "";
                            userData["PreferredLanguage"] = profile.PreferredLanguage ?? "";
                        }

                        // 기능 프로필 정보
                        if (request.IncludeFeatureProfiles && userWithProfile?.UserFeatureProfile != null)
                        {
                            var featureProfile = userWithProfile.UserFeatureProfile;
                            userData["ActiveAddons"] = featureProfile.ActiveAddons ?? "";
                            userData["ApiAccess"] = featureProfile.ApiAccess ?? "";
                            userData["TotalApiCalls"] = featureProfile.TotalApiCalls;
                        }
                    }

                    // 활동 로그 추가
                    if (request.IncludeActivityLogs)
                    {
                        var logsResult = await _activityLogService.GetByConnectedIdAsync(
                            user.Id,
                            user.Id,
                            DateTime.UtcNow.AddDays(-30),
                            DateTime.UtcNow,
                            100);

                        if (logsResult.IsSuccess && logsResult.Data != null)
                        {
                            userData["RecentActivityCount"] = logsResult.Data.TotalCount;

                            // ActivityAt 사용
                            var lastActivity = logsResult.Data.Items?.FirstOrDefault();
                            userData["LastActivityDate"] = lastActivity?.ActivityAt.ToString() ?? "N/A";
                        }
                        else
                        {
                            userData["RecentActivityCount"] = 0;
                            userData["LastActivityDate"] = "N/A";
                        }

                        // Suspension 이력 추가
                        var suspensionHistory = await _userSuspensionRepository.GetHistoryByUserIdAsync(user.Id);
                        userData["SuspensionHistoryCount"] = suspensionHistory.Count();
                    }
                    exportData.Add(userData);
                }

                // 형식에 따라 내보내기
                byte[] exportedData = request.Format switch
                {
                    DataFormat.Json => ExportToJson(exportData),
                    DataFormat.Csv => ExportToCsv(exportData),
                    DataFormat.Excel => ExportToExcel(exportData),
                    _ => ExportToCsv(exportData)
                };

                // 감사 로그
                await _auditService.LogActionAsync(
                    Guid.Empty,
                    $"Exported {users.Count} users in {request.Format} format",
                    AuditActionType.Read,
                    "User",
                    "Export",
                    true,
                    null);

                _logger.LogInformation(
                    "User data exported: Count={Count}, Format={Format}",
                    users.Count, request.Format);

                return ServiceResult<byte[]>.Success(exportedData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting user data");
                return ServiceResult<byte[]>.Failure("Failed to export user data");
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// 유효한 상태 전환인지 확인
        /// </summary>
        private bool IsValidStatusTransition(UserStatus from, UserStatus to)
        {
            return (from, to) switch
            {
                // Active에서 가능한 전환
                (UserStatus.Active, UserStatus.Inactive) => true,
                (UserStatus.Active, UserStatus.Suspended) => true,
                (UserStatus.Active, UserStatus.Deleted) => true,

                // Inactive에서 가능한 전환
                (UserStatus.Inactive, UserStatus.Active) => true,
                (UserStatus.Inactive, UserStatus.Deleted) => true,

                // Suspended에서 가능한 전환
                (UserStatus.Suspended, UserStatus.Active) => true,
                (UserStatus.Suspended, UserStatus.Inactive) => true,
                (UserStatus.Suspended, UserStatus.Deleted) => true,

                // Deleted는 최종 상태
                (UserStatus.Deleted, _) => false,

                // 동일한 상태로의 전환은 허용
                _ when from == to => true,

                // 그 외는 불가
                _ => false
            };
        }

        /// <summary>
        /// 관련 서비스들과 상태 동기화
        /// </summary>
        private async Task SynchronizeRelatedServicesAsync(
            Core.Entities.User.User user,
            UserStatus newStatus,
            string? reason)
        {
            var tasks = new List<Task>();

            switch (newStatus)
            {
                case UserStatus.Inactive:
                case UserStatus.Suspended:
                    // 세션 종료
                    tasks.Add(_sessionService.EndAllSessionsAsync(
                        user.Id,
                        SessionEndReason.AdminTerminated));
                    break;

                case UserStatus.Active:
                    // 권한 복구 - 별도 로직 필요
                    break;

                case UserStatus.Deleted:
                    // 모든 관련 데이터 정리
                    tasks.Add(CleanupDeletedUserDataAsync(user.Id));
                    break;
            }

            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// 삭제된 사용자의 데이터 정리
        /// </summary>
        private async Task CleanupDeletedUserDataAsync(Guid userId)
        {
            // 세션 삭제
            await _sessionService.EndAllSessionsAsync(userId, SessionEndReason.AdminTerminated);

            // 애플리케이션 접근 권한 삭제
            var accesses = await _applicationAccessService.GetUserAccessesAsync(userId, true);
            if (accesses.IsSuccess && accesses.Data != null)
            {
                foreach (var access in accesses.Data)
                {
                    await _applicationAccessService.RevokeAccessAsync(
                        userId,
                        access.ApplicationId,
                        userId,
                        "User deleted");
                }
            }
        }

        /// <summary>
        /// 사용자와 관련 데이터 삭제
        /// </summary>
        private async Task DeleteUserWithRelatedDataAsync(Guid userId, string? reason)
        {
            // Suspension 이력 삭제
            var suspensions = await _userSuspensionRepository.GetHistoryByUserIdAsync(userId);
            foreach (var suspension in suspensions)
            {
                suspension.IsDeleted = true;
                suspension.DeletedAt = DateTime.UtcNow;
                await _userSuspensionRepository.UpdateAsync(suspension);
            }

            // 사용자 엔티티 삭제
            await _userRepository.SoftDeleteAsync(userId);
        }

        /// <summary>
        /// 상태 변경 알림 발송
        /// </summary>
        private async Task SendStatusChangeNotificationAsync(
            Core.Entities.User.User user,
            UserStatus oldStatus,
            UserStatus newStatus,
            string? reason)
        {
            await _notificationService.QueueNotificationAsync(new NotificationSendRequest
            {
                RecipientConnectedIds = new List<Guid> { user.Id },
                Subject = "Account Status Changed",
                Body = $"Your account status has been changed from {oldStatus} to {newStatus}." +
                      (string.IsNullOrEmpty(reason) ? "" : $" Reason: {reason}"),
                ChannelOverride = NotificationChannel.Email,
                Priority = NotificationPriority.Normal,
                SendImmediately = false,
                TemplateVariables = new Dictionary<string, string>
                {
                    ["OldStatus"] = oldStatus.ToString(),
                    ["NewStatus"] = newStatus.ToString(),
                    ["Reason"] = reason ?? ""
                }
            });
        }

        /// <summary>
        /// 상태 변경 이메일 발송
        /// </summary>
        private async Task SendStatusChangeEmailAsync(
            Guid userId,
            UserStatus newStatus,
            string? reason)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user == null) return;

            await _notificationService.SendImmediateNotificationAsync(new NotificationSendRequest
            {
                RecipientConnectedIds = new List<Guid> { userId },
                Subject = "Account Status Update",
                Body = $"Hello {user.DisplayName ?? user.Username ?? "User"},\n\n" +
                      $"Your account status has been changed to {newStatus}.\n" +
                      $"Reason: {reason ?? "Administrative action"}\n" +
                      $"Date: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC\n\n" +
                      "If you have any questions, please contact support.",
                ChannelOverride = NotificationChannel.Email,
                Priority = NotificationPriority.High,
                SendImmediately = true,
                TemplateVariables = new Dictionary<string, string>
                {
                    ["UserName"] = user.DisplayName ?? user.Username ?? "User",
                    ["NewStatus"] = newStatus.ToString(),
                    ["Reason"] = reason ?? "Administrative action",
                    ["Date"] = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC")
                }
            });
        }

        /// <summary>
        /// 사용자 활동 로그 기록
        /// </summary>
        private async Task LogUserActivityAsync(
            Guid userId,
            UserActivityType activityType,
            string description,
            string? reason)
        {
            _logger.LogInformation(
                "Activity log: UserId={UserId}, Type={ActivityType}, Description={Description}, Reason={Reason}",
                userId, activityType, description, reason);

            // TODO: 실제 IUserActivityLogService 구현에 맞춰 수정 필요
            await Task.CompletedTask;
        }

        /// <summary>
        /// JSON으로 내보내기
        /// </summary>
        private byte[] ExportToJson(List<Dictionary<string, object>> data)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(data, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
            return Encoding.UTF8.GetBytes(json);
        }

        /// <summary>
        /// CSV로 내보내기
        /// </summary>
        private byte[] ExportToCsv(List<Dictionary<string, object>> data)
        {
            if (!data.Any()) return Array.Empty<byte>();

            var csv = new StringBuilder();

            // 헤더
            var headers = data.First().Keys;
            csv.AppendLine(string.Join(",", headers.Select(h => $"\"{h}\"")));

            // 데이터
            foreach (var row in data)
            {
                var values = headers.Select(h =>
                {
                    var value = row[h]?.ToString() ?? "";
                    // CSV 이스케이프
                    if (value.Contains("\"") || value.Contains(",") || value.Contains("\n"))
                    {
                        value = $"\"{value.Replace("\"", "\"\"")}\"";
                    }
                    return value;
                });
                csv.AppendLine(string.Join(",", values));
            }

            return Encoding.UTF8.GetBytes(csv.ToString());
        }

        /// <summary>
        /// Excel로 내보내기 (간단한 구현 - 실제로는 EPPlus 등 라이브러리 사용)
        /// </summary>
        private byte[] ExportToExcel(List<Dictionary<string, object>> data)
        {
            // 임시로 CSV 형식으로 반환 (실제 구현 시 EPPlus 또는 ClosedXML 사용)
            _logger.LogWarning("Excel export requested but returning CSV format");
            return ExportToCsv(data);
        }

        #endregion
    }

}