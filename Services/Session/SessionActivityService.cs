using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Auth.Session;
using AuthHive.Core.Models.Auth.Session.Common;
using AuthHive.Core.Models.Auth.Session.Requests;
using AuthHive.Core.Models.Auth.Session.Views;
using AuthHive.Core.Models.Common;
using AuthHive.Core.Models.Infra.Monitoring;
using AuthHive.Core.Models.Infra.Security;
using static AuthHive.Core.Enums.Auth.SessionEnums;

namespace AuthHive.Core.Interfaces.Auth.Service
{
    /// <summary>
    /// 세션 활동 추적 및 분석 서비스 인터페이스 - AuthHive v15
    /// IOrganizationScopedService를 상속하여 표준 CRUD 및 조직 범위 작업 지원
    /// </summary>
    public interface ISessionActivityService : IOrganizationScopedService<
        SessionActivityLog,
        SessionActivityDto,
        SessionActivityRequest,
        SessionActivityUpdateRequest>
    {
        #region 활동 로깅

        /// <summary>
        /// 세션 활동 기록
        /// </summary>
        /// <param name="request">활동 요청</param>
        /// <returns>처리 결과</returns>
        Task<ServiceResult> LogActivityAsync(SessionActivityRequest request);

        /// <summary>
        /// 여러 활동 일괄 기록
        /// </summary>
        /// <param name="requests">활동 요청 목록</param>
        /// <returns>처리 결과</returns>
        Task<ServiceResult> LogBulkActivitiesAsync(IEnumerable<SessionActivityRequest> requests);

        #endregion

        #region 활동 조회

        /// <summary>
        /// 세션별 활동 조회
        /// </summary>
        /// <param name="sessionId">세션 ID</param>
        /// <param name="from">시작 일시</param>
        /// <param name="to">종료 일시</param>
        /// <param name="limit">최대 결과 수</param>
        /// <returns>활동 목록</returns>
        Task<ServiceResult<IEnumerable<SessionActivityDto>>> GetSessionActivitiesAsync(
            Guid sessionId,
            DateTime? from = null,
            DateTime? to = null,
            int? limit = null);

        /// <summary>
        /// 세션 활동 뷰 조회
        /// </summary>
        /// <param name="sessionId">세션 ID</param>
        /// <returns>활동 뷰</returns>
        Task<ServiceResult<SessionActivityView>> GetSessionActivityViewAsync(Guid sessionId);

        /// <summary>
        /// 사용자별 활동 조회
        /// </summary>
        /// <param name="userId">사용자 ID</param>
        /// <param name="from">시작 일시</param>
        /// <param name="to">종료 일시</param>
        /// <param name="request">페이징 요청</param>
        /// <returns>페이징된 활동 목록</returns>
        Task<ServiceResult<PagedResult<SessionActivityDto>>> GetUserActivitiesAsync(
            Guid userId,
            DateTime? from = null,
            DateTime? to = null,
            PaginationRequest? request = null);

        /// <summary>
        /// ConnectedId별 활동 조회
        /// </summary>
        /// <param name="connectedId">ConnectedId</param>
        /// <param name="from">시작 일시</param>
        /// <param name="to">종료 일시</param>
        /// <returns>활동 목록</returns>
        Task<ServiceResult<IEnumerable<SessionActivityDto>>> GetConnectedIdActivitiesAsync(
            Guid connectedId,
            DateTime? from = null,
            DateTime? to = null);

        #endregion

        #region 보안 및 위험 분석

        /// <summary>
        /// 세션 보안 이벤트 조회
        /// </summary>
        /// <param name="sessionId">세션 ID</param>
        /// <param name="from">시작 일시</param>
        /// <param name="to">종료 일시</param>
        /// <returns>보안 이벤트 목록</returns>
        Task<ServiceResult<IEnumerable<SecurityEventDto>>> GetSecurityEventsAsync(
            Guid sessionId,
            DateTime? from = null,
            DateTime? to = null);

        /// <summary>
        /// 세션 위험도 평가
        /// </summary>
        /// <param name="sessionId">세션 ID</param>
        /// <returns>위험도 평가 결과</returns>
        Task<ServiceResult<RiskAssessmentResult>> AssessSessionRiskAsync(Guid sessionId);

        /// <summary>
        /// 활동 패턴 분석
        /// </summary>
        /// <param name="sessionId">세션 ID</param>
        /// <param name="from">분석 시작 일시</param>
        /// <returns>패턴 분석 결과</returns>
        Task<ServiceResult<ActivityPatternAnalysis>> AnalyzeActivityPatternsAsync(
            Guid sessionId,
            DateTime? from = null);

        /// <summary>
        /// 의심스러운 활동 탐지
        /// </summary>
        /// <param name="sessionId">세션 ID</param>
        /// <param name="threshold">임계값</param>
        /// <returns>의심스러운 활동 목록</returns>
        Task<ServiceResult<IEnumerable<SessionActivityDto>>> DetectSuspiciousActivitiesAsync(
            Guid sessionId,
            int? threshold = null);

        #endregion

        #region 통계 및 분석

        /// <summary>
        /// 세션 활동 통계
        /// </summary>
        /// <param name="sessionId">세션 ID</param>
        /// <param name="from">시작 일시</param>
        /// <param name="to">종료 일시</param>
        /// <returns>활동 통계</returns>
        Task<ServiceResult<SessionActivityStatistics>> GetActivityStatisticsAsync(
            Guid sessionId,
            DateTime? from = null,
            DateTime? to = null);

        /// <summary>
        /// 조직별 활동 통계
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="from">시작 일시</param>
        /// <param name="to">종료 일시</param>
        /// <returns>조직 활동 통계</returns>
        Task<ServiceResult<OrganizationActivityStatistics>> GetOrganizationStatisticsAsync(
            Guid organizationId,
            DateTime? from = null,
            DateTime? to = null);

        /// <summary>
        /// 실시간 활동 모니터링
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="windowMinutes">모니터링 시간 창 (분)</param>
        /// <returns>실시간 활동 정보</returns>
        Task<ServiceResult<RealtimeActivityMonitor>> GetRealtimeActivityAsync(
            Guid organizationId,
            int windowMinutes = 5);

        #endregion

        #region 정리 및 유지보수

        /// <summary>
        /// 오래된 활동 로그 정리
        /// </summary>
        /// <param name="olderThan">기준 일시</param>
        /// <param name="archiveBeforeDelete">삭제 전 아카이브 여부</param>
        /// <returns>삭제된 레코드 수</returns>
        Task<ServiceResult<int>> CleanupOldActivitiesAsync(
            DateTime olderThan,
            bool archiveBeforeDelete = true);

        /// <summary>
        /// 활동 로그 아카이브
        /// </summary>
        /// <param name="from">시작 일시</param>
        /// <param name="to">종료 일시</param>
        /// <param name="archiveLocation">아카이브 위치</param>
        /// <returns>아카이브된 레코드 수</returns>
        Task<ServiceResult<int>> ArchiveActivitiesAsync(
            DateTime from,
            DateTime to,
            string archiveLocation);

        /// <summary>
        /// 세션별 활동 로그 내보내기
        /// </summary>
        /// <param name="sessionId">세션 ID</param>
        /// <param name="format">내보내기 형식 (json, csv, xlsx)</param>
        /// <returns>내보내기 파일 경로</returns>
        Task<ServiceResult<string>> ExportSessionActivitiesAsync(
            Guid sessionId,
            string format = "json");

        #endregion

        #region 고급 기능

        /// <summary>
        /// 활동 재생 (세션 재현)
        /// </summary>
        /// <param name="sessionId">세션 ID</param>
        /// <param name="from">시작 시점</param>
        /// <param name="to">종료 시점</param>
        /// <returns>활동 재생 데이터</returns>
        Task<ServiceResult<SessionReplay>> GetSessionReplayAsync(
            Guid sessionId,
            DateTime? from = null,
            DateTime? to = null);

        /// <summary>
        /// 활동 기반 사용자 행동 프로파일링
        /// </summary>
        /// <param name="userId">사용자 ID</param>
        /// <param name="days">분석 기간 (일)</param>
        /// <returns>사용자 행동 프로파일</returns>
        Task<ServiceResult<UserBehaviorProfile>> GenerateUserProfileAsync(
            Guid userId,
            int days = 30);

        /// <summary>
        /// 이상 탐지 모델 학습
        /// </summary>
        /// <param name="organizationId">조직 ID</param>
        /// <param name="trainingDays">학습 데이터 기간 (일)</param>
        /// <returns>모델 학습 결과</returns>
        Task<ServiceResult<AnomalyDetectionResult>> TrainAnomalyModelAsync(
            Guid organizationId,
            int trainingDays = 90);

        #endregion
    }

    #region Supporting DTOs


    /// <summary>
    /// 조직 활동 통계
    /// </summary>
    public class OrganizationActivityStatistics
    {
        public Guid OrganizationId { get; set; }
        public int ActiveSessions { get; set; }
        public int TotalActivities { get; set; }
        public int UniqueUsers { get; set; }
        public Dictionary<SessionActivityType, int> ActivityBreakdown { get; set; } = new();
        public List<TopUser> MostActiveUsers { get; set; } = new();
        public List<RiskAlert> HighRiskActivities { get; set; } = new();
        public DateTime PeriodStart { get; set; }
        public DateTime PeriodEnd { get; set; }
    }

    /// <summary>
    /// 실시간 활동 모니터
    /// </summary>
    public class RealtimeActivityMonitor
    {
        public int CurrentActiveSessions { get; set; }
        public int ActivitiesPerMinute { get; set; }
        public List<SessionActivityDto> RecentActivities { get; set; } = new();
        public List<SecurityAlert> ActiveAlerts { get; set; } = new();
        public Dictionary<string, int> ActivityHotspots { get; set; } = new();
        public DateTime WindowStart { get; set; }
        public DateTime WindowEnd { get; set; }
    }

    /// <summary>
    /// 세션 재생 데이터
    /// </summary>
    public class SessionReplay
    {
        public Guid SessionId { get; set; }
        public List<ReplayFrame> Frames { get; set; } = new();
        public TimeSpan Duration { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
    }

    /// <summary>
    /// 재생 프레임
    /// </summary>
    public class ReplayFrame
    {
        public DateTime Timestamp { get; set; }
        public SessionActivityType ActivityType { get; set; }
        public string Description { get; set; } = string.Empty;
        public string? ResourceAccessed { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// 사용자 행동 프로파일
    /// </summary>
    public class UserBehaviorProfile
    {
        public Guid UserId { get; set; }
        public Dictionary<int, double> HourlyActivityPattern { get; set; } = new();
        public Dictionary<string, int> FrequentlyAccessedResources { get; set; } = new();
        public List<string> UnusualBehaviors { get; set; } = new();
        public double NormalRiskScore { get; set; }
        public DateTime ProfileGeneratedAt { get; set; }
    }


    /// <summary>
    /// 상위 사용자
    /// </summary>
    public class TopUser
    {
        public Guid UserId { get; set; }
        public string Username { get; set; } = string.Empty;
        public int ActivityCount { get; set; }
        public double AverageRiskScore { get; set; }
    }

    /// <summary>
    /// 위험 경고
    /// </summary>
    public class RiskAlert
    {
        public Guid ActivityId { get; set; }
        public string Description { get; set; } = string.Empty;
        public int RiskScore { get; set; }
        public DateTime OccurredAt { get; set; }
    }

    /// <summary>
    /// 세션 활동 업데이트 요청
    /// </summary>
    public class SessionActivityUpdateRequest
    {
        public string? Description { get; set; }
        public int? RiskScore { get; set; }
        public bool? IsSuspicious { get; set; }
        public string? Metadata { get; set; }
    }

    #endregion
}