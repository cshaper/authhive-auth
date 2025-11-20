using System;
using System.Collections.Generic;
using System.Collections.ObjectModel; // IReadOnlyDictionary 사용을 위해 필요할 수 있습니다.
using System.Linq;

namespace AuthHive.Core.Models.Organization.ReadModels
{
    /// <summary>
    /// 플랫폼 전체의 데이터 정책 사용 통계 (v17 Immutable Read Model)
    /// [주의] 특정 조직의 통계가 아닌, 전역 집계 통계입니다.
    /// </summary>
    public class DataPolicyStatisticsReadModel
    {
        // --- 시간 및 범위 ---

        /// <summary>
        /// 통계가 생성된 시간
        /// </summary>
        public required DateTime GeneratedAt { get; init; }

        /// <summary>
        /// 통계 기간 시작일
        /// </summary>
        public required DateTime PeriodStart { get; init; }

        /// <summary>
        /// 통계 기간 종료일
        /// </summary>
        public required DateTime PeriodEnd { get; init; }

        // --- 주요 집계 수치 ---

        /// <summary>
        /// 전체 조직 수
        /// </summary>
        public required int TotalOrganizations { get; init; }

        /// <summary>
        /// 정책을 보유한 조직 수
        /// </summary>
        public required int OrganizationsWithPolicy { get; init; }

        /// <summary>
        /// 기본 정책을 사용하는 조직 수 (0으로 초기화 가능)
        /// </summary>
        public required int OrganizationsWithDefaultPolicy { get; init; }

        /// <summary>
        /// 데이터 내보내기를 허용한 조직 수
        /// </summary>
        public required int AllowDataExportCount { get; init; }

        /// <summary>
        /// 자동 익명화를 활성화한 조직 수
        /// </summary>
        public required int AutoAnonymizationEnabledCount { get; init; }

        /// <summary>
        /// 평균 데이터 보존 기간 (일)
        /// </summary>
        public required double AverageDataRetentionDays { get; init; }

        // --- 분포 (Distribution) ---

        /// <summary>
        /// 암호화 수준별 조직 분포
        /// </summary>
        public required IReadOnlyDictionary<string, int> EncryptionLevelDist { get; init; }

        /// <summary>
        /// 사용자 메타데이터 모드별 조직 분포
        /// </summary>
        public required IReadOnlyDictionary<string, int> MetadataModeDist { get; init; }

        /// <summary>
        /// 컴플라이언스 준수 유형별 조직 분포 (예: GDPR 준수 조직 수)
        /// </summary>
        public required IReadOnlyDictionary<string, int> RegulationComplianceDist { get; init; }

        /// <summary>
        /// 허용된 외부 시스템별 조직 분포 (v17 추가 속성)
        /// </summary>
        public required IReadOnlyDictionary<string, int> ExternalSystemDist { get; init; }

        /// <summary>
        /// API 키 관리 정책별 조직 분포 (v17 추가 속성)
        /// </summary>
        public required IReadOnlyDictionary<string, int> ApiKeyPolicyDist { get; init; }

        // [수정] 생성자를 제거하고, 'required init' 속성을 사용하도록 변경했습니다.
    }
}