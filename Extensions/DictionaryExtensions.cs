// File: AuthHive.Auth/Extensions/DictionaryExtensions.cs
// ----------------------------------------------------------------------
// [수정된 파일]
// ❗️ 기존 Merge, ToStringDictionary 메서드에
// ❗️ MergeMetadata 확장 메서드를 추가합니다.
// ----------------------------------------------------------------------

using Microsoft.Extensions.Logging; // ❗️ 로깅 필요 시 사용 (선택 사항)
using System; // ❗️ Exception 사용 위해 추가
using System.Collections.Generic;
using System.Linq;

namespace AuthHive.Auth.Extensions
{
    /// <summary>
    /// (한글 주석) Dictionary<string, object> 확장 메서드
    /// </summary>
    public static class DictionaryExtensions
    {
        /// <summary>
        /// source 딕셔너리의 모든 항목을 target 딕셔너리에 병합(덮어쓰기)합니다.
        /// </summary>
        public static void Merge(this Dictionary<string, object> target, Dictionary<string, object>? source)
        {
            if (source == null || target == null)
            {
                return;
            }

            foreach (var kvp in source)
            {
                target[kvp.Key] = kvp.Value; // (한글 주석) 키가 이미 존재하면 덮어씁니다.
            }
        }

        /// <summary>
        /// Dictionary<string, object>를 Dictionary<string, string>으로 변환합니다.
        /// 값은 ToString()을 사용하며 null일 경우 string.Empty로 처리합니다.
        /// </summary>
        public static Dictionary<string, string> ToStringDictionary(this Dictionary<string, object> source)
        {
            if (source == null)
            {
                return new Dictionary<string, string>();
            }

            return source.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value?.ToString() ?? string.Empty // (한글 주석) null 값은 빈 문자열로 변환
            );
        }

        /// <summary>
        /// (한글 주석) [신규 추가] 원본 딕셔너리(target)에 다른 딕셔너리(metadata)의 내용을 병합합니다.
        /// 병합 시 키 충돌을 피하기 위해 metadata의 키 앞에 "custom_" 접두사를 붙입니다.
        /// </summary>
        /// <param name="target">병합 대상이 되는 딕셔너리 (this)</param>
        /// <param name="metadata">병합할 내용을 가진 딕셔너리 (nullable)</param>
        /// <param name="logger">(선택 사항) 오류 로깅을 위한 로거</param>
        /// <returns>병합된 target 딕셔너리 (메서드 체이닝을 위해)</returns>
        public static Dictionary<string, object> MergeMetadata(
            this Dictionary<string, object> target,
            Dictionary<string, object>? metadata,
            ILogger? logger = null) // ❗️ 로거는 선택적으로 받도록 수정
        {
            if (metadata == null || metadata.Count == 0)
            {
                return target; // (한글 주석) 병합할 내용이 없으면 그대로 반환
            }

            try
            {
                foreach (var kvp in metadata)
                {
                    // (한글 주석) 키 충돌 방지를 위해 접두사 추가
                    var newKey = $"custom_{kvp.Key}";
                    if (!target.ContainsKey(newKey)) // (한글 주석) 이미 같은 custom 키가 없다면 추가
                    {
                         target[newKey] = kvp.Value;
                    }
                    else
                    {
                        // (한글 주석) 이미 custom 키가 존재할 경우 경고 로깅 (선택 사항)
                        logger?.LogWarning("MergeMetadata conflict: Key '{Key}' already exists in target dictionary.", newKey);
                        // 또는 값을 덮어쓰거나 다른 방식으로 처리할 수 있습니다.
                        // target[newKey] = kvp.Value; // 덮어쓰기 예시
                    }
                }
            }
            catch (Exception ex)
            {
                // (한글 주석) 병합 중 오류 발생 시 처리
                logger?.LogWarning(ex, "Failed to merge dynamic metadata dictionary.");
                target["raw_metadata_error"] = $"Failed to merge metadata: {ex.Message}";
            }

            return target; // 병합된 딕셔너리 반환
        }
    }
}