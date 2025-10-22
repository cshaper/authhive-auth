using System;
using System.Text.Json;
using Microsoft.Extensions.Logging; // ILogger 사용 위해 추가 (선택적)

namespace AuthHive.Auth.Extensions // ✨ 네임스페이스 확인
{
    /// <summary>
    /// JSON 문자열 관련 확장 메서드를 제공합니다.
    /// </summary>
    public static class JsonExtensions
    {
        // ILogger를 정적으로 주입받거나 LoggerFactory 사용 (선택적)
        // private static readonly ILogger _logger = /* 로거 인스턴스 가져오기 */;

        /// <summary>
        /// JSON 문자열을 지정된 타입 T 객체로 역직렬화합니다.
        /// 실패 시 null을 반환하고 경고 로그를 기록합니다. (로거 설정 필요)
        /// </summary>
        /// <typeparam name="T">역직렬화할 대상 타입 (클래스)</typeparam>
        /// <param name="json">역직렬화할 JSON 문자열</param>
        /// <param name="logger">로깅을 위한 ILogger 인스턴스 (선택적)</param>
        /// <returns>역직렬화된 객체 또는 null</returns>
        public static T? DeserializeJson<T>(this string? json, ILogger? logger = null) where T : class
        {
            if (string.IsNullOrEmpty(json))
            {
                return null;
            }

            try
            {
                // 표준 System.Text.Json 사용
                return JsonSerializer.Deserialize<T>(json);
            }
            catch (JsonException ex)
            {
                // 로거가 제공되면 경고 기록
                logger?.LogWarning(ex, "Failed to deserialize JSON string to type {TypeName}. JSON: {JsonString}", typeof(T).Name, json);
                return null; // 실패 시 null 반환
            }
            catch (Exception ex) // 그 외 예외 처리
            {
                 logger?.LogError(ex, "Unexpected error during JSON deserialization to type {TypeName}. JSON: {JsonString}", typeof(T).Name, json);
                 return null;
            }
        }
    }
}