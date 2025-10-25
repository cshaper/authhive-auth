using System.Collections.Generic;
using System.Linq;

namespace AuthHive.Auth.Extensions
{
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
                target[kvp.Key] = kvp.Value;
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
                kvp => kvp.Value?.ToString() ?? string.Empty
            );
        }
    }
}