using System;
using System.Linq.Expressions;

namespace AuthHive.Auth.Extensions
{
    /// <summary>
    /// LINQ 표현식 트리에서 속성 이름을 안전하게 추출하는 확장 메서드를 제공합니다.
    /// 주로 통계 쿼리 등에서 동적으로 속성 이름을 참조할 때 사용됩니다.
    /// </summary>
    public static class ExpressionExtensions
    {
        /// <summary>
        /// 멤버 접근 람다 표현식 (예: x => x.PropertyName) 에서 속성 이름을 가져옵니다.
        /// Convert(x.EnumProperty)와 같은 박싱/언박싱 표현식도 처리합니다.
        /// </summary>
        /// <typeparam name="T">엔티티 또는 객체의 타입</typeparam>
        /// <typeparam name="TProperty">속성의 타입</typeparam>
        /// <param name="expression">멤버에 접근하는 람다 표현식</param>
        /// <returns>추출된 속성 이름</returns>
        /// <exception cref="ArgumentException">표현식이 멤버 접근 식이 아닐 경우 발생</exception>
        public static string GetPropertyName<T, TProperty>(this Expression<Func<T, TProperty>> expression)
        {
            // 기본적인 멤버 접근 (예: x => x.Name)
            if (expression.Body is MemberExpression memberExpression)
            {
                return memberExpression.Member.Name;
            }

            // 값 타입이나 열거형 등이 object로 변환되는 경우 (예: x => (object)x.Status)
            // UnaryExpression (Convert) 안에 MemberExpression이 있습니다.
            if (expression.Body is UnaryExpression unaryExpression && unaryExpression.Operand is MemberExpression operand)
            {
                return operand.Member.Name;
            }

            // 위 두 경우가 아니면 지원하지 않는 표현식 형태
            throw new ArgumentException($"표현식 '{expression}'은 멤버 속성을 참조해야 합니다.", nameof(expression));
        }
    }
}