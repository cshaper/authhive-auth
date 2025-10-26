using System;
using System.Linq;
using System.Linq.Expressions;

namespace AuthHive.Auth.Extensions
{
    /// <summary>
    /// LINQ Expression<Func<T, bool>> 타입의 Predicate(조건자)를 조합하는 확장 메서드를 제공합니다.
    /// 동적 쿼리 생성을 용이하게 합니다.
    /// </summary>
    public static class PredicateBuilder
    {
        /// <summary>
        /// 항상 true를 반환하는 기본 Predicate를 생성합니다. And 연산의 시작점으로 유용합니다.
        /// </summary>
        public static Expression<Func<T, bool>> True<T>() { return f => true; }

        /// <summary>
        /// 항상 false를 반환하는 기본 Predicate를 생성합니다. Or 연산의 시작점으로 유용합니다.
        /// </summary>
        public static Expression<Func<T, bool>> False<T>() { return f => false; }

        /// <summary>
        /// 두 개의 Predicate를 논리적 OR (||) 연산으로 조합합니다.
        /// </summary>
        /// <param name="expr1">첫 번째 Predicate</param>
        /// <param name="expr2">두 번째 Predicate</param>
        /// <returns>조합된 새로운 Predicate</returns>
        public static Expression<Func<T, bool>> Or<T>(this Expression<Func<T, bool>> expr1, Expression<Func<T, bool>> expr2)
        {
            // 두 번째 표현식의 파라미터를 첫 번째 표현식의 파라미터로 치환하여 호출하는 Expression 생성
            var invokedExpr = Expression.Invoke(expr2, expr1.Parameters.Cast<Expression>());
            // 두 표현식의 Body를 OrElse 연산으로 연결하고, 새 Lambda Expression 생성
            return Expression.Lambda<Func<T, bool>>(Expression.OrElse(expr1.Body, invokedExpr), expr1.Parameters);
        }

        /// <summary>
        /// 두 개의 Predicate를 논리적 AND (&&) 연산으로 조합합니다.
        /// </summary>
        /// <param name="expr1">첫 번째 Predicate</param>
        /// <param name="expr2">두 번째 Predicate</param>
        /// <returns>조합된 새로운 Predicate</returns>
        public static Expression<Func<T, bool>> And<T>(this Expression<Func<T, bool>> expr1, Expression<Func<T, bool>> expr2)
        {
            // 두 번째 표현식의 파라미터를 첫 번째 표현식의 파라미터로 치환하여 호출하는 Expression 생성
            var invokedExpr = Expression.Invoke(expr2, expr1.Parameters.Cast<Expression>());
            // 두 표현식의 Body를 AndAlso 연산으로 연결하고, 새 Lambda Expression 생성
            return Expression.Lambda<Func<T, bool>>(Expression.AndAlso(expr1.Body, invokedExpr), expr1.Parameters);
        }
    }
}