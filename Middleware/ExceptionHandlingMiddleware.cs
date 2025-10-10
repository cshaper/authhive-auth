using AuthHive.Core.Constants.Business;
using AuthHive.Core.Models.Common;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;

namespace AuthHive.Auth.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;
        private readonly IWebHostEnvironment _environment;

        public ExceptionHandlingMiddleware(
            RequestDelegate next,
            ILogger<ExceptionHandlingMiddleware> logger,
            IWebHostEnvironment environment)
        {
            _next = next;
            _logger = logger;
            _environment = environment;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred");
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            var response = context.Response;
            response.ContentType = "application/json";

            var serviceResult = exception switch
            {
                AuthHiveValidationException validationEx => CreateErrorResponse(
                    HttpStatusCode.BadRequest,
                    validationEx.ErrorCode,
                    validationEx.Message,
                    validationEx.ValidationErrors),
                AuthHiveException authEx => CreateErrorResponse(
                    authEx.StatusCode,
                    authEx.ErrorCode,
                    authEx.Message),
                ValidationException validationEx => CreateValidationErrorResponse(validationEx),
                UnauthorizedAccessException => CreateErrorResponse(
                    HttpStatusCode.Unauthorized,
                    "UNAUTHORIZED",
                    "Access denied"),
                KeyNotFoundException => CreateErrorResponse(
                    HttpStatusCode.NotFound,
                    "NOT_FOUND",
                    "Resource not found"),
                ArgumentException argEx => CreateErrorResponse(
                    HttpStatusCode.BadRequest,
                    "BAD_REQUEST",
                    argEx.Message),
                InvalidOperationException invalidOpEx => CreateErrorResponse(
                    HttpStatusCode.BadRequest,
                    "INVALID_OPERATION",
                    invalidOpEx.Message),
                TimeoutException => CreateErrorResponse(
                    HttpStatusCode.RequestTimeout,
                    "TIMEOUT",
                    "Request timeout"),
                TaskCanceledException => CreateErrorResponse(
                    HttpStatusCode.RequestTimeout,
                    "REQUEST_CANCELLED",
                    "Request was cancelled"),

                _ => CreateErrorResponse(
                    HttpStatusCode.InternalServerError,
                    "INTERNAL_ERROR",
                    "An internal server error occurred")
            };

            response.StatusCode = (int)GetStatusCodeFromErrorCode(serviceResult.ErrorCode);

            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = _environment.IsDevelopment()
            };

            var jsonResponse = JsonSerializer.Serialize(serviceResult, jsonOptions);
            await response.WriteAsync(jsonResponse);
        }

        private ServiceResult CreateErrorResponse(
                    HttpStatusCode statusCode,
                    string errorCode,
                    string message,
                    Dictionary<string, List<string>>? validationErrors = null)
        {
            if (validationErrors?.Count > 0)
            {
                return ServiceResult.ValidationFailure(validationErrors);
            }

            var result = ServiceResult.Failure(message, errorCode);

            // Development 환경에서만 상세 스택 트레이스 포함 (기존 로직 유지)
            if (_environment.IsDevelopment())
            {
                // NOTE: 실제 구현에서는 exception.StackTrace를 result.Metadata에 추가하는 로직이 필요합니다.
                if (result.Metadata == null)
                    result.Metadata = new Dictionary<string, object>();

                result.Metadata["StatusCode"] = (int)statusCode;
            }

            return result;
        }

        private ServiceResult CreateValidationErrorResponse(ValidationException validationException)
        {
            var validationErrors = new Dictionary<string, List<string>>();

            // Data 컬렉션에서 필드별 에러 추출 로직 (기존 로직 유지)
            if (validationException.Data.Count > 0)
            {
                foreach (var key in validationException.Data.Keys)
                {
                    var fieldName = key.ToString();
                    var errorMessage = validationException.Data[key]?.ToString();

                    if (!string.IsNullOrEmpty(fieldName) && !string.IsNullOrEmpty(errorMessage))
                    {
                        if (!validationErrors.ContainsKey(fieldName))
                            validationErrors[fieldName] = new List<string>();

                        validationErrors[fieldName].Add(errorMessage);
                    }
                }
            }
            else
            {
                validationErrors.Add("ValidationError", new List<string> { validationException.Message });
            }

            // AuthHiveValidationException의 생성자가 Dictionary를 받으므로, 
            // 여기서는 ServiceResult.ValidationFailure을 직접 호출합니다.
            return ServiceResult.ValidationFailure(validationErrors);
        }

        private HttpStatusCode GetStatusCodeFromErrorCode(string? errorCode)
        {
            return errorCode switch
            {
                "UNAUTHORIZED" => HttpStatusCode.Unauthorized,
                "FORBIDDEN" => HttpStatusCode.Forbidden,
                "NOT_FOUND" => HttpStatusCode.NotFound,
                "BAD_REQUEST" => HttpStatusCode.BadRequest,
                "VALIDATION_ERROR" => HttpStatusCode.BadRequest,
                "INVALID_OPERATION" => HttpStatusCode.BadRequest,
                "CONFLICT" => HttpStatusCode.Conflict,
                "TIMEOUT" or "REQUEST_CANCELLED" => HttpStatusCode.RequestTimeout,
                "TOO_MANY_REQUESTS" => HttpStatusCode.TooManyRequests,
                // "UPGRADE_REQUIRED" (FeatureRestrictionException)는 Forbidden을 반환해야 함
                "UPGRADE_REQUIRED" => HttpStatusCode.Forbidden,
                _ => HttpStatusCode.InternalServerError
            };
        }
    }
    // 커스텀 예외 클래스들 (필요시 추가)
    public class AuthHiveException : Exception
    {
        public string ErrorCode { get; }
        public HttpStatusCode StatusCode { get; }

        public AuthHiveException(string errorCode, string message, HttpStatusCode statusCode = HttpStatusCode.BadRequest)
            : base(message)
        {
            ErrorCode = errorCode;
            StatusCode = statusCode;
        }
    }

    /// <summary>
    /// 플랜 제한 또는 기능 토글 비활성화로 인해 접근이 거부되었을 때 발생하는 예외.
    /// PricingConstants.UpgradeRequired 오류 코드를 사용합니다.
    /// </summary>
    public class FeatureRestrictionException : AuthHiveException
    {
        // ⭐️ 2개의 인수를 받도록 수정
        public FeatureRestrictionException(string errorCode, string message)
            : base(errorCode,
                   message,
                   HttpStatusCode.Forbidden)
        {
        }
    }
    public class AuthHiveValidationException : AuthHiveException
    {
        public Dictionary<string, List<string>> ValidationErrors { get; }

        public AuthHiveValidationException(Dictionary<string, List<string>> validationErrors)
            : base("VALIDATION_ERROR", "Validation failed", HttpStatusCode.BadRequest)
        {
            ValidationErrors = validationErrors;
        }
    }

    public class AuthHiveUnauthorizedException : AuthHiveException
    {
        public AuthHiveUnauthorizedException(string message = "Unauthorized access")
            : base("UNAUTHORIZED", message, HttpStatusCode.Unauthorized)
        {
        }
    }

    public class AuthHiveForbiddenException : AuthHiveException
    {
        public AuthHiveForbiddenException(string message = "Access forbidden")
            : base("FORBIDDEN", message, HttpStatusCode.Forbidden)
        {
        }
    }

    public class AuthHiveNotFoundException : AuthHiveException
    {
        public AuthHiveNotFoundException(string message = "Resource not found")
            : base("NOT_FOUND", message, HttpStatusCode.NotFound)
        {
        }
    }
}