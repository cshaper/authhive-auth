using AuthHive.Core.Models.Common;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.Json;

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

       private ServiceResult CreateErrorResponse(HttpStatusCode statusCode, string errorCode, string message)
       {
           var result = ServiceResult.Failure(message, errorCode);
           
           // Development 환경에서만 상세 스택 트레이스 포함
           if (_environment.IsDevelopment() && result.Metadata == null)
           {
               result.Metadata = new Dictionary<string, object>();
           }

           return result;
       }

       private ServiceResult CreateValidationErrorResponse(ValidationException validationException)
       {
           var validationErrors = new Dictionary<string, List<string>>();
           
           // ValidationException에서 필드별 에러 추출
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
               // 기본 검증 에러
               validationErrors.Add("ValidationError", new List<string> { validationException.Message });
           }

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
               "TIMEOUT" => HttpStatusCode.RequestTimeout,
               "REQUEST_CANCELLED" => HttpStatusCode.RequestTimeout,
               "CONFLICT" => HttpStatusCode.Conflict,
               "TOO_MANY_REQUESTS" => HttpStatusCode.TooManyRequests,
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