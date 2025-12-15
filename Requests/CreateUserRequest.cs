using System.ComponentModel.DataAnnotations;

namespace AuthHive.Auth.Models.Requests;

/// <summary>
/// [API Input] 회원가입 요청 DTO
/// 보안상 안전한 필드(사용자 입력값)만 정의합니다.
/// </summary>
public record CreateUserRequest(
    [Required] [EmailAddress] string Email,
    [Required] string Password,
    string? Username,
    [Phone] string? PhoneNumber,
    string? DisplayName
);