// Path: AuthHive.Auth/Controllers/v1/AuthController.cs
using Microsoft.AspNetCore.Mvc;
using AuthHive.Core.Interfaces.Auth.Service;
using AuthHive.Core.Models.Auth.Authentication.Responses;
using AuthHive.Core.Models.Auth.Authentication.Requests;
using System.ComponentModel.DataAnnotations;

namespace AuthHive.Auth.Controllers.v1
{
    [ApiController]
    [Route("api/v1/auth")]
    [Produces("application/json")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthenticationService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthenticationService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// 사용자 회원가입
        /// </summary>
        /// <param name="request">회원가입 요청 정보</param>
        /// <returns>인증 정보</returns>
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthenticationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await _authService.RegisterAsync(request.Email, request.Password, request.DisplayName);
            if (!result.IsSuccess)
            {
                return BadRequest(new ProblemDetails { Title = "Registration failed", Detail = result.ErrorMessage });
            }
            return Ok(result.Data);
        }
        
        /// <summary>
        /// 이메일/패스워드 로그인
        /// </summary>
        /// <param name="request">로그인 요청 정보</param>
        /// <returns>인증 정보</returns>
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthenticationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var result = await _authService.AuthenticateWithPasswordAsync(request.Email, request.Password, request.OrganizationId);
            if (!result.IsSuccess)
            {
                return Unauthorized(new ProblemDetails { Title = "Login failed", Detail = result.ErrorMessage });
            }
            return Ok(result.Data);
        }

        /// <summary>
        /// 소셜 로그인
        /// </summary>
        /// <param name="request">소셜 로그인 요청 정보</param>
        /// <returns>인증 정보</returns>
        [HttpPost("social-login")]
        [ProducesResponseType(typeof(AuthenticationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> SocialLogin([FromBody] SocialLoginRequest request)
        {
            var result = await _authService.AuthenticateWithSocialAsync(request.Provider, request.Token, request.OrganizationId);
            if (!result.IsSuccess)
            {
                return Unauthorized(new ProblemDetails { Title = "Social login failed", Detail = result.ErrorMessage });
            }
            return Ok(result.Data);
        }

        /// <summary>
        /// 토큰 유효성 검증
        /// </summary>
        /// <param name="request">토큰 검증 요청 정보</param>
        /// <returns>검증 결과</returns>
        [HttpPost("validate-token")]
        [ProducesResponseType(typeof(TokenValidationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> ValidateToken([FromBody] ValidateTokenRequest request)
        {
            var result = await _authService.ValidateTokenAsync(request.Token);
            if (!result.IsSuccess || result.Data == null || !result.Data.IsValid)
            {
                return Unauthorized(new ProblemDetails { Title = "Token validation failed", Detail = "Invalid or expired token." });
            }
            return Ok(result.Data);
        }
        
        // Logout과 같은 다른 엔드포인트들은 필요에 따라 여기에 추가할 수 있습니다.
    }

}