// [AuthHive.Auth] CreateUserCommandHandler.cs
// v17 CQRS "본보기": 플랫폼에 신규 사용자를 생성하는 'CreateUserCommand'를 처리합니다.
// 이 핸들러는 유효성 검사를 IUserValidator에 위임하고,
// UserService.CreateAsync의 기존 로직을 이관받아 수행합니다.

using AuthHive.Core.Entities.User;
using AuthHive.Core.Enums.Core;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Infra.Security; // IPasswordHashProvider
using AuthHive.Core.Interfaces.Security;
using AuthHive.Core.Interfaces.User.Repository;
using AuthHive.Core.Interfaces.User.Validator; // v17 Validator 주입
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Events.Lifecycle; // v17 UserAccountCreatedEvent
using AuthHive.Core.Models.User.Responses;
using MediatR;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations; // ValidationException
using UserEntity = AuthHive.Core.Entities.User.User; // 별칭(Alias) 사용

namespace AuthHive.Auth.Handlers.User
{
    /// <summary>
    /// [v17 리팩토링] "사용자 생성" 유스케이스 핸들러 (본보기)
    /// 유효성 검사 로직을 IUserValidator로 분리합니다.
    /// </summary>
    public class CreateUserCommandHandler : IRequestHandler<CreateUserCommand, UserDetailResponse>
    {
        private readonly IUserRepository _userRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IPasswordHashProvider _passwordProvider;
        private readonly IMediator _mediator;
        private readonly ILogger<CreateUserCommandHandler> _logger;
        private readonly IUserValidator _userValidator; 

        public CreateUserCommandHandler(
            IUserRepository userRepository,
            IUnitOfWork unitOfWork,
            IPasswordHashProvider passwordProvider,
            IMediator mediator,
            ILogger<CreateUserCommandHandler> logger,
            IUserValidator userValidator) 
        {
            _userRepository = userRepository;
            _unitOfWork = unitOfWork;
            _passwordProvider = passwordProvider;
            _mediator = mediator;
            _logger = logger;
            _userValidator = userValidator;
        }

        public async Task<UserDetailResponse> Handle(CreateUserCommand command, CancellationToken cancellationToken)
        {
            // [v17 수정] 로거 메시지에서 한글 제거
            _logger.LogInformation("Handling CreateUserCommand for {Email}", command.Email);

            // 1. 유효성 검사 (Validator로 책임 이관)
            // 핸들러가 직접 검사하지 않고 Validator에 위임
            var validationResult = await _userValidator.ValidateCreateAsync(command);
            if (!validationResult.IsSuccess)
            {
                // 실패 시, ServiceResult의 오류 메시지를 사용해 예외 발생
                throw new ValidationException(validationResult.ErrorMessage ?? "User validation failed.");
            }

            // 2. 비밀번호 해싱 (핸들러의 책임)
            string? passwordHash = null;
            if (!string.IsNullOrEmpty(command.Password))
            {
                passwordHash = await _passwordProvider.HashPasswordAsync(command.Password);
            }

            // 3. 엔티티 매핑 (핸들러의 책임)
            var newUser = new UserEntity
            {
                Email = command.Email,
                Username = command.Username,
                DisplayName = command.DisplayName,
                ExternalUserId = command.ExternalUserId,
                ExternalSystemType = command.ExternalSystemType,
                PasswordHash = passwordHash,
                Status = UserEnums.UserStatus.PendingVerification, // v16 UserService 로직 참조
                IsEmailVerified = false,
                IsTwoFactorEnabled = false,
                FailedLoginAttempts = 0,
                IsAccountLocked = false
            };

            // 4. 데이터베이스 저장 (핸들러의 책임)
            await _userRepository.AddAsync(newUser, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken); 

            _logger.LogInformation("New user created successfully: {UserId} (Email: {Email})", newUser.Id, newUser.Email);

            // 5. 이벤트 발행 (핸들러의 책임)
            var regMethod = !string.IsNullOrEmpty(command.ExternalSystemType) 
                ? command.ExternalSystemType 
                : "Email";

            var userCreatedEvent = new UserAccountCreatedEvent(
                userId: newUser.Id,
                email: newUser.Email,
                createdByConnectedId: null, // 플랫폼 가입은 '본인'이므로 null
                invitedByUserId: null,
                registrationMethod: regMethod,
                emailVerified: newUser.IsEmailVerified,
                requiresAdditionalSetup: false,
                source: "UserCommandHandler" // v17 표준
            );
            await _mediator.Publish(userCreatedEvent, cancellationToken);

            // 6. 응답 DTO 반환 (핸들러의 책임)
            return new UserDetailResponse
            {
                Id = newUser.Id, // required
                Email = newUser.Email,
                Username = newUser.Username,
                DisplayName = newUser.DisplayName,
                Status = newUser.Status,
                EmailVerified = newUser.IsEmailVerified,
                IsTwoFactorEnabled = newUser.IsTwoFactorEnabled,
                CreatedAt = newUser.CreatedAt,
                UpdatedAt = newUser.UpdatedAt,
                ExternalUserId = newUser.ExternalUserId,
                ExternalSystemType = newUser.ExternalSystemType,
                Profile = null, // Profile 생성은 이 핸들러의 책임이 아님
                Organizations = new (), // 조직 연결은 이 핸들러의 책임이 아님
                ActiveSessionCount = 0,
                TotalConnectedIdCount = 0
            };
        }
    }
}