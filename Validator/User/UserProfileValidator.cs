using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation;
using AuthHive.Core.Interfaces.User.Validators;
using AuthHive.Core.Interfaces.User.Repositories;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.User.Commands.Profile;

namespace AuthHive.Auth.Validators.User;

/// <summary>
/// [Auth] 사용자 프로필 검증 구현체 (IUserProfileValidator + FluentValidation)
/// </summary>
public class UserProfileValidator : AbstractValidator<CreateUserProfileCommand>, IUserProfileValidator
{
    private readonly IUserProfileRepository _profileRepository;
    private readonly IUserRepository _userRepository;

    public UserProfileValidator(
        IUserProfileRepository profileRepository,
        IUserRepository userRepository)
    {
        _profileRepository = profileRepository;
        _userRepository = userRepository;

        // [CreateUserProfileCommand 규칙]
        RuleFor(x => x.UserId)
            .NotEmpty()
            .MustAsync(UserMustExist).WithMessage("User does not exist.")
            .MustAsync(ProfileMustNotExist).WithMessage("User profile already exists.");
        
        // ... (나머지 길이 및 URL 규칙은 동일하게 적용) ...

        RuleFor(x => x.Bio).MaximumLength(1000);
        RuleFor(x => x.Location).MaximumLength(100);
        
        RuleFor(x => x.WebsiteUrl)
            .Must(BeAValidUrl).When(x => !string.IsNullOrEmpty(x.WebsiteUrl))
            .WithMessage("Invalid Website URL format.");

        RuleFor(x => x.ProfileImageUrl)
            .Must(BeAValidUrl).When(x => !string.IsNullOrEmpty(x.ProfileImageUrl))
            .WithMessage("Invalid Profile Image URL format.");
    }
    
    // IUserProfileValidator 인터페이스 구현
    public async Task<ValidationResult> ValidateCreateAsync(CreateUserProfileCommand command, CancellationToken cancellationToken = default)
    {
        var result = await ValidateAsync(command, cancellationToken);
        return MapToCoreResult(result);
    }
    
    // UpdateUserProfileCommand는 아직 없으므로 임시 구현
    public Task<ValidationResult> ValidateUpdateAsync(UpdateUserProfileCommand command, CancellationToken cancellationToken = default)
    {
         // Update Command가 준비되면 여기에 로직을 채워 넣습니다.
         return Task.FromResult(ValidationResult.Success()); 
    }
    
    // ... (UserMustExist, ProfileMustNotExist, BeAValidUrl 헬퍼 메서드 생략) ...
    
    private bool BeAValidUrl(string? url)
    {
        return Uri.TryCreate(url, UriKind.Absolute, out var uriResult)
               && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
    }
    
    private async Task<bool> UserMustExist(Guid userId, CancellationToken token)
    {
        return await _userRepository.ExistsAsync(userId, token);
    }

    private async Task<bool> ProfileMustNotExist(Guid userId, CancellationToken token)
    {
        var exists = await _profileRepository.GetByUserIdAsync(userId, token);
        return exists == null;
    }

    private static ValidationResult MapToCoreResult(FluentValidation.Results.ValidationResult result)
    {
        if (result.IsValid) return ValidationResult.Success();
        var errors = result.Errors.Select(e => e.ErrorMessage).ToList();
        return ValidationResult.Failure(errors);
    }
}