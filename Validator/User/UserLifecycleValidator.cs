using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using FluentValidation;

// [Core Interfaces] 이름 바뀐 네임스페이스들 적용 (Validators, Repositories)
using AuthHive.Core.Interfaces.User.Validators; 
using AuthHive.Core.Interfaces.User.Repositories; 

// [Core Models]
using AuthHive.Core.Models.User.Commands.Lifecycle;
using AuthHive.Core.Models.Common.Validation;
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Validators.User;

public class UserLifecycleValidator : AbstractValidator<CreateUserCommand>, IUserLifecycleValidator
{
    // [규칙 적용] IUserRepository는 Repositories 네임스페이스에 있습니다.
    private readonly IUserRepository _userRepository;

    public UserLifecycleValidator(IUserRepository userRepository)
    {
        _userRepository = userRepository;
        
        // ... (RuleFor 규칙들은 동일) ...
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Invalid email format.")
            .MustAsync(BeUniqueEmail).WithMessage("Email is already taken.");
    }

    private async Task<bool> BeUniqueEmail(string email, CancellationToken cancellationToken)
    {
        return !await _userRepository.ExistsByEmailAsync(email, cancellationToken);
    }

    // --- 인터페이스 구현 ---

    public async Task<ValidationResult> ValidateCreateAsync(CreateUserCommand command, CancellationToken cancellationToken = default)
    {
        var result = await this.ValidateAsync(command, cancellationToken);
        return MapToCoreResult(result);
    }

    public Task<ValidationResult> ValidateDeleteAsync(UserEntity user, CancellationToken cancellationToken = default)
    {
        if (user.IsDeleted)
        {
            return Task.FromResult(ValidationResult.Failure("User is already deleted."));
        }
        return Task.FromResult(ValidationResult.Success());
    }

    public Task<ValidationResult> ValidateSuspendAsync(CreateUserSuspensionCommand command, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.Reason))
        {
             return Task.FromResult(ValidationResult.Failure("Suspension reason is required."));
        }
        return Task.FromResult(ValidationResult.Success());
    }

    private static ValidationResult MapToCoreResult(FluentValidation.Results.ValidationResult result)
    {
        if (result.IsValid) return ValidationResult.Success();
        var errors = result.Errors.Select(e => e.ErrorMessage).ToList();
        return ValidationResult.Failure(errors);
    }
}