using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation; // IValidator<T>

// [Interfaces]
using AuthHive.Core.Interfaces.User.Validator; // IUserValidator (Core)

// [Models]
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.Common.Validation; // ValidationResult (Core)

namespace AuthHive.Auth.Validators.User;

/// <summary>
/// [Auth] UserValidator (Facade)
/// 개별 Command Validator들을 조립하여 IUserValidator 인터페이스를 구현합니다.
/// </summary>
public class UserValidator : IUserValidator
{
    // 1:1 Validator들을 주입받습니다. (FluentValidation 인터페이스)
    // 1:1 Validator들을 주입받습니다. (FluentValidation 인터페이스)
    private readonly IValidator<CreateUserCommand> _createValidator;
    private readonly IValidator<UpdateUserCommand> _updateValidator;
    private readonly IValidator<CreateUserSuspensionCommand> _suspendValidator;
    private readonly IValidator<UpdateUserProfileCommand> _profileUpdateValidator;
    private readonly IValidator<UpdateUserFeatureProfileCommand> _featureProfileUpdateValidator;

    public UserValidator(
        IValidator<CreateUserCommand> createValidator,
        IValidator<UpdateUserCommand> updateValidator,
        IValidator<CreateUserSuspensionCommand> suspendValidator,
        IValidator<UpdateUserProfileCommand> profileUpdateValidator,
        IValidator<UpdateUserFeatureProfileCommand> featureProfileUpdateValidator)
    {
        _createValidator = createValidator;
        _updateValidator = updateValidator;
        _suspendValidator = suspendValidator;
        _profileUpdateValidator = profileUpdateValidator;
        _featureProfileUpdateValidator = featureProfileUpdateValidator;
    }
    // 1. Create 검증 위임
    public async Task<ValidationResult> ValidateCreateAsync(CreateUserCommand command, CancellationToken cancellationToken = default)
    {
        var result = await _createValidator.ValidateAsync(command, cancellationToken);
        return MapToCoreResult(result);
    }

    // 2. Update 검증 위임
    public async Task<ValidationResult> ValidateUpdateAsync(UpdateUserCommand command, CancellationToken cancellationToken = default)
    {
        var result = await _updateValidator.ValidateAsync(command, cancellationToken);
        return MapToCoreResult(result);
    }

    // 3. Suspend 검증 위임 (CS0535 해결)
    public async Task<ValidationResult> ValidateSuspendAsync(CreateUserSuspensionCommand command, CancellationToken cancellationToken = default)
    {
        var result = await _suspendValidator.ValidateAsync(command, cancellationToken);
        return MapToCoreResult(result);
    }
    // 4. Feature Profile Update 검증 위임
    public async Task<ValidationResult> ValidateFeatureProfileUpdateAsync(UpdateUserFeatureProfileCommand command, CancellationToken cancellationToken = default)
    {
        var result = await _featureProfileUpdateValidator.ValidateAsync(command, cancellationToken);
        return MapToCoreResult(result);
    }
    public async Task<ValidationResult> ValidateProfileUpdateAsync(UpdateUserProfileCommand command, CancellationToken cancellationToken = default)
    {
        var result = await _profileUpdateValidator.ValidateAsync(command, cancellationToken);
        return MapToCoreResult(result);
    }
    // --- 기타 특화 메서드 (필요하다면 직접 구현하거나 별도 Validator 위임) ---
    public Task<ValidationResult> ValidateEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        // 단순 로직은 여기서 처리해도 무방
        if (string.IsNullOrWhiteSpace(email) || !email.Contains("@"))
            return Task.FromResult(ValidationResult.Failure("Invalid email format."));

        return Task.FromResult(ValidationResult.Success());
    }

    public Task<ValidationResult> ValidateUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username))
            return Task.FromResult(ValidationResult.Failure("Username required."));

        return Task.FromResult(ValidationResult.Success());
    }

    // --- Helper ---
    private static ValidationResult MapToCoreResult(FluentValidation.Results.ValidationResult result)
    {
        if (result.IsValid) return ValidationResult.Success();

        var errors = result.Errors.Select(e => e.ErrorMessage).ToList();
        return ValidationResult.Failure(errors);
    }
}