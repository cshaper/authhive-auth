using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation; // RuleFor

// [Interfaces]
using AuthHive.Core.Interfaces.User.Validator; // IUserValidator
using AuthHive.Core.Interfaces.User.Repository;

// [Models]
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.Common.Validation; // ValidationResult

namespace AuthHive.Auth.Validators.User;

public class CreateUserCommandValidator : AbstractValidator<CreateUserCommand>
{
    private readonly IUserRepository _userRepository;

    public CreateUserCommandValidator(IUserRepository userRepository)
    {
        _userRepository = userRepository;

        // 1. FluentValidation 규칙 정의
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Invalid email format.")
            .MustAsync(BeUniqueEmail).WithMessage("Email is already taken.");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required.")
            .MinimumLength(8).WithMessage("Password must be at least 8 characters.");

        RuleFor(x => x.PhoneNumber)
            .Matches(@"^\+?[1-9]\d{1,14}$").When(x => !string.IsNullOrEmpty(x.PhoneNumber))
            .WithMessage("Invalid phone number format.");
    }

    private async Task<bool> BeUniqueEmail(string email, CancellationToken cancellationToken)
    {
        return !await _userRepository.ExistsByEmailAsync(email, cancellationToken);
    }

    // 2. IUserValidator 인터페이스 구현 (Handler에서 호출)
    public async Task<ValidationResult> ValidateCreateAsync(CreateUserCommand command, CancellationToken cancellationToken = default)
    {
        // FluentValidation 실행
        var result = await this.ValidateAsync(command, cancellationToken);

        if (result.IsValid) return ValidationResult.Success();

        var errors = result.Errors.Select(e => e.ErrorMessage).ToList();
        return ValidationResult.Failure(errors);
    }

    
    public Task<ValidationResult> ValidateEmailAsync(string email, CancellationToken cancellationToken = default) => Task.FromResult(ValidationResult.Success());
    public Task<ValidationResult> ValidateUsernameAsync(string username, CancellationToken cancellationToken = default) => Task.FromResult(ValidationResult.Success());
}