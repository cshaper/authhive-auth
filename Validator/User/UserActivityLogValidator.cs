using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation;
using AuthHive.Core.Interfaces.User.Validator;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.Common.Validation;

namespace AuthHive.Auth.Validators.User;

public class UserActivityLogValidator : AbstractValidator<CreateUserActivityLogCommand>, IUserActivityLogValidator
{
    public UserActivityLogValidator()
    {
        // 활동 타입은 필수
        RuleFor(x => x.ActivityType).IsInEnum();

        // DB 스키마(StringLength) 보호를 위한 길이 검증
        RuleFor(x => x.Description).MaximumLength(500);
        RuleFor(x => x.ResourceType).MaximumLength(50);
        RuleFor(x => x.ResourceId).MaximumLength(100);
        RuleFor(x => x.IpAddress).MaximumLength(45);
        RuleFor(x => x.UserAgent).MaximumLength(500);
        RuleFor(x => x.ErrorMessage).MaximumLength(1000); // DB 스키마 확인 필요
    }

    public async Task<ValidationResult> ValidateCreateAsync(CreateUserActivityLogCommand command, CancellationToken cancellationToken = default)
    {
        var result = await ValidateAsync(command, cancellationToken);
        
        if (result.IsValid) return ValidationResult.Success();
        
        return ValidationResult.Failure(result.Errors.Select(e => e.ErrorMessage));
    }
}