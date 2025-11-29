using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json; // JSON 검증용
using FluentValidation; 

// [Interfaces]
using AuthHive.Core.Interfaces.User.Validators;

// [Models]
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.User.Commands.Settings;

namespace AuthHive.Auth.Validators.User;

public class UserFeatureProfileValidator : AbstractValidator<UpdateUserFeatureProfileCommand>, IUserFeatureProfileValidator
{
    public UserFeatureProfileValidator()
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage("User ID is required.");

        // JSON 필드는 값이 있을 때만 유효성 검사
        RuleFor(x => x.FeaturePreferencesJson)
            .Must(BeValidJson)
            .When(x => !string.IsNullOrWhiteSpace(x.FeaturePreferencesJson))
            .WithMessage("Feature preferences must be a valid JSON string.");

        RuleFor(x => x.BetaFeaturesJson)
            .Must(BeValidJson)
            .When(x => !string.IsNullOrWhiteSpace(x.BetaFeaturesJson))
            .WithMessage("Beta features list must be a valid JSON string.");
    }

    public async Task<ValidationResult> ValidateUpdateAsync(UpdateUserFeatureProfileCommand command, CancellationToken cancellationToken = default)
    {
        var result = await ValidateAsync(command, cancellationToken);
        
        if (result.IsValid) return ValidationResult.Success();
        
        return ValidationResult.Failure(result.Errors.Select(e => e.ErrorMessage));
    }

    // JSON 유효성 검사 헬퍼
    private bool BeValidJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}