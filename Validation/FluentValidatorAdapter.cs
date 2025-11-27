using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Models.Common.Validation;

namespace AuthHive.Auth.Validation; // 네임스페이스 주의

/// <summary>
/// FluentValidation을 Core.IValidator 인터페이스에 맞게 감싸는 어댑터
/// </summary>
public class FluentValidatorAdapter<T> : AuthHive.Core.Interfaces.Base.IValidator<T>
{
    private readonly FluentValidation.IValidator<T> _fluentValidator;

    public FluentValidatorAdapter(FluentValidation.IValidator<T> fluentValidator)
    {
        _fluentValidator = fluentValidator;
    }

    public async Task<ValidationResult> ValidateAsync(T entity, CancellationToken cancellationToken = default)
    {
        var result = await _fluentValidator.ValidateAsync(entity, cancellationToken);
        if (result.IsValid) return ValidationResult.Success();

        var errors = result.Errors.Select(e => e.ErrorMessage).ToList();
        return ValidationResult.Failure(errors);
    }
}