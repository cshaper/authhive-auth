using System;
using FluentValidation;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Models.User.Commands.Lifecycle;

namespace AuthHive.Auth.Validators.User;

/// <summary>
/// [Auth] 사용자 정지 명령 전용 검증기
/// </summary>
public class SuspendUserCommandValidator : AbstractValidator<CreateUserSuspensionCommand>
{
    public SuspendUserCommandValidator()
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage("User ID is required.");

        RuleFor(x => x.Reason)
            .NotEmpty().WithMessage("Suspension reason is required.")
            .MaximumLength(500).WithMessage("Reason cannot exceed 500 characters.");

        RuleFor(x => x.SuspendedUntil)
            .Must(date => date == null || date > DateTime.UtcNow)
            .WithMessage("Suspension end date must be in the future.");
    }
}