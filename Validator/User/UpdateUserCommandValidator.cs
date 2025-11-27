using FluentValidation;
using AuthHive.Core.Models.User.Commands;

namespace AuthHive.Auth.Validators.User;

public class UpdateUserCommandValidator : AbstractValidator<UpdateUserCommand>
{
    public UpdateUserCommandValidator()
    {
        RuleFor(x => x.UserId).NotEmpty();
        
        RuleFor(x => x.Username)
            .Matches(@"^[a-zA-Z0-9_]+$").When(x => !string.IsNullOrEmpty(x.Username))
            .WithMessage("Username can only contain letters, numbers, and underscores.");
            
        // 필요 시 중복 검사 로직 추가 (Repository 주입)
    }
}