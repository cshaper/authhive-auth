using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation;
using AuthHive.Core.Interfaces.User.Validators; // 인터페이스 위치 확인 필요
using AuthHive.Core.Models.User.Commands.Activity;
using AuthHive.Core.Models.Common.Validation;

namespace AuthHive.Auth.Validators.User;

public class UserActivityLogValidator : AbstractValidator<CreateUserActivityLogCommand>, IUserActivityLogValidator
{
    public UserActivityLogValidator()
    {
        // 1. 필수 값 검증
        RuleFor(x => x.UserId).NotEmpty();
        RuleFor(x => x.ActivityType).IsInEnum();

        // 2. 문자열 길이 검증 (DB 스키마 보호)
        // 빈 규칙 수정: RuleFor(x => x. ).MaximumLength(500); -> Summary로 매핑
        RuleFor(x => x.Summary)
            .MaximumLength(500)
            .When(x => !string.IsNullOrEmpty(x.Summary));

        // ResourceType -> TargetResourceType 수정
        RuleFor(x => x.TargetResourceType)
            .MaximumLength(50)
            .When(x => !string.IsNullOrEmpty(x.TargetResourceType));

        // ResourceId -> TargetResourceId는 Guid? 타입이므로 Length 검증 불필요 (삭제)

        RuleFor(x => x.IpAddress)
            .MaximumLength(45)
            .When(x => !string.IsNullOrEmpty(x.IpAddress));

        RuleFor(x => x.UserAgent)
            .MaximumLength(500)
            .When(x => !string.IsNullOrEmpty(x.UserAgent));

        // ErrorMessage -> FailureReason 수정
        RuleFor(x => x.FailureReason)
            .MaximumLength(1000) // DB 컬럼 크기에 맞게 조정 (보통 TEXT나 1000자)
            .When(x => !string.IsNullOrEmpty(x.FailureReason));
            
        // 3. 논리적 유효성 검증 (Cross-field Validation)
        // 실패(IsSuccess=false) 했는데 사유(FailureReason)가 없는 경우 방지
        RuleFor(x => x.FailureReason)
            .NotEmpty()
            .When(x => !x.IsSuccess)
            .WithMessage("Activity failed but no failure reason provided.");
    }

    public async Task<ValidationResult> ValidateCreateAsync(CreateUserActivityLogCommand command, CancellationToken cancellationToken = default)
    {
        var result = await ValidateAsync(command, cancellationToken);
        
        if (result.IsValid) return ValidationResult.Success();
        
        return ValidationResult.Failure(result.Errors.Select(e => e.ErrorMessage));
    }
}