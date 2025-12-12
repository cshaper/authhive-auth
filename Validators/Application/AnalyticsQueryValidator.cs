// Path: AuthHive.Auth/Validators/Application/AnalyticsQueryValidator.cs
using AuthHive.Core.Models.Application.Queries;
using FluentValidation;

public class AnalyticsQueryValidator : AbstractValidator<AnalyticsQuery>
{
    public AnalyticsQueryValidator()
    {
        RuleFor(x => x.EndDate)
            .GreaterThanOrEqualTo(x => x.StartDate)
            .WithMessage("종료일은 시작일보다 이후여야 합니다.");

        RuleFor(x => x.OrganizationId).NotEmpty();
        // (선택) 조회 기간 제한 (예: 최대 180)
        RuleFor(x => x.EndDate)
            .Must((query, endDate) => (endDate - query.StartDate).TotalDays <= 180)
            .WithMessage("조회 기간은 최대 180일까지만 가능합니다.");
    }
}