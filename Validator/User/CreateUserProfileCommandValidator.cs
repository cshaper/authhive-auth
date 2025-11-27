using System;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation;
using AuthHive.Core.Models.User.Commands;
using AuthHive.Core.Interfaces.User.Repository;

namespace AuthHive.Auth.Validators.User;

public class CreateUserProfileCommandValidator : AbstractValidator<CreateUserProfileCommand>
{
    private readonly IUserProfileRepository _profileRepository;
    private readonly IUserRepository _userRepository;

    public CreateUserProfileCommandValidator(
        IUserProfileRepository profileRepository,
        IUserRepository userRepository)
    {
        _profileRepository = profileRepository;
        _userRepository = userRepository;

        RuleFor(x => x.UserId)
            .NotEmpty()
            .MustAsync(UserMustExist).WithMessage("User does not exist.")
            .MustAsync(ProfileMustNotExist).WithMessage("User profile already exists.");

        RuleFor(x => x.Bio).MaximumLength(1000);
        RuleFor(x => x.Location).MaximumLength(100);
        RuleFor(x => x.WebsiteUrl)
    .Must(BeAValidUrl).When(x => !string.IsNullOrEmpty(x.WebsiteUrl))
    .WithMessage("Invalid Website URL format.");


        RuleFor(x => x.ProfileImageUrl)
            .Must(BeAValidUrl).When(x => !string.IsNullOrEmpty(x.ProfileImageUrl))
            .WithMessage("Invalid Profile Image URL format.");
    }

    private async Task<bool> UserMustExist(Guid userId, CancellationToken token)
    {
        // User가 존재하는지 확인 (IUserRepository 활용)
        // GetByIdAsync는 캐싱되므로 부하가 적음
        return await _userRepository.ExistsAsync(userId, token);
    }

    private async Task<bool> ProfileMustNotExist(Guid userId, CancellationToken token)
    {
        // 이미 프로필이 있으면 False (중복 생성 불가)
        var exists = await _profileRepository.GetByUserIdAsync(userId, token);
        return exists == null;
    }

    private bool BeAValidUrl(string? url)
    {
        return Uri.TryCreate(url, UriKind.Absolute, out var uriResult)
               && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
    }
}