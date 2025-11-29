using System.Threading;
using System.Threading.Tasks;
using AuthHive.Core.Interfaces.User.Validators;
using AuthHive.Core.Models.Common.Validation;
using AuthHive.Core.Models.User.Commands.Lifecycle;
using AuthHive.Core.Models.User.Commands.Profile;
using AuthHive.Core.Models.User.Commands.Settings;
using UserEntity = AuthHive.Core.Entities.User.User;

namespace AuthHive.Auth.Validators.User
{
    public class UserValidator : IUserValidator
    {
        // ✅ 잘 정리된 두 개의 인터페이스를 주입받습니다.
        private readonly IUserLifecycleValidator _lifecycleValidator;
        private readonly IUserProfileValidator _profileValidator;

        public UserValidator(
            IUserLifecycleValidator lifecycleValidator,
            IUserProfileValidator profileValidator)
        {
            _lifecycleValidator = lifecycleValidator;
            _profileValidator = profileValidator;
        }

        // --- Lifecycle 위임 ---
        public Task<ValidationResult> ValidateCreateAsync(CreateUserCommand c, CancellationToken t) 
            => _lifecycleValidator.ValidateCreateAsync(c, t);

        public Task<ValidationResult> ValidateDeleteAsync(UserEntity u, CancellationToken t) 
            => _lifecycleValidator.ValidateDeleteAsync(u, t);

        public Task<ValidationResult> ValidateSuspendAsync(CreateUserSuspensionCommand c, CancellationToken t) 
            => _lifecycleValidator.ValidateSuspendAsync(c, t);

        // --- Profile 위임 ---
        public Task<ValidationResult> ValidateCreateProfileAsync(CreateUserProfileCommand c, CancellationToken t) 
            => _profileValidator.ValidateCreateAsync(c, t);

        public Task<ValidationResult> ValidateProfileUpdateAsync(UpdateUserProfileCommand c, CancellationToken t) 
            => _profileValidator.ValidateUpdateAsync(c, t);

        // --- 기타 (아직 인터페이스 없는 것들 - 추후 분리) ---
        public Task<ValidationResult> ValidateUpdateAsync(UpdateUserCommand c, CancellationToken t) => Task.FromResult(ValidationResult.Success());
        public Task<ValidationResult> ValidateFeatureProfileUpdateAsync(UpdateUserFeatureProfileCommand c, CancellationToken t) => Task.FromResult(ValidationResult.Success());
        public Task<ValidationResult> ValidateEmailAsync(string e, CancellationToken t) => Task.FromResult(ValidationResult.Success());
        public Task<ValidationResult> ValidateUsernameAsync(string u, CancellationToken t) => Task.FromResult(ValidationResult.Success());
    }
}