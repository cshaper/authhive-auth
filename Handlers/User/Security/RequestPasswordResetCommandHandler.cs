// using System;
// using System.Linq;
// using System.Threading;
// using System.Threading.Tasks;
// using MediatR; // IPublisher가 여기에 포함됨
// using Microsoft.Extensions.Logging;
// using FluentValidation;
// using AuthHive.Core.Exceptions;
// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.User.Repositories.Lifecycle;
// using AuthHive.Core.Interfaces.Auth.Authentication.Provider;
// using AuthHive.Core.Models.User.Commands.Security;
// using AuthHive.Core.Models.User.Events.Security;
// using AuthHive.Core.Interfaces.Infra;

// namespace AuthHive.Auth.Handlers.User.Security;

// public class RequestPasswordResetCommandHandler : IRequestHandler<RequestPasswordResetCommand, Unit>
// {
//     private readonly IUserQueryRepository _userRepository;
//     private readonly IUnitOfWork _unitOfWork;
//     private readonly ITokenProvider _tokenProvider;
//     private readonly IDateTimeProvider _timeProvider;
//     private readonly ILogger<RequestPasswordResetCommandHandler> _logger;
//     private readonly IValidator<RequestPasswordResetCommand> _validator;
//     private readonly IPrincipalAccessor _principalAccessor;
    
//     // [Fix] IMediator 대신 IPublisher 사용 (이벤트 발행 전용)
//     private readonly IPublisher _publisher; 

//     public RequestPasswordResetCommandHandler(
//         IUserQueryRepository userRepository,
//         IUnitOfWork unitOfWork,
//         IValidator<RequestPasswordResetCommand> validator,
//         ITokenProvider tokenProvider,
//         IDateTimeProvider timeProvider,
//         // [Fix] 생성자 주입 변경 (IMediator -> IPublisher)
//         IPublisher publisher, 
//         ILogger<RequestPasswordResetCommandHandler> logger,
//         IPrincipalAccessor principalAccessor)
//     {
//         _userRepository = userRepository;
//         _unitOfWork = unitOfWork;
//         _validator = validator;
//         _tokenProvider = tokenProvider;
//         _timeProvider = timeProvider;
//         _publisher = publisher;
//         _logger = logger;
//         _principalAccessor = principalAccessor;
//     }

//     public async Task<Unit> Handle(RequestPasswordResetCommand command, CancellationToken cancellationToken)
//     {
//         _logger.LogInformation("Processing CommandId: {CommandId} for Email: {Email}", command.CommandId, command.Email);

//         // 1. 유효성 검사
//         var validationResult = await _validator.ValidateAsync(command, cancellationToken);
//         if (!validationResult.IsValid)
//         {
//             var errorMessages = validationResult.Errors.Select(e => e.ErrorMessage);
//             throw new DomainValidationException("Validation failed.", errorMessages);
//         }

//         // 2. 사용자 조회
//         var user = await _userRepository.GetByEmailAsync(command.Email, cancellationToken);
//         if (user == null)
//         {
//             _logger.LogWarning("Password reset requested for non-existent email: {Email}", command.Email);
//             return Unit.Value; 
//         }

//         // 3. 요청자 식별
//         var triggeredBy = _principalAccessor.UserId ?? user.Id;

//         // 4. 토큰 생성
//         var resetToken = await _tokenProvider.GenerateRefreshTokenAsync(cancellationToken);
        
//         // 5. 이벤트 발행 (IPublisher 사용)
//         var requestedEvent = new PasswordResetRequestedEvent
//         {
//             EventId = Guid.NewGuid(),
//             AggregateId = user.Id,
//             OccurredAt = _timeProvider.UtcNow,
//             TriggeredBy = triggeredBy,
//             OrganizationId = _principalAccessor.OrganizationId,
            
//             UserId = user.Id,
//             Email = user.Email,
//             ResetToken = resetToken,
//             RequestedAt = _timeProvider.UtcNow,
//             IpAddress = command.IpAddress,
//             CorrelationId = command.CommandId.ToString() 
//         };

//         // [Fix] _mediator.Publish -> _publisher.Publish
//         await _publisher.Publish(requestedEvent, cancellationToken);

//         _logger.LogInformation("Password reset requested. User: {UserId}", user.Id);

//         return Unit.Value;
//     }
// }