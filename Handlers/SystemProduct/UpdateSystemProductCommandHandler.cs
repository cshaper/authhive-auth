// using System;
// using System.Threading;
// using System.Threading.Tasks;
// using MediatR;
// using Microsoft.Extensions.Logging;

// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.SystemProduct.Repositories;
// using AuthHive.Core.Interfaces.Infra;
// using AuthHive.Core.Interfaces.Infra.Cache; // CacheService
// using AuthHive.Core.Models.SystemProduct.Commands;
// using AuthHive.Core.Models.SystemProduct.Responses;
// using AuthHive.Core.Models.SystemProduct.Events;
// using AuthHive.Core.Exceptions;

// namespace AuthHive.Auth.Handlers.SystemProduct;

// public class UpdateSystemProductCommandHandler : IRequestHandler<UpdateSystemProductCommand, SystemProductResponse>
// {
//     private readonly ISystemProductRepository _repository;
//     private readonly IUnitOfWork _unitOfWork;
//     private readonly IMediator _mediator;
//     private readonly IDateTimeProvider _timeProvider;
//     private readonly ICacheService _cacheService; // 캐시 무효화용
//     private readonly ILogger<UpdateSystemProductCommandHandler> _logger;

//     public UpdateSystemProductCommandHandler(
//         ISystemProductRepository repository,
//         IUnitOfWork unitOfWork,
//         IMediator mediator,
//         IDateTimeProvider timeProvider,
//         ICacheService cacheService,
//         ILogger<UpdateSystemProductCommandHandler> logger)
//     {
//         _repository = repository;
//         _unitOfWork = unitOfWork;
//         _mediator = mediator;
//         _timeProvider = timeProvider;
//         _cacheService = cacheService;
//         _logger = logger;
//     }

//     public async Task<SystemProductResponse> Handle(UpdateSystemProductCommand command, CancellationToken cancellationToken)
//     {
//         // 1. 조회
//         var entity = await _repository.GetByIdAsync(command.SystemProductId, cancellationToken);
//         if (entity == null)
//         {
//             throw new DomainEntityNotFoundException($"SystemProduct {command.SystemProductId} not found.");
//         }

//         // 2. 권한 검증 (Provider ID 일치 여부)
//         if (entity.OrganizationId != command.OrganizationId)
//         {
//             throw new UnauthorizedAccessException("You are not the owner of this product.");
//         }

//         // 3. 업데이트 (Nullable 체크)
//         bool isChanged = false;

//         if (command.Name != null && entity.Name != command.Name)
//         {
//             entity.Name = command.Name;
//             isChanged = true;
//         }
//         if (command.Description != null) entity.Description = command.Description;
//         if (command.BasePrice.HasValue) entity.BasePrice = command.BasePrice.Value;
//         if (command.UsagePriceGP.HasValue) entity.UsagePriceGP = command.UsagePriceGP;
//         if (command.IsActive.HasValue) entity.IsActive = command.IsActive.Value;
//         if (command.InheritanceMode.HasValue) entity.InheritanceMode = command.InheritanceMode.Value;
//         if (command.RequiredPermission != null) entity.RequiredPermissionKey = command.RequiredPermission;

//         if (isChanged)
//         {
//             entity.UpdatedAt = _timeProvider.UtcNow;
            
//             // 4. 저장
//             await _repository.UpdateAsync(entity, cancellationToken);
//             await _unitOfWork.SaveChangesAsync(cancellationToken);

//             // 5. 캐시 무효화 (ProductKey 기반 캐시 제거)
//             // Repository 내부 로직이 처리할 수도 있지만, 명시적으로 처리
//             string cacheKey = $"SystemProduct:Key:{entity.ProductKey.ToLowerInvariant()}";
//             await _cacheService.RemoveAsync(cacheKey, cancellationToken);

//             // 6. 이벤트 발행
//             var updatedEvent = new SystemProductUpdatedEvent
//             {
//                 EventId = Guid.NewGuid(),
//                 AggregateId = entity.Id,
//                 OccurredOn = _timeProvider.UtcNow,
//                 TriggeredBy = command.TriggeredBy,
//                 OrganizationId = entity.OrganizationId,
//                 SystemProductId = entity.Id,
//                 ProductKey = entity.ProductKey
//             };
//             await _mediator.Publish(updatedEvent, cancellationToken);
//         }

//         // 7. 응답
//         return new SystemProductResponse
//         {
//             Id = entity.Id,
//             ProductKey = entity.ProductKey,
//             Name = entity.Name,
//             Description = entity.Description,
//             ProductType = entity.ProductType,
//             BasePrice = entity.BasePrice,
//             UsagePriceGP = entity.UsagePriceGP,
//             IsActive = entity.IsActive,
//             InheritanceMode = entity.InheritanceMode,
//             RequiredPermission = entity.RequiredPermissionKey,
//             CreatedAt = entity.CreatedAt
//         };
//     }
// }