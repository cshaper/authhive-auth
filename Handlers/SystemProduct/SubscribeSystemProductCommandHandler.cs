using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;

using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.SystemProduct.Repositories;
using AuthHive.Core.Interfaces.SystemProduct.Validator;
using AuthHive.Core.Interfaces.Infra;
using AuthHive.Core.Models.SystemProduct.Commands;
using AuthHive.Core.Models.SystemProduct.Responses;
using AuthHive.Core.Models.SystemProduct.Events;
using AuthHive.Core.Exceptions;
using AuthHive.Core.Entities.SystemProduct;
using static AuthHive.Core.Enums.Business.AddonEnums;

namespace AuthHive.Auth.Handlers.SystemProduct;

/// <summary>
/// [Auth] 시스템 상품 구독 처리 핸들러
/// </summary>
public class SubscribeSystemProductCommandHandler : IRequestHandler<SubscribeSystemProductCommand, SystemProductSubscriptionResponse>
{
    private readonly ISystemProductRepository _productRepo;
    private readonly ISystemProductSubscriptionRepository _subscriptionRepo;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ISystemProductValidator _validator;
    private readonly IMediator _mediator;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ILogger<SubscribeSystemProductCommandHandler> _logger;

    public SubscribeSystemProductCommandHandler(
        ISystemProductRepository productRepo,
        ISystemProductSubscriptionRepository subscriptionRepo,
        IUnitOfWork unitOfWork,
        ISystemProductValidator validator,
        IMediator mediator,
        IDateTimeProvider timeProvider,
        ILogger<SubscribeSystemProductCommandHandler> logger)
    {
        _productRepo = productRepo;
        _subscriptionRepo = subscriptionRepo;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _mediator = mediator;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task<SystemProductSubscriptionResponse> Handle(SubscribeSystemProductCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Organization {OrgId} subscribing to {ProductKey}", command.OrganizationId, command.ProductKey);

        // 1. 유효성 검사 (Validator)
        // - 상품 존재 여부
        // - 중복 구독 여부
        // - 정책 위반 여부 (Enterprise 등)
        var validationResult = await _validator.ValidateSubscribeAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new DomainValidationException("Subscription failed", validationResult.Errors);
        }

        // 2. 상품 정보 조회 (Event/Response 매핑용)
        // Validator가 검사했지만, 데이터를 쓰기 위해 다시 가져옵니다 (Tracking)
        var product = await _productRepo.GetByKeyAsync(command.ProductKey, cancellationToken);
        if (product == null) throw new DomainEntityNotFoundException("Product not found"); // 혹시나 해서 방어

        // 3. Subscription Entity 생성
        var subscription = new SystemProductSubscription
        {
            OrganizationId = command.OrganizationId,
            SystemProductId = product.Id,
            AcquisitionType = SystemProductAcquisitionType.DirectSubscription,
            BillingSubscriptionId = command.BillingSubscriptionId,
            IsActive = true,
            StartDate = command.StartDate,
            EndDate = command.EndDate,
            CreatedAt = _timeProvider.UtcNow
        };

        // 4. 저장
        await _subscriptionRepo.AddAsync(subscription, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 5. 이벤트 발행 (중요: 다른 모듈이 이걸 보고 동작함)
        var subscribedEvent = new SystemProductSubscribedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = subscription.Id,
            OccurredOn = _timeProvider.UtcNow,
            TriggeredBy = command.TriggeredBy,
            OrganizationId = command.OrganizationId,
            
            SubscriptionId = subscription.Id,
            SystemProductId = product.Id,
            ProductKey = product.ProductKey,
            StartDate = subscription.StartDate,
            AutoRenew = command.AutoRenew
        };

        await _mediator.Publish(subscribedEvent, cancellationToken);

        // 6. 응답 반환
        return new SystemProductSubscriptionResponse
        {
            Id = subscription.Id,
            OrganizationId = subscription.OrganizationId,
            SystemProductId = product.Id,
            ProductKey = product.ProductKey,
            ProductName = product.Name,
            IsActive = subscription.IsActive,
            AcquisitionType = subscription.AcquisitionType,
            StartDate = subscription.StartDate,
            EndDate = subscription.EndDate
        };
    }
}