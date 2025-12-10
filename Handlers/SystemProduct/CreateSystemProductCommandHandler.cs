using System;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;

// [Interfaces]
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.SystemProduct.Repositories;
using AuthHive.Core.Interfaces.SystemProduct.Validator;
using AuthHive.Core.Interfaces.Infra; // IDateTimeProvider
using AuthHive.Core.Interfaces.Infra.Cache;

// [Models]
using AuthHive.Core.Models.SystemProduct.Commands;
using AuthHive.Core.Models.SystemProduct.Responses;
using AuthHive.Core.Models.SystemProduct.Events;

// [Exceptions]
using AuthHive.Core.Exceptions;

// [Entity]
using AuthHive.Core.Entities.SystemProduct;

namespace AuthHive.Auth.Handlers.SystemProduct;

/// <summary>
/// [Auth] 시스템 상품 생성 핸들러
/// </summary>
public class CreateSystemProductCommandHandler : IRequestHandler<CreateSystemProductCommand, SystemProductResponse>
{
    private readonly ISystemProductRepository _repository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ISystemProductValidator _validator;
    private readonly IMediator _mediator;
    private readonly IDateTimeProvider _timeProvider;
    private readonly ILogger<CreateSystemProductCommandHandler> _logger;

    public CreateSystemProductCommandHandler(
        ISystemProductRepository repository,
        IUnitOfWork unitOfWork,
        ISystemProductValidator validator,
        IMediator mediator,
        IDateTimeProvider timeProvider,
        ILogger<CreateSystemProductCommandHandler> logger)
    {
        _repository = repository;
        _unitOfWork = unitOfWork;
        _validator = validator;
        _mediator = mediator;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task<SystemProductResponse> Handle(CreateSystemProductCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Creating SystemProduct: {ProductKey}", command.ProductKey);

        // 1. 유효성 검사 (Validator -> PricingConstants 정책 확인)
        var validationResult = await _validator.ValidateCreateProductAsync(command, cancellationToken);
        if (!validationResult.IsValid)
        {
            throw new DomainValidationException("Validation failed for CreateSystemProduct", validationResult.Errors);
        }

        // 2. Entity 생성 & 매핑
        var entity = new AuthHive.Core.Entities.SystemProduct.Core.SystemProduct
        {
            OrganizationId = command.OrganizationId, // Provider ID
            ProductKey = command.ProductKey,
            ProductType = command.ProductType,
            Name = command.Name,
            Description = command.Description,
            BasePrice = command.BasePrice,
            UsagePriceGP = command.UsagePriceGP,
            IsActive = command.IsActive,
            InheritanceMode = command.InheritanceMode,
            RequiredPermissionKey = command.RequiredPermission,
            Currency = "USD", // 기본값
            Status = Core.Enums.Business.ProductStatus.Published, // 기본 활성
            CreatedAt = _timeProvider.UtcNow
        };

        // 3. 저장
        await _repository.AddAsync(entity, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        // 4. 이벤트 발행
        var createdEvent = new SystemProductCreatedEvent
        {
            EventId = Guid.NewGuid(),
            AggregateId = entity.Id,
            OccurredOn = _timeProvider.UtcNow,
            TriggeredBy = command.TriggeredBy,
            OrganizationId = entity.OrganizationId,
            
            SystemProductId = entity.Id,
            ProductKey = entity.ProductKey,
            Name = entity.Name
        };

        await _mediator.Publish(createdEvent, cancellationToken);

        // 5. 응답 생성
        return new SystemProductResponse
        {
            Id = entity.Id,
            ProductKey = entity.ProductKey,
            Name = entity.Name,
            Description = entity.Description,
            ProductType = entity.ProductType,
            BasePrice = entity.BasePrice,
            UsagePriceGP = entity.UsagePriceGP,
            IsActive = entity.IsActive,
            InheritanceMode = entity.InheritanceMode,
            RequiredPermission = entity.RequiredPermissionKey,
            CreatedAt = entity.CreatedAt
        };
    }
}