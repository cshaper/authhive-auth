// // [AuthHive.Auth] Handlers/Cache/SessionSwitchedPermissionCacheHandler.cs
// // v17 CQRS "본보기": 'SessionSwitchedEvent' (알림)를 구독(Handle)합니다.
// // (SOP 2-Notify-C)
// //
// // 1. INotificationHandler<T>: 'SessionSwitchedEvent'를 구독하는 "부가 작업" 전문가입니다.
// // 2. "권한 캐시 무효화": v16 SessionEventHandler의 권한 캐시 정리 로직을 이관합니다.
// // 3. ICacheService: "계약서"에서 확인된 'RemoveByPatternAsync'를 사용합니다.

// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Infra.Cache; // [v17] ICacheService
// using AuthHive.Core.Models.Auth.Session.Events; // [v17] SessionSwitchedEvent (구독 대상)
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System;
// using System.Threading;
// using System.Threading.Tasks;

// namespace AuthHive.Auth.Handlers.Cache
// {
//     /// <summary>
//     /// [v17] "세션 전환 시 권한 캐시" 핸들러 (SOP 2-Notify-C)
//     /// v16 'SessionEventHandler'의 권한 캐시 무효화 로직을 이관합니다.
//     /// </summary>
//     /// <remarks>
//     /// ### [v17 아키텍처 설명]
//     /// 
//     /// **1. 언제(When) 이 핸들러가 실행되는가?**
//     ///    - 'SessionSwitchedCacheMigrationHandler'와 *동시에* 실행됩니다.
//     ///    - 사용자가 조직(테넌트)을 A에서 B로 "전환(Switch)"하여 'SessionSwitchedEvent'가
//     ///      발행(Publish)되면, MediatR이 이 이벤트를 구독하는 모든 핸들러를 실행합니다.
//     /// 
//     /// **2. 왜(Why) 이 작업이 필요한가? (v16 로직 이관)**
//     ///    - AuthHive는 성능을 위해 사용자의 "권한"을 조직(테넌트)별로 캐시합니다.
//     ///    - (예: "tenant:OrgA:user:555:permissions:...")
//     ///    - 사용자가 "A회사"에서 "B회사"로 전환하면, "A회사"의 권한 캐시는 더 이상 유효하지 않으며,
//     ///      "B회사"의 새로운 권한을 DB에서 다시 읽어와 캐시해야 합니다.
//     ///    - 이 핸들러는 v16 'InvalidatePermissionCacheAsync'  로직을 이관받아,
//     ///      *새로운* 조직("B회사")의 *모든* 권한 캐시를 삭제(무효화)합니다.
//     /// 
//     /// **3. 어떻게(How) 작동하는가?**
//     ///    - 'SessionSwitchedEvent'로부터 "새 테넌트 ID (ToOrganizationId)"와 "사용자 ID (UserId)"를 받습니다.
//     ///    - 'ICacheService.RemoveByPatternAsync'를 호출하여 "B회사"의 권한 캐시 패턴
//     ///      (예: "tenant:OrgB:user:555:permissions:*")과 일치하는 모든 캐시를 삭제합니다.
//     ///    - (참고: 이 작업 후 사용자가 "B회사"의 리소스에 처음 접근할 때, 'PermissionService' 등이
//     ///      캐시 미스(Cache Miss)를 감지하고 DB에서 새 권한을 읽어와 캐시를 다시 생성합니다.)
//     /// </remarks>
//     public class SessionSwitchedPermissionCacheHandler : INotificationHandler<SessionSwitchedEvent>
//     {
//         private readonly ICacheService _cacheService;
//         private readonly ILogger<SessionSwitchedPermissionCacheHandler> _logger;

//         public SessionSwitchedPermissionCacheHandler(
//             ICacheService cacheService,
//             ILogger<SessionSwitchedPermissionCacheHandler> logger)
//         {
//             _cacheService = cacheService;
//             _logger = logger;
//         }

//         /// <summary>
//         /// SessionSwitchedEvent 알림을 처리합니다.
//         /// </summary>
//         public async Task Handle(SessionSwitchedEvent notification, CancellationToken cancellationToken)
//         {
//             // 1. [v17 "계약서" 확인]
//             // "세션 전환 계약서"의 속성들을 변수로 추출합니다.
//             var tenantId = notification.ToOrganizationId ?? Guid.Empty;
//             var userId = notification.UserId;

//             if (tenantId == Guid.Empty)
//             {
//                 // 조직 컨텍스트가 없는 전환(예: 전역 -> 전역)은 권한 캐시가 없습니다.
//                 return;
//             }
            
//             _logger.LogInformation(
//                 "Handling SessionSwitchedEvent for User {UserId}. Invalidating permission cache for new Tenant {TenantId}.",
//                 userId, tenantId);

//             try
//             {
//                 // 2. [v17 로직 이관] v16 'InvalidatePermissionCacheAsync' 로직 이관 
                
//                 // v16과 동일하게 "권한 캐시" 패턴을 정의합니다.
//                 // (이 패턴은 권한을 저장하는 'PermissionService'의 "계약서"와 일치해야 합니다.)
//                 var permissionPattern = $"tenant:{tenantId}:user:{userId}:permissions:*";

//                 // "계약서"에서 확인된 'ICacheService.RemoveByPatternAsync'를 호출하여
//                 // 새 조직에 대한 기존 권한 캐시를 모두 삭제(무효화)합니다.
//                 await _cacheService.RemoveByPatternAsync(permissionPattern, cancellationToken);
                
//                 _logger.LogDebug("Permission cache invalidated for User {UserId} in Tenant {TenantId}.", userId, tenantId);
//             }
//             catch (Exception ex)
//             {
//                 // [v17 중요] 알림(Notify) 핸들러는 절대 예외를 전파(throw)하면 안 됩니다.
//                 _logger.LogError(ex, "Failed to invalidate permission cache for SessionSwitchedEvent (User: {UserId}, Tenant: {TenantId})", 
//                     notification.UserId, notification.ToOrganizationId);
//             }
//         }
//     }
// }