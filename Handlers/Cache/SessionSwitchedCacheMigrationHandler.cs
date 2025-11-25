// // [AuthHive.Auth] Handlers/Cache/SessionSwitchedCacheMigrationHandler.cs
// // v17 CQRS "본보기": 'SessionSwitchedEvent' (알림)를 구독(Handle)합니다.
// // (SOP 2-Notify-C)
// //
// // 1. INotificationHandler<T>: 'SessionSwitchedEvent'를 구독하는 "부가 작업" 전문가입니다.
// // 2. "캐시 마이그레이션": v16 SessionEventHandler의 캐시 이전 로직을 이관합니다.
// // 3. ICacheService: "계약서"에서 확인된 'GetAsync', 'SetAsync', 'RemoveAsync'를 사용합니다.

// using AuthHive.Core.Interfaces.Base;
// using AuthHive.Core.Interfaces.Infra.Cache; // [v17] ICacheService
// using AuthHive.Core.Models.Auth.Session.Events; // [v17] SessionSwitchedEvent (구독 대상)
// using MediatR;
// using Microsoft.Extensions.Logging;
// using System;
// using System.Collections.Generic;
// using System.Threading;
// using System.Threading.Tasks;

// namespace AuthHive.Auth.Handlers.Cache
// {
//     /// <summary>
//     /// [v17] "세션 전환 시 캐시 마이그레이션" 핸들러 (SOP 2-Notify-C)
//     /// v16 'SessionEventHandler'의 캐시 이전 로직을 이관합니다.
//     /// </summary>
//     /// <remarks>
//     /// ### [v17 아키텍처 설명]
//     /// 
//     /// **1. 언제(When) 이 핸들러가 실행되는가?**
//     ///    - 사용자가 UI에서 조직(테넌트)을 A에서 B로 "전환(Switch)"할 때 실행됩니다.
//     ///    - v17의 핵심 로직(예: 'SwitchContextCommandHandler')이 세션 전환을 완료한 후,
//     ///      `IMediator.Publish(new SessionSwitchedEvent(...))`를 호출합니다.
//     ///    - 이 핸들러는 그 'SessionSwitchedEvent' 알림을 구독(subscribe)하고 있습니다.
//     /// 
//     /// **2. 왜(Why) 이 작업이 필요한가? (v16 로직 이관)**
//     ///    - v16 'SessionEventHandler' [cite: 378-386]는 세션 데이터를 "테넌트(조직)별로 격리"하여 캐시했습니다.
//     ///    - (예: "tenant:OrgA:session:123")
//     ///    - 사용자가 조직을 A에서 B로 전환하면, 캐시 키도 "tenant:OrgB:session:123"로 변경되어야 합니다.
//     ///    - 이 핸들러는 이전 키("OrgA")의 캐시 데이터를 읽어와 새 키("OrgB")로 복사(마이그레이션)하고
//     ///      이전 키("OrgA")의 데이터를 삭제하여, 데이터 정합성을 유지하고 "캐시 쓰레기"를 방지합니다.
//     /// 
//     /// **3. 어떻게(How) 작동하는가?**
//     ///    - 'SessionSwitchedEvent'로부터 "이전 테넌트 ID (FromOrganizationId)"와
//     ///      "새 테넌트 ID (ToOrganizationId)"를 받습니다.
//     ///    - 'ICacheService'를 사용하여 이전 캐시 키로 데이터를 'GetAsync'합니다.
//     ///    - 데이터를 'SetAsync'하여 새 캐시 키로 저장하고, 'RemoveAsync'로 이전 캐시를 삭제합니다.
//     /// </remarks>
//     public class SessionSwitchedCacheMigrationHandler : INotificationHandler<SessionSwitchedEvent>
//     {
//         private readonly ICacheService _cacheService;
//         private readonly ILogger<SessionSwitchedCacheMigrationHandler> _logger;
//         // v16 이벤트 핸들러의 캐시 TTL 설정을 그대로 사용
//         private static readonly TimeSpan SessionCacheTTL = TimeSpan.FromHours(2);

//         public SessionSwitchedCacheMigrationHandler(
//             ICacheService cacheService,
//             ILogger<SessionSwitchedCacheMigrationHandler> logger)
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
//             var fromTenantId = notification.FromOrganizationId ?? Guid.Empty;
//             var toTenantId = notification.ToOrganizationId ?? Guid.Empty;
//             var sessionId = notification.ToSessionId; // AggregateId

//             if (fromTenantId == toTenantId)
//             {
//                 // 동일 조직 내 전환(예: 앱 전환)은 캐시 마이그레이션이 필요 없습니다.
//                 return;
//             }

//             _logger.LogInformation(
//                 "Handling SessionSwitchedEvent for Session {SessionId}. Migrating cache from Tenant {FromTenantId} to {ToTenantId}.",
//                 sessionId, fromTenantId, toTenantId);

//             try
//             {
//                 // 2. [v17 로직 이관] v16 'MigrateSessionCacheToNewTenantAsync' 로직 이관 
                
//                 // v16 헬퍼 메서드 [cite: 372-374]를 사용하여 이전 캐시 키와 새 캐시 키를 생성합니다.
//                 var oldKey = GetTenantSessionCacheKey(fromTenantId, sessionId);
//                 var newKey = GetTenantSessionCacheKey(toTenantId, sessionId);

//                 // "계약서"에서 확인된 'ICacheService.GetAsync<T>' (T: class)를 호출합니다.
//                 // v16은 Dictionary<string, object>를 사용했습니다. [cite: 380-381]
//                 var sessionData = await _cacheService.GetAsync<Dictionary<string, object>>(oldKey, cancellationToken);
                
//                 if (sessionData != null)
//                 {
//                     // 3. 캐시 데이터 "번역" (테넌트 ID 업데이트)
//                     // v16 로직과 동일하게 캐시 내부의 'TenantId' 필드도 업데이트합니다.
//                     sessionData["TenantId"] = toTenantId;

//                     // "계약서"에서 확인된 'ICacheService.SetAsync<T>'로 새 키에 저장합니다.
//                     await _cacheService.SetAsync(newKey, sessionData, SessionCacheTTL, cancellationToken);
                    
//                     // "계약서"에서 확인된 'ICacheService.RemoveAsync'로 이전 키를 삭제합니다.
//                     await _cacheService.RemoveAsync(oldKey, cancellationToken);

//                     _logger.LogDebug("Cache migration successful for Session {SessionId}.", sessionId);
//                 }
//                 else
//                 {
//                     _logger.LogWarning("SessionSwitchedEvent: Could not find old cache key '{OldKey}' for Session {SessionId}. Cache migration skipped.",
//                         oldKey, sessionId);
//                 }
//             }
//             catch (Exception ex)
//             {
//                 // [v17 중요] 알림(Notify) 핸들러는 절대 예외를 전파(throw)하면 안 됩니다.
//                 _logger.LogError(ex, "Failed to migrate cache for SessionSwitchedEvent {SessionId}", notification.AggregateId);
//             }
//         }

//         #region v16 Helper Methods [cite: 370-374]
        
//         // v16 SessionEventHandler의 헬퍼 메서드를 그대로 이관합니다.
        
//         private string GetTenantSessionCacheKey(Guid tenantId, Guid sessionId)
//         {
//             // v16 "본보기" [cite: 372-374]
//             return $"tenant:{tenantId}:session:{sessionId}";
//         }

//         #endregion
//     }
// }