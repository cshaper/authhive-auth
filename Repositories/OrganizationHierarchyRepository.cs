using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Infra.Cache;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Models.Organization.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 계층 구조 전용 Repository - AuthHive v16 (Final Fix)
    /// WHO: 조직 계층 관리 서비스, 권한 검증 서비스
    /// WHEN: 조직 트리 조회, 계층 검증, 조직 이동 시
    /// WHERE: AuthHive.Auth 데이터 액세스 레이어
    /// WHAT: 조직 간 부모-자식 관계 및 계층 구조 데이터
    /// WHY: AWS Organizations 스타일의 계층적 조직 관리
    /// HOW: PostgreSQL의 재귀 CTE(WITH RECURSIVE)를 활용한 효율적 계층 쿼리
    /// </summary>
    public class OrganizationHierarchyRepository : BaseRepository<Core.Entities.Organization.Organization>, IOrganizationHierarchyRepository
    {
        private readonly ILogger<OrganizationHierarchyRepository> _logger;

        /// <summary>
        /// 생성자: 필요한 서비스(DbContext, CacheService, Logger)를 주입받습니다.
        /// 사용: 의존성 주입(DI) 컨테이너가 이 클래스의 인턴스를 생성할 때 호출됩니다.
        /// </summary>
        public OrganizationHierarchyRepository(
            AuthDbContext context,
            ICacheService? cacheService,
            ILogger<OrganizationHierarchyRepository> logger)
            : base(context, cacheService)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// 이 리포지토리가 다루는 엔티티(Organization)가 조직 범위에 속하는지 여부를 결정합니다.
        /// Organization 엔티티 자체는 최상위 스코프이므로 false를 반환하여 불필요한 필터링을 방지합니다.
        /// </summary>
        protected override bool IsOrganizationScopedEntity() => false;

        /// <summary>
        /// 특정 조직의 직접 자식 또는 모든 하위 조직을 조회합니다.
        /// HOW: recursive=false시 ParentId로 직접 자식만 조회, true시 재귀 CTE를 사용하는 GetDescendantsAsync 호출
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetChildrenAsync(
            Guid parentId,
            bool recursive = false,
            CancellationToken cancellationToken = default)
        {
            if (!recursive)
            {
                // 직접 자식만 조회 (단순 쿼리)
                return await Query()
                    .Where(o => o.ParentId == parentId)
                    .OrderBy(o => o.SortOrder).ThenBy(o => o.Name)
                    .AsNoTracking()
                    .ToListAsync(cancellationToken);
            }
            else
            {
                // 모든 하위 조직 조회 (효율적인 재귀 CTE 활용)
                return await GetDescendantsAsync(parentId, null, cancellationToken);
            }
        }

        /// <summary>
        /// 특정 조직의 모든 상위 조직(조상)을 루트까지 조회합니다. (재귀 CTE 사용)
        /// WHY: 계층적 권한/정책 상속 및 breadcrumb 경로 추적을 위해 단일 쿼리로 효율적인 조회가 필요합니다.
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetAncestorsAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = $"Ancestors:{organizationId}";
            if (_cacheService != null)
            {
                var cachedAncestors = await _cacheService.GetAsync<List<Core.Entities.Organization.Organization>>(cacheKey, cancellationToken);
                if (cachedAncestors != null) return cachedAncestors;
            }

            var sql = @"
                WITH RECURSIVE ancestors AS (
                    SELECT * FROM ""Organizations"" WHERE ""Id"" = {0} AND ""IsDeleted"" = false
                    UNION ALL
                    SELECT o.* FROM ""Organizations"" o
                    INNER JOIN ancestors a ON o.""Id"" = a.""ParentId"" WHERE o.""IsDeleted"" = false
                )
                SELECT * FROM ancestors WHERE ""Id"" != {0};"; // 자기 자신은 제외

            var ancestorsList = await _dbSet.FromSqlRaw(sql, organizationId).AsNoTracking().ToListAsync(cancellationToken);

            if (_cacheService != null)
            {
                await _cacheService.SetAsync(cacheKey, ancestorsList, TimeSpan.FromHours(1), cancellationToken);
            }
            return ancestorsList;
        }

        /// <summary>
        /// 특정 조직의 모든 하위 조직(자손)을 조회합니다. (재귀 CTE 사용, 깊이 제한 가능)
        /// WHY: N+1 쿼리 문제를 피하고 단일 DB 호출로 모든 하위 조직을 효율적으로 가져오기 위함입니다.
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetDescendantsAsync(
            Guid organizationId,
            int? maxDepth = null,
            CancellationToken cancellationToken = default)
        {
            var depthCondition = maxDepth.HasValue ? $"AND level < {maxDepth.Value}" : "";
            var sql = $@"
                WITH RECURSIVE descendants AS (
                    SELECT *, 1 as level FROM ""Organizations"" WHERE ""ParentId"" = {{0}} AND ""IsDeleted"" = false
                    UNION ALL
                    SELECT o.*, d.level + 1 FROM ""Organizations"" o
                    INNER JOIN descendants d ON o.""ParentId"" = d.""Id"" WHERE o.""IsDeleted"" = false {depthCondition}
                )
                SELECT * FROM descendants;";

            return await _dbSet.FromSqlRaw(sql, organizationId).AsNoTracking().ToListAsync(cancellationToken);
        }

        /// <summary>
        /// 조직 계층 구조를 트리 형태로 조회합니다. (메모리 내 구성 방식)
        /// HOW: 관련된 모든 조직을 한 번에 DB에서 가져온 후, 메모리에서 부모-자식 관계를 재귀적으로 구성하여 N+1 문제를 회피합니다.
        /// </summary>
        // [수정] 반환 타입을 인터페이스에 맞춰 OrganizationHierarchyTree? -> OrganizationHierarchyTree로 변경
        public async Task<OrganizationHierarchyTree> GetHierarchyTreeAsync(
            Guid? rootId = null,
            int maxDepth = 5,
            CancellationToken cancellationToken = default)
        {
            string cacheKey = $"HierarchyTree:{rootId?.ToString() ?? "All"}:{maxDepth}";
            if (_cacheService != null)
            {
                var cachedTree = await _cacheService.GetAsync<OrganizationHierarchyTree>(cacheKey, cancellationToken);
                if (cachedTree != null) return cachedTree;
            }

            List<Core.Entities.Organization.Organization> organizations;
            if (rootId.HasValue)
            {
                var root = await GetByIdAsync(rootId.Value, cancellationToken);
                if (root == null) return new OrganizationHierarchyTree(); // [수정] null 대신 비어있는 트리 객체 반환

                var descendants = await GetDescendantsAsync(rootId.Value, maxDepth, cancellationToken);
                organizations = descendants.ToList();
                organizations.Add(root);
            }
            else
            {
                organizations = await Query().ToListAsync(cancellationToken);
            }

            if (!organizations.Any()) return new OrganizationHierarchyTree();

            var tree = BuildTreeInMemory(organizations, rootId);
            if (_cacheService != null && tree != null) // tree가 null일 수 있으므로 체크
            {
                await _cacheService.SetAsync(cacheKey, tree, TimeSpan.FromMinutes(30), cancellationToken);
            }
            return tree ?? new OrganizationHierarchyTree(); // 만약을 위해 null이면 비어있는 객체 반환
        }

        /// <summary>
        /// 조직에 직접 자식 조직이 있는지 빠르게 확인합니다.
        /// HOW: SQL의 EXISTS 구문으로 변환되는 AnyAsync를 사용하여 성능을 최적화합니다.
        /// </summary>
        public async Task<bool> HasChildrenAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await Query().AnyAsync(o => o.ParentId == organizationId, cancellationToken);
        }

        /// <summary>
        /// 조직의 계층 내 깊이(레벨)를 조회합니다. (DB에 저장된 Level 값 사용)
        /// WHY: 조직 생성/이동 시 플랜별 깊이 제한을 검증하기 위해 필요합니다. 이 값은 조직 이동 시 서비스 계층에서 재계산되어야 합니다.
        /// </summary>
        public async Task<int> GetDepthLevelAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            // GetByIdAsync는 캐시를 활용하므로 효율적
            var organization = await GetByIdAsync(organizationId, cancellationToken);
            return organization?.Level ?? 0;
        }

        /// <summary>
        /// 조직을 특정 부모 아래로 이동시킬 때 순환 참조가 발생하는지 검증합니다.
        /// HOW: 이동할 조직의 하위 조직 목록(자손)에 새로운 부모가 포함되어 있는지 확인합니다.
        /// </summary>
        public async Task<bool> WouldCreateCycleAsync(
            Guid organizationId,
            Guid proposedParentId,
            CancellationToken cancellationToken = default)
        {
            if (organizationId == proposedParentId) return true; // 자기 자신을 부모로 설정 불가

            // GetDescendantsAsync는 효율적인 CTE 쿼리를 사용
            var descendants = await GetDescendantsAsync(organizationId, null, cancellationToken);
            return descendants.Any(d => d.Id == proposedParentId);
        }

        /// <summary>
        /// 특정 조직을 루트로 하는 하위 트리의 최대 깊이를 계산합니다.
        /// WHY: 플랜 변경(다운그레이드) 시 현재 계층 구조가 새로운 플랜의 깊이 제한을 만족하는지 검증하기 위해 필요합니다.
        /// </summary>
        public async Task<int> GetHierarchyDepthAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var organization = await GetByIdAsync(organizationId, cancellationToken);
            if (organization == null) return 0;
            
            var descendants = await GetDescendantsAsync(organizationId, null, cancellationToken);
            if (!descendants.Any()) return 0;

            // 현재 조직 레벨과의 차이를 계산하여 하위 깊이 계산
            return descendants.Max(d => d.Level) - organization.Level;
        }

        /// <summary>
        /// 최상위 조직(루트 조직)들의 목록을 조회합니다.
        /// HOW: ParentId가 null인 조직을 필터링하여 조회합니다.
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetRootOrganizationsAsync(
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(o => o.ParentId == null)
                .OrderBy(o => o.SortOrder).ThenBy(o => o.Name)
                .AsNoTracking()
                .ToListAsync(cancellationToken);
        }

        #region Private Helper Methods

        /// <summary>
        /// DB에서 가져온 조직 목록을 메모리 내에서 트리 구조로 효율적으로 구성합니다.
        /// </summary>
        private OrganizationHierarchyTree? BuildTreeInMemory(List<Core.Entities.Organization.Organization> allOrgs, Guid? rootId)
        {
            if (!allOrgs.Any()) return null;

            var tree = new OrganizationHierarchyTree();
            var nodeLookup = allOrgs.ToDictionary(o => o.Id, o => new OrganizationNode
            {
                Id = o.Id, Name = o.Name, OrganizationKey = o.OrganizationKey, Level = o.Level, Path = o.Path ?? ""
            });

            var rootNodes = new List<OrganizationNode>();

            foreach (var org in allOrgs)
            {
                if (nodeLookup.TryGetValue(org.Id, out var currentNode))
                {
                    if (org.ParentId.HasValue && nodeLookup.TryGetValue(org.ParentId.Value, out var parentNode))
                    {
                        parentNode.Children.Add(currentNode);
                    }
                    else // ParentId가 없으면 루트 노드
                    {
                        rootNodes.Add(currentNode);
                    }
                }
            }
            
            // 지정된 루트 ID가 있으면 해당 노드를, 없으면 첫 번째 루트 노드를 사용
            tree.Root = rootId.HasValue ? nodeLookup.GetValueOrDefault(rootId.Value) : rootNodes.FirstOrDefault();

            if (tree.Root != null)
            {
                tree.TotalNodes = CountNodes(tree.Root);
                tree.MaxDepth = GetMaxDepth(tree.Root);
                BuildPathMap(tree.Root, "", tree.PathMap);
            }

            return tree;
        }

        private int CountNodes(OrganizationNode? node)
        {
            if (node == null) return 0;
            return 1 + node.Children.Sum(CountNodes);
        }

        private int GetMaxDepth(OrganizationNode? node, int currentDepth = 0)
        {
            if (node == null || !node.Children.Any()) return currentDepth;
            return node.Children.Max(c => GetMaxDepth(c, currentDepth + 1));
        }
        
        private void BuildPathMap(OrganizationNode? node, string parentPath, Dictionary<Guid, string> pathMap)
        {
            if (node == null) return;
            var currentPath = string.IsNullOrEmpty(parentPath) ? node.Name : $"{parentPath} > {node.Name}";
            pathMap[node.Id] = currentPath;
            foreach (var child in node.Children)
            {
                BuildPathMap(child, currentPath, pathMap);
            }
        }
        
        /// <summary>
        /// 특정 조직과 관련된 계층 구조 캐시를 무효화합니다.
        /// 참고: 이 Repository는 조회 전용이므로, 조직 이동 등 계층 구조를 변경하는 서비스에서 이 메서드를 호출해야 합니다.
        /// </summary>
        public async Task InvalidateHierarchyCacheAsync(Guid organizationId, CancellationToken cancellationToken = default)
        {
            if (_cacheService == null) return;
            
            var tasks = new List<Task>();
            try
            {
                // 이 조직의 모든 상위 조직을 먼저 조회 (캐시를 사용할 수 있음)
                var ancestors = await GetAncestorsAsync(organizationId, cancellationToken);
                
                // 캐시 무효화 작업 목록 생성
                tasks.Add(_cacheService.RemoveAsync($"Ancestors:{organizationId}", cancellationToken));
                tasks.Add(_cacheService.RemoveAsync($"HierarchyTree:{organizationId}:5", cancellationToken)); // maxDepth 고려 필요
                tasks.Add(_cacheService.RemoveAsync($"HierarchyTree:All:5", cancellationToken)); // 전체 트리 캐시 무효화

                // 모든 상위 조직에 대한 트리 캐시도 무효화
                foreach (var ancestor in ancestors)
                {
                    tasks.Add(_cacheService.RemoveAsync($"HierarchyTree:{ancestor.Id}:5", cancellationToken));
                }
            
                await Task.WhenAll(tasks);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to invalidate hierarchy cache for organization {OrganizationId}", organizationId);
            }
        }

        #endregion
    }
}

