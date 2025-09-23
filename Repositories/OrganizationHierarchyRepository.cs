using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AuthHive.Auth.Data.Context;
using AuthHive.Auth.Repositories.Base;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Interfaces.Base;
using AuthHive.Core.Interfaces.Organization.Repository;
using AuthHive.Core.Interfaces.Organization.Service;
using AuthHive.Core.Models.Organization.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace AuthHive.Auth.Repositories.Organization
{
    /// <summary>
    /// 조직 계층 구조 전용 Repository - AuthHive v15
    /// WHO: 조직 계층 관리 서비스, 권한 검증 서비스
    /// WHEN: 조직 트리 조회, 계층 검증, 조직 이동 시
    /// WHERE: AuthHive.Auth 데이터 액세스 레이어
    /// WHAT: 조직 간 부모-자식 관계 및 계층 구조 데이터
    /// WHY: AWS Organizations 스타일의 계층적 조직 관리
    /// HOW: PostgreSQL의 재귀 CTE(WITH RECURSIVE)를 활용한 효율적 계층 쿼리
    /// </summary>
    public class OrganizationHierarchyRepository : BaseRepository<Core.Entities.Organization.Organization>,
        IOrganizationHierarchyRepository
    {
        public OrganizationHierarchyRepository(
            AuthDbContext context,
            IOrganizationContext organizationContext,
            IMemoryCache? cache = null)
            : base(context, organizationContext, cache)
        {
        }

        /// <summary>
        /// 특정 조직의 직접 또는 모든 자식 조직 조회
        /// WHO: 조직 관리자, 계층 뷰 컴포넌트
        /// WHEN: 조직 트리 렌더링, 하위 조직 목록 표시
        /// WHERE: 조직 관리 페이지, 권한 상속 프로세스
        /// WHAT: 지정된 부모 조직의 자식 조직들
        /// WHY: 계층 구조 네비게이션 및 권한 상속
        /// HOW: recursive=false시 직접 자식만, true시 재귀 쿼리로 모든 하위 조직
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetChildrenAsync(
            Guid parentId,
            bool recursive = false,
            CancellationToken cancellationToken = default)
        {
            if (!recursive)
            {
                // 직접 자식만 조회
                return await Query()
                    .Where(o => o.ParentId == parentId)
                    .OrderBy(o => o.SortOrder)
                    .ThenBy(o => o.Name)
                    .ToListAsync(cancellationToken);
            }
            else
            {
                // 재귀적으로 모든 하위 조직 조회
                var allChildren = new List<Core.Entities.Organization.Organization>();
                await GetChildrenRecursiveAsync(parentId, allChildren, cancellationToken);
                return allChildren;
            }
        }

        /// <summary>
        /// 특정 조직의 모든 상위 조직 조회 (루트까지)
        /// WHO: 권한 검증 서비스, 정책 상속 서비스
        /// WHEN: 상위 조직의 정책/권한 상속, breadcrumb 생성
        /// WHERE: 권한 검증 로직, 조직 경로 표시
        /// WHAT: 현재 조직부터 루트까지의 모든 부모 조직
        /// WHY: 계층적 권한/정책 상속 및 경로 추적
        /// HOW: 재귀적으로 ParentId를 따라 루트까지 탐색
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetAncestorsAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var ancestors = new List<Core.Entities.Organization.Organization>();
            var current = await GetByIdAsync(organizationId);

            while (current?.ParentId != null)
            {
                var parent = await GetByIdAsync(current.ParentId.Value);
                if (parent != null)
                {
                    ancestors.Add(parent);
                    current = parent;
                }
                else
                {
                    break;
                }
            }

            return ancestors;
        }

        /// <summary>
        /// 특정 조직의 모든 하위 조직 조회 (깊이 제한 가능)
        /// WHO: 조직 삭제 서비스, 정책 전파 서비스
        /// WHEN: 조직 삭제 영향 분석, 정책 일괄 적용
        /// WHERE: 조직 삭제 확인, 정책 변경 프로세스
        /// WHAT: 지정 조직 아래의 모든 하위 조직
        /// WHY: 종속 조직 파악 및 일괄 작업 수행
        /// HOW: WITH RECURSIVE를 사용한 깊이 제한 하위 트리 조회
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetDescendantsAsync(
            Guid organizationId,
            int? maxDepth = null,
            CancellationToken cancellationToken = default)
        {
            var descendants = new List<Core.Entities.Organization.Organization>();
            await GetDescendantsRecursiveAsync(organizationId, descendants, 0, maxDepth, cancellationToken);
            return descendants;
        }

        /// <summary>
        /// 조직 계층 구조를 트리 형태로 조회
        /// WHO: Admin Dashboard, 조직 관리 UI
        /// WHEN: 조직 계층 구조 시각화
        /// WHERE: 조직 트리 뷰 컴포넌트
        /// WHAT: 계층 구조를 트리 데이터 구조로 변환
        /// WHY: UI에서 효율적인 트리 렌더링
        /// HOW: 재귀적으로 부모-자식 관계를 트리 노드로 구성
        /// </summary>
        public async Task<OrganizationHierarchyTree> GetHierarchyTreeAsync(
            Guid? rootId = null,
            int maxDepth = 5,
            CancellationToken cancellationToken = default)
        {
            var tree = new OrganizationHierarchyTree();

            if (rootId.HasValue)
            {
                var root = await GetByIdAsync(rootId.Value);
                if (root != null)
                {
                    tree.Root = await BuildTreeNodeAsync(root, 0, maxDepth, cancellationToken);
                }
            }
            else
            {
                // 모든 루트 조직을 가져와서 포레스트 구성
                var roots = await GetRootOrganizationsAsync(cancellationToken);
                foreach (var root in roots)
                {
                    var node = await BuildTreeNodeAsync(root, 0, maxDepth, cancellationToken);
                    if (tree.Root == null)
                    {
                        tree.Root = node;
                    }
                    else
                    {
                        // 여러 루트가 있는 경우 처리
                        tree.Root.Children.Add(node);
                    }
                }
            }

            tree.TotalNodes = CountNodes(tree.Root);
            tree.MaxDepth = GetMaxDepth(tree.Root);
            BuildPathMap(tree.Root, "", tree.PathMap);

            return tree;
        }

        /// <summary>
        /// 조직에 자식이 있는지 확인
        /// WHO: 조직 삭제 서비스, UI 상태 관리
        /// WHEN: 삭제 가능 여부 확인, 폴더 아이콘 표시
        /// WHERE: 삭제 전 검증, 트리 UI 렌더링
        /// WHAT: 자식 조직 존재 여부
        /// WHY: 삭제 가능성 판단, UI 힌트 제공
        /// HOW: EXISTS 쿼리로 빠른 존재 여부 확인
        /// </summary>
        public async Task<bool> HasChildrenAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .AnyAsync(o => o.ParentId == organizationId, cancellationToken);
        }

        /// <summary>
        /// 조직의 루트로부터의 깊이 레벨 조회
        /// WHO: 플랜 검증 서비스, 계층 제한 검증
        /// WHEN: 조직 생성/이동 시 깊이 제한 확인
        /// WHERE: 조직 생성/수정 검증 로직
        /// WHAT: 루트(0)부터 현재 조직까지의 레벨
        /// WHY: 플랜별 깊이 제한 검증
        /// HOW: 루트까지의 부모 수를 카운트
        /// </summary>
        public async Task<int> GetDepthLevelAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var organization = await GetByIdAsync(organizationId);
            return organization?.Level ?? 0;
        }

        /// <summary>
        /// 조직 이동 시 순환 참조 발생 여부 검증
        /// WHO: 조직 계층 수정 서비스
        /// WHEN: 조직의 부모 변경 요청 시
        /// WHERE: MoveOrganizationAsync 사전 검증
        /// WHAT: A를 B의 자식으로 만들 때 순환 발생 여부
        /// WHY: 무한 루프 방지, 데이터 무결성 보장
        /// HOW: proposedParent의 조상에 organization이 있는지 확인
        /// </summary>
        public async Task<bool> WouldCreateCycleAsync(
            Guid organizationId,
            Guid proposedParentId,
            CancellationToken cancellationToken = default)
        {
            // 자기 자신을 부모로 설정하려는 경우
            if (organizationId == proposedParentId)
                return true;

            // proposedParent가 organization의 자손인지 확인
            var descendants = await GetDescendantsAsync(organizationId, null, cancellationToken);
            return descendants.Any(d => d.Id == proposedParentId);
        }

        /// <summary>
        /// 계층 구조의 최대 깊이를 확인 (Business 플랜은 3단계까지만 허용)
        /// WHO: 플랜 검증 서비스, 조직 생성 서비스
        /// WHEN: 하위 조직 추가 시, 플랜 다운그레이드 시
        /// WHERE: OrganizationService.CreateAsync 사전 검증
        /// WHAT: 특정 조직부터 최하위까지의 깊이 계산
        /// WHY: 플랜별 계층 깊이 제한 적용
        /// HOW: 재귀적 하위 조직 탐색으로 최대 깊이 계산
        /// </summary>
        public async Task<int> GetHierarchyDepthAsync(
            Guid organizationId,
            CancellationToken cancellationToken = default)
        {
            var maxDepth = 0;
            var descendants = await GetDescendantsAsync(organizationId, null, cancellationToken);
            
            foreach (var descendant in descendants)
            {
                var depth = descendant.Level - (await GetByIdAsync(organizationId))?.Level ?? 0;
                if (depth > maxDepth)
                {
                    maxDepth = depth;
                }
            }

            return maxDepth;
        }

        /// <summary>
        /// 루트 조직 조회 (최상위 조직들)
        /// WHO: 조직 트리 뷰, 전체 조직 관리자
        /// WHEN: 조직 계층 구조 시각화, 루트 조직 목록 필요 시
        /// WHERE: Admin Dashboard 조직 트리 뷰
        /// WHAT: ParentId가 null인 모든 최상위 조직
        /// WHY: 계층 구조의 시작점 식별
        /// HOW: ParentId IS NULL 조건으로 필터링
        /// </summary>
        public async Task<IEnumerable<Core.Entities.Organization.Organization>> GetRootOrganizationsAsync(
            CancellationToken cancellationToken = default)
        {
            return await Query()
                .Where(o => o.ParentId == null)
                .OrderBy(o => o.SortOrder)
                .ThenBy(o => o.Name)
                .ToListAsync(cancellationToken);
        }

        #region Private Helper Methods

        private async Task GetChildrenRecursiveAsync(
            Guid parentId,
            List<Core.Entities.Organization.Organization> result,
            CancellationToken cancellationToken)
        {
            var children = await Query()
                .Where(o => o.ParentId == parentId)
                .OrderBy(o => o.SortOrder)
                .ThenBy(o => o.Name)
                .ToListAsync(cancellationToken);

            result.AddRange(children);

            foreach (var child in children)
            {
                await GetChildrenRecursiveAsync(child.Id, result, cancellationToken);
            }
        }

        private async Task GetDescendantsRecursiveAsync(
            Guid parentId,
            List<Core.Entities.Organization.Organization> result,
            int currentDepth,
            int? maxDepth,
            CancellationToken cancellationToken)
        {
            if (maxDepth.HasValue && currentDepth >= maxDepth.Value)
                return;

            var children = await Query()
                .Where(o => o.ParentId == parentId)
                .ToListAsync(cancellationToken);

            result.AddRange(children);

            foreach (var child in children)
            {
                await GetDescendantsRecursiveAsync(child.Id, result, currentDepth + 1, maxDepth, cancellationToken);
            }
        }

        private async Task<OrganizationNode> BuildTreeNodeAsync(
            Core.Entities.Organization.Organization org,
            int currentDepth,
            int maxDepth,
            CancellationToken cancellationToken)
        {
            var node = new OrganizationNode
            {
                Id = org.Id,
                Name = org.Name,
                OrganizationKey = org.OrganizationKey,
                Level = org.Level,
                Path = org.Path ?? $"/{org.Id}"
            };

            if (currentDepth < maxDepth)
            {
                var children = await GetChildrenAsync(org.Id, false, cancellationToken);
                foreach (var child in children)
                {
                    var childNode = await BuildTreeNodeAsync(child, currentDepth + 1, maxDepth, cancellationToken);
                    node.Children.Add(childNode);
                }
            }

            return node;
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

            var currentPath = string.IsNullOrEmpty(parentPath)
                ? node.Name
                : $"{parentPath} > {node.Name}";

            pathMap[node.Id] = currentPath;

            foreach (var child in node.Children)
            {
                BuildPathMap(child, currentPath, pathMap);
            }
        }

        #endregion
    }
}