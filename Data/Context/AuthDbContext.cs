using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Entities.System;
using Microsoft.AspNetCore.Http;
using System.Linq.Expressions;
using OrganizationEntity = AuthHive.Core.Entities.Organization.Organization;
namespace AuthHive.Auth.Data.Context
{
    public class AuthDbContext : DbContext
    {
        private readonly IHttpContextAccessor? _httpContextAccessor;
        // 테넌트 격리를 위한 현재 조직 ID
        public Guid? CurrentOrganizationId { get; set; }
        public Guid? CurrentConnectedId { get; set; }

        #region User 도메인
        public DbSet<User> Users { get; set; }
        public DbSet<UserProfile> UserProfiles { get; set; }
        public DbSet<UserActivityLog> UserActivityLogs { get; set; }
        public DbSet<UserFeatureProfile> UserFeatureProfiles { get; set; }
        #endregion

        #region Auth 도메인 - 핵심
        public DbSet<ConnectedId> ConnectedIds { get; set; }
        public DbSet<ConnectedIdContext> ConnectedIdContexts { get; set; }
        public DbSet<ConnectedIdRole> ConnectedIdRoles { get; set; }

        public DbSet<ClientCertificate> ClientCertificates { get; set; }
        public DbSet<SessionEntity> Sessions { get; set; }
        public DbSet<SessionActivityLog> SessionActivityLogs { get; set; }
        public DbSet<AuthenticationAttemptLog> AuthenticationAttemptLogs { get; set; }
        public DbSet<AuthorizationAuditLog> AuthorizationAuditLogs { get; set; }
        #endregion

        #region 권한 관리
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<RolePermission> RolePermissions { get; set; }
        public DbSet<PermissionValidationLog> PermissionValidationLogs { get; set; }
        #endregion

        #region OAuth & Tokens
        public DbSet<OAuthClient> OAuthClients { get; set; }
        public DbSet<AccessToken> AccessTokens { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        #endregion

        #region Organization 도메인
        public DbSet<OrganizationEntity> Organizations { get; set; }
        public DbSet<OrganizationMembership> OrganizationMemberships { get; set; }
        public DbSet<OrganizationMemberProfile> OrganizationMemberProfiles { get; set; }
        public DbSet<OrganizationSettings> OrganizationSettings { get; set; }
        public DbSet<OrganizationPolicy> OrganizationPolicies { get; set; }
        public DbSet<OrganizationPricingPolicy> OrganizationPricingPolicies { get; set; }
        public DbSet<OrganizationDataPolicy> OrganizationDataPolicies { get; set; }
        public DbSet<OrganizationDomain> OrganizationDomains { get; set; }
        public DbSet<OrganizationSSO> OrganizationSSOs { get; set; }
        public DbSet<OrganizationCapabilityAssignment> OrganizationCapabilityAssignments { get; set; }
        #endregion

        #region Platform Applications
        public DbSet<PlatformApplication> PlatformApplications { get; set; }
        public DbSet<PlatformApplicationApiKey> PlatformApplicationApiKeys { get; set; }
        public DbSet<PlatformApplicationAccessTemplate> PlatformApplicationAccessTemplates { get; set; }
        // [수정] DbSet 이름을 UserPlatformApplicationAccess로 통일
        public DbSet<UserPlatformApplicationAccess> UserPlatformApplicationAccess { get; set; }
        #endregion

        #region Audit & System
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<AuditTrailDetail> AuditTrailDetails { get; set; }
        public DbSet<SystemConfiguration> SystemConfigurations { get; set; }
        #endregion

        public AuthDbContext(DbContextOptions<AuthDbContext> options, IHttpContextAccessor? httpContextAccessor = null)
            : base(options)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseNpgsql()
                    .EnableSensitiveDataLogging(false)
                    .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
            }
        }

        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            // Auditable 엔티티 자동 처리
            var entries = ChangeTracker.Entries()
                .Where(e => e.Entity is Core.Entities.Base.AuditableEntity ||
                           e.Entity is Core.Entities.Base.SystemAuditableEntity);

            foreach (var entry in entries)
            {
                if (entry.Entity is Core.Entities.Base.AuditableEntity auditable)
                {
                    if (entry.State == EntityState.Added)
                    {
                        auditable.CreatedAt = DateTime.UtcNow;
                        auditable.CreatedByConnectedId = CurrentConnectedId;
                        auditable.OrganizationId = CurrentOrganizationId ?? auditable.OrganizationId;
                    }
                    else if (entry.State == EntityState.Modified)
                    {
                        auditable.UpdatedAt = DateTime.UtcNow;
                        auditable.UpdatedByConnectedId = CurrentConnectedId;
                    }
                }
                else if (entry.Entity is Core.Entities.Base.SystemAuditableEntity systemAuditable)
                {
                    if (entry.State == EntityState.Added)
                    {
                        systemAuditable.CreatedAt = DateTime.UtcNow;
                        systemAuditable.CreatedByConnectedId = CurrentConnectedId;
                    }
                    else if (entry.State == EntityState.Modified)
                    {
                        systemAuditable.UpdatedAt = DateTime.UtcNow;
                        systemAuditable.UpdatedByConnectedId = CurrentConnectedId;
                    }
                }
            }

            // Soft delete 처리
            var deletedEntries = ChangeTracker.Entries()
                .Where(e => e.State == EntityState.Deleted && e.Entity is Core.Entities.Base.BaseEntity);

            foreach (var entry in deletedEntries)
            {
                entry.State = EntityState.Modified;
                var entity = (Core.Entities.Base.BaseEntity)entry.Entity;
                entity.IsDeleted = true;
                entity.DeletedAt = DateTime.UtcNow;

                if (entity is Core.Entities.Base.AuditableEntity auditableEntity)
                {
                    auditableEntity.DeletedByConnectedId = CurrentConnectedId;
                }
                else if (entity is Core.Entities.Base.SystemAuditableEntity systemAuditableEntity)
                {
                    systemAuditableEntity.DeletedByConnectedId = CurrentConnectedId;
                }
            }

            return await base.SaveChangesAsync(cancellationToken);
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // PostgreSQL 스키마 설정
            modelBuilder.HasDefaultSchema("auth");

            // PostgreSQL 확장 활성화
            modelBuilder.HasPostgresExtension("uuid-ossp");
            modelBuilder.HasPostgresExtension("pg_trgm");

            #region Global Query Filters - 소프트 삭제 & RLS

            // 소프트 삭제 필터
            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                if (typeof(Core.Entities.Base.BaseEntity).IsAssignableFrom(entityType.ClrType))
                {
                    var parameter = Expression.Parameter(entityType.ClrType, "e");
                    var property = Expression.Property(parameter, nameof(Core.Entities.Base.BaseEntity.IsDeleted));
                    var filter = Expression.Lambda(
                        Expression.Equal(property, Expression.Constant(false)),
                        parameter);
                    modelBuilder.Entity(entityType.ClrType).HasQueryFilter(filter);
                }
            }

            // RLS (Row Level Security) - 조직 격리
            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                if (typeof(Core.Entities.Base.OrganizationScopedEntity).IsAssignableFrom(entityType.ClrType))
                {
                    var parameter = Expression.Parameter(entityType.ClrType, "e");
                    var property = Expression.Property(parameter, nameof(Core.Entities.Base.OrganizationScopedEntity.OrganizationId));
                    var filter = Expression.Lambda(
                        Expression.Equal(property, Expression.Property(Expression.Constant(this), nameof(CurrentOrganizationId))),
                        parameter);
                    modelBuilder.Entity(entityType.ClrType).HasQueryFilter(filter);
                }
            }
            #endregion

            #region User 도메인 설정
            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("users");
                entity.HasIndex(u => u.Email).IsUnique();
                entity.HasIndex(u => u.CreatedAt);
                entity.HasIndex(u => u.Username).IsUnique().HasFilter("username IS NOT NULL");
            });

            modelBuilder.Entity<UserProfile>(entity =>
            {
                entity.ToTable("user_profiles");
                entity.HasOne<User>()
                    .WithOne()
                    .HasForeignKey<UserProfile>(p => p.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<UserActivityLog>(entity =>
            {
                entity.ToTable("user_activity_logs");
                entity.HasIndex(l => l.ConnectedId);
                entity.HasIndex(l => l.Timestamp);
            });

            modelBuilder.Entity<UserFeatureProfile>(entity =>
            {
                entity.ToTable("user_feature_profiles");
                entity.HasIndex(p => p.UserId).IsUnique();
            });
            #endregion

            #region ConnectedId 관계 설정
            modelBuilder.Entity<ConnectedId>(entity =>
            {
                entity.ToTable("connected_ids");
                entity.HasIndex(c => new { c.UserId, c.OrganizationId }).IsUnique();
                entity.HasIndex(c => c.CreatedAt);

                entity.HasOne(c => c.User)
                    .WithMany()
                    .HasForeignKey(c => c.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(c => c.Organization)
                    .WithMany()
                    .HasForeignKey(c => c.OrganizationId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(c => c.MemberProfile)
                    .WithOne()
                    .HasForeignKey<OrganizationMemberProfile>(p => p.ConnectedId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(c => c.RoleAssignments)
                    .WithOne()
                    .HasForeignKey(r => r.ConnectedId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(c => c.Sessions)
                    .WithOne()
                    .HasForeignKey(s => s.ConnectedId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(c => c.InvitedBy)
                    .WithMany(c => c.InvitedMembers)
                    .HasForeignKey(c => c.InvitedByConnectedId)
                    .OnDelete(DeleteBehavior.Restrict);
            });

            modelBuilder.Entity<ConnectedIdContext>(entity =>
            {
                entity.ToTable("connected_id_contexts");
                entity.HasIndex(c => c.ConnectedId);
                entity.HasIndex(c => c.IsHotPath);
                entity.HasIndex(c => new { c.ConnectedId, c.ContextKey }).IsUnique();
            });

            modelBuilder.Entity<ConnectedIdRole>(entity =>
            {
                entity.ToTable("connected_id_roles");
                entity.HasIndex(cr => new { cr.ConnectedId, cr.RoleId, cr.ApplicationId }).IsUnique();
            });
            #endregion

            #region Session 설정
            modelBuilder.Entity<SessionEntity>(entity =>
            {
                entity.ToTable("sessions");
                entity.HasIndex(s => s.SessionToken).IsUnique();
                entity.HasIndex(s => s.ConnectedId);
                entity.HasIndex(s => s.ExpiresAt);
                entity.HasIndex(s => s.Status);
                entity.HasIndex(s => s.LastActivityAt);
            });

            modelBuilder.Entity<SessionActivityLog>(entity =>
            {
                entity.ToTable("session_activity_logs");
                entity.HasIndex(l => l.SessionId);
                entity.HasIndex(l => l.Timestamp);
            });
            #endregion

            #region 권한 관계 설정
            modelBuilder.Entity<Permission>(entity =>
            {
                entity.ToTable("permissions");
                entity.HasIndex(p => p.Scope).IsUnique();
                entity.HasIndex(p => p.Category);
                entity.HasIndex(p => p.IsSystemPermission);
                entity.HasIndex(p => p.ParentPermissionId);
                entity.HasIndex(p => new { p.ResourceType, p.ActionType });
                entity.HasIndex(p => p.IsActive);

                entity.HasOne(p => p.ParentPermission)
                    .WithMany(p => p.ChildPermissions)
                    .HasForeignKey(p => p.ParentPermissionId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(p => p.RolePermissions)
                    .WithOne(rp => rp.Permission)
                    .HasForeignKey(rp => rp.PermissionId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<Role>(entity =>
            {
                entity.ToTable("roles");
                entity.HasIndex(r => new { r.Name, r.OrganizationId }).IsUnique();
                entity.HasIndex(r => r.IsActive);

                entity.HasOne(r => r.ParentRole)
                    .WithMany(r => r.ChildRoles)
                    .HasForeignKey(r => r.ParentRoleId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasMany(r => r.RolePermissions)
                    .WithOne(rp => rp.Role)
                    .HasForeignKey(rp => rp.RoleId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<RolePermission>(entity =>
            {
                entity.ToTable("role_permissions");
                entity.HasIndex(rp => new { rp.RoleId, rp.PermissionId }).IsUnique();
            });

            modelBuilder.Entity<PermissionValidationLog>(entity =>
            {
                entity.ToTable("permission_validation_logs");
                entity.HasIndex(l => l.ConnectedId);
                entity.HasIndex(l => l.Timestamp);
            });
            #endregion

            #region Organization 설정
            modelBuilder.Entity<OrganizationEntity>(entity =>
            {
                entity.ToTable("organizations");
                entity.HasIndex(o => o.Name);
                entity.HasIndex(o => o.Slug).IsUnique();
                entity.HasIndex(o => o.ParentOrganizationId);
                entity.HasIndex(o => o.CreatedAt);
            });

            modelBuilder.Entity<OrganizationMembership>(entity =>
            {
                entity.ToTable("organization_memberships");
                entity.HasIndex(m => new { m.ConnectedId, m.OrganizationId }).IsUnique();
                entity.HasIndex(m => m.JoinedAt);
            });

            modelBuilder.Entity<OrganizationMemberProfile>(entity =>
            {
                entity.ToTable("organization_member_profiles");
                entity.HasIndex(p => p.ConnectedId).IsUnique();
            });

            modelBuilder.Entity<OrganizationSettings>(entity =>
            {
                entity.ToTable("organization_settings");
                entity.HasIndex(s => s.OrganizationId).IsUnique();
            });

            modelBuilder.Entity<OrganizationPolicy>(entity =>
            {
                entity.ToTable("organization_policies");
                entity.HasIndex(p => new { p.OrganizationId, p.PolicyType }).IsUnique();
            });

            modelBuilder.Entity<OrganizationDomain>(entity =>
            {
                entity.ToTable("organization_domains");
                entity.HasIndex(d => d.Domain).IsUnique();
                entity.HasIndex(d => d.OrganizationId);
            });

            modelBuilder.Entity<OrganizationSSO>(entity =>
            {
                entity.ToTable("organization_sso");
                entity.HasIndex(s => s.OrganizationId);
            });
            #endregion

            #region Platform Application 설정
            modelBuilder.Entity<PlatformApplication>(entity =>
            {
                entity.ToTable("platform_applications");
                entity.HasIndex(a => a.Name);
                entity.HasIndex(a => a.OrganizationId);
                entity.HasIndex(a => a.CreatedAt);
                entity.HasIndex(a => a.ApplicationType);
                entity.HasIndex(a => a.Status);
            });

            modelBuilder.Entity<PlatformApplicationApiKey>(entity =>
            {
                entity.ToTable("platform_application_api_keys");
                entity.HasIndex(k => k.KeyHash).IsUnique();
                entity.HasIndex(k => k.KeyPrefix);
                entity.HasIndex(k => k.ApplicationId);
                entity.HasIndex(k => k.ExpiresAt);
                entity.HasIndex(k => k.IsActive);
                entity.HasIndex(k => k.LastUsedAt);
                entity.HasIndex(k => new { k.ApplicationId, k.IsActive });
            });

            modelBuilder.Entity<PlatformApplicationAccessTemplate>(entity =>
            {
                entity.ToTable("platform_application_access_templates");

                // ApplicationId 제거 - 템플릿은 조직 레벨에서 관리
                // entity.HasIndex(t => t.ApplicationId); // 삭제

                // 조직별 템플릿 관리를 위한 인덱스
                entity.HasIndex(t => t.OrganizationId);
                entity.HasIndex(t => t.Name);
                entity.HasIndex(t => t.Level);
                entity.HasIndex(t => t.IsDefault);
                entity.HasIndex(t => t.IsActive);

                // 조직 내에서 템플릿 이름은 유니크해야 함
                entity.HasIndex(t => new { t.OrganizationId, t.Name }).IsUnique();

                // 조직별 기본 템플릿은 레벨당 하나만
                entity.HasIndex(t => new { t.OrganizationId, t.Level, t.IsDefault })
                    .HasFilter("\"IsDefault\" = true")
                    .IsUnique();
            });

            // [수정] UserPlatformApplicationAccess 인덱스 추가
            modelBuilder.Entity<UserPlatformApplicationAccess>(entity =>
            {
                entity.ToTable("user_platform_application_accesses");
                entity.HasIndex(a => new { a.ConnectedId, a.ApplicationId }).IsUnique();
                entity.HasIndex(a => new { a.OrganizationId, a.ApplicationId, a.IsActive });
                entity.HasIndex(a => new { a.AccessTemplateId, a.IsActive });
                entity.HasIndex(a => a.AccessLevel);
                entity.HasIndex(a => a.IsActive);
                entity.HasIndex(a => a.ExpiresAt);
                entity.HasIndex(a => a.LastAccessedAt);
                entity.HasIndex(a => a.IsInherited);
                entity.HasIndex(a => a.GrantedAt);
            });
            #endregion

            #region OAuth & Token 설정
            modelBuilder.Entity<OAuthClient>(entity =>
            {
                entity.ToTable("oauth_clients");
                entity.HasIndex(c => c.ClientId).IsUnique();
                entity.HasIndex(c => c.OrganizationId);
                entity.HasIndex(c => c.IsActive);
            });

            modelBuilder.Entity<AccessToken>(entity =>
            {
                entity.ToTable("access_tokens");
                entity.HasIndex(t => t.TokenHash).IsUnique();
                entity.HasIndex(t => t.ConnectedId);
                entity.HasIndex(t => t.ExpiresAt);
                entity.HasIndex(t => t.IsRevoked);
            });

            modelBuilder.Entity<RefreshToken>(entity =>
            {
                entity.ToTable("refresh_tokens");

                // 기본 인덱스
                entity.HasIndex(t => t.TokenHash).IsUnique();
                entity.HasIndex(t => t.ExpiresAt);
                entity.HasIndex(t => t.ConnectedId);
                entity.HasIndex(t => t.IsActive);
                entity.HasIndex(t => t.IsRevoked);
                entity.HasIndex(t => t.LastUsedAt);

                // 복합 인덱스
                entity.HasIndex(t => new { t.OrganizationId, t.ConnectedId });
                entity.HasIndex(t => new { t.ClientId, t.IsActive });

                // 사용 추적을 위한 인덱스
                entity.HasIndex(t => t.UsageCount);
                entity.HasIndex(t => new { t.IsActive, t.ExpiresAt })
                    .HasFilter("\"IsActive\" = true"); // 활성 토큰의 만료 체크용
            });
            #endregion

            #region Audit 설정
            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.ToTable("audit_logs");
                entity.HasIndex(l => l.ResourceType);
                entity.HasIndex(l => l.Action);
                entity.HasIndex(l => l.Timestamp);
                entity.HasIndex(l => l.PerformedByConnectedId);
                entity.HasIndex(l => l.RequestId).IsUnique()
                    .HasFilter("\"RequestId\" IS NOT NULL");
                entity.HasIndex(l => l.Severity);
                entity.HasIndex(l => l.Success);
                entity.HasIndex(l => l.IsArchived);
                entity.HasIndex(l => l.ActionType);

                // 복합 인덱스들
                entity.HasIndex(l => new { l.ResourceType, l.ResourceId });
                entity.HasIndex(l => new { l.PerformedByConnectedId, l.Timestamp });
                entity.HasIndex(l => new { l.TargetOrganizationId, l.Timestamp })
                    .HasFilter("\"TargetOrganizationId\" IS NOT NULL");
                entity.HasIndex(l => new { l.ApplicationId, l.Timestamp })
                    .HasFilter("\"ApplicationId\" IS NOT NULL");
            });
            #endregion

            modelBuilder.Entity<AuditTrailDetail>(entity =>
            {
                entity.ToTable("audit_trail_details");
                entity.HasIndex(d => d.AuditLogId);
                entity.HasIndex(d => d.FieldName);
            });

            modelBuilder.Entity<AuthenticationAttemptLog>(entity =>
            {
                entity.ToTable("authentication_attempt_logs");
                entity.HasIndex(l => l.Username);
                entity.HasIndex(l => l.IpAddress);
                entity.HasIndex(l => l.AttemptedAt);
                entity.HasIndex(l => l.IsSuccess);
                entity.HasIndex(l => new { l.Username, l.AttemptedAt });
                entity.HasIndex(l => new { l.IpAddress, l.AttemptedAt });
            });

            modelBuilder.Entity<AuthorizationAuditLog>(entity =>
            {
                entity.ToTable("authorization_audit_logs");
                entity.HasIndex(l => l.ConnectedId);
                entity.HasIndex(l => l.Resource);
                entity.HasIndex(l => l.Action);
                entity.HasIndex(l => l.Timestamp);
                entity.HasIndex(l => new { l.ConnectedId, l.Timestamp });
                entity.HasIndex(l => new { l.Resource, l.Action, l.Timestamp });
            });


            #region System 설정
            modelBuilder.Entity<SystemConfiguration>(entity =>
            {
                entity.ToTable("system_configurations");
                entity.HasIndex(c => c.ConfigurationKey).IsUnique();
                entity.HasIndex(c => c.Category);
                // IsActive 관련 인덱스 제거
                // entity.HasIndex(c => c.IsActive);
                // entity.HasIndex(c => new { c.Category, c.IsActive });

                // 대신 시간 기반 활성화를 위한 인덱스 추가
                entity.HasIndex(c => c.EffectiveFrom);
                entity.HasIndex(c => c.EffectiveUntil);
                entity.HasIndex(c => c.ConfigurationType);
                entity.HasIndex(c => c.IsReadOnly);
            });
            #endregion
        }
    }
}