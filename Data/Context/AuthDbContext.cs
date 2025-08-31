using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Entities.Audit;
using AuthHive.Core.Entities.System;
using Microsoft.AspNetCore.Http;
using System.Linq.Expressions;

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
        public DbSet<Organization> Organizations { get; set; }
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
        public DbSet<UserPlatformApplicationAccess> UserApplicationAccesses { get; set; }
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
                // Username은 nullable이므로 조건부 인덱스
                entity.HasIndex(u => u.Username).IsUnique().HasFilter("username IS NOT NULL");
                // LastLoginAt은 Entity에 필요 (추가 권장)
            });

            modelBuilder.Entity<UserProfile>(entity =>
            {
                entity.ToTable("user_profiles");
                entity.HasOne<User>()
                    .WithOne()
                    .HasForeignKey<UserProfile>(p => p.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
                // PhoneNumber는 여기에 있어야 함
            });

            modelBuilder.Entity<UserActivityLog>(entity =>
            {
                entity.ToTable("user_activity_logs");
                entity.HasIndex(l => l.ConnectedId);
                entity.HasIndex(l => l.Timestamp);
                // ActivityType은 Enum이어야 함
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
                // MembershipStatus는 Enum이어야 함

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
                // ContextType은 Enum이어야 함
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
                // SessionLevel은 Enum이어야 함 (추가 필요)
            });

            modelBuilder.Entity<SessionActivityLog>(entity =>
            {
                entity.ToTable("session_activity_logs");
                entity.HasIndex(l => l.SessionId);
                entity.HasIndex(l => l.Timestamp);
                // ActivityType은 Enum이어야 함
            });
            #endregion

            #region 권한 관계 설정
            modelBuilder.Entity<Permission>(entity =>
            {
                entity.ToTable("permissions");
                entity.HasIndex(p => p.Scope).IsUnique();
                entity.HasIndex(p => p.IsActive);
                // ResourceType은 Enum이어야 함

                entity.HasOne(p => p.ParentPermission)
                    .WithMany(p => p.ChildPermissions)
                    .HasForeignKey(p => p.ParentPermissionId)
                    .OnDelete(DeleteBehavior.Restrict);

                entity.HasMany(p => p.RolePermissions)
                    .WithOne(rp => rp.Permission)
                    .HasForeignKey(rp => rp.PermissionId)
                    .OnDelete(DeleteBehavior.Restrict);
            });

            modelBuilder.Entity<Role>(entity =>
            {
                entity.ToTable("roles");
                entity.HasIndex(r => new { r.Name, r.OrganizationId }).IsUnique();
                entity.HasIndex(r => r.IsActive);
                // IsSystem은 Entity에 있어야 함 (시스템 정의 역할 구분)

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
                // ValidationResult는 Enum이어야 함
            });
            #endregion

            #region Organization 설정
            modelBuilder.Entity<Organization>(entity =>
            {
                entity.ToTable("organizations");
                entity.HasIndex(o => o.Name);
                entity.HasIndex(o => o.Slug).IsUnique();
                entity.HasIndex(o => o.ParentOrganizationId);
                entity.HasIndex(o => o.CreatedAt);
                // OrganizationStatus는 Enum이어야 함
            });

            modelBuilder.Entity<OrganizationMembership>(entity =>
            {
                entity.ToTable("organization_memberships");
                entity.HasIndex(m => new { m.ConnectedId, m.OrganizationId }).IsUnique();
                entity.HasIndex(m => m.JoinedAt);
                // MembershipStatus는 Enum이어야 함
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
                // VerificationStatus는 Enum이어야 함
            });

            modelBuilder.Entity<OrganizationSSO>(entity =>
            {
                entity.ToTable("organization_sso");
                entity.HasIndex(s => s.OrganizationId);
                // ProviderType은 Enum이어야 함
            });
            #endregion

            #region Platform Application 설정
            modelBuilder.Entity<PlatformApplication>(entity =>
            {
                entity.ToTable("platform_applications");
                entity.HasIndex(a => a.Name);
                entity.HasIndex(a => a.OrganizationId);
                // ApplicationStatus는 Enum이어야 함
            });

            modelBuilder.Entity<PlatformApplicationApiKey>(entity =>
            {
                entity.ToTable("platform_application_api_keys");
                entity.HasIndex(k => k.KeyHash).IsUnique();
                entity.HasIndex(k => k.ApplicationId);
                entity.HasIndex(k => k.ExpiresAt);
            });

            modelBuilder.Entity<UserPlatformApplicationAccess>(entity =>
            {
                entity.ToTable("user_platform_application_accesses");
                entity.HasIndex(a => new { a.ConnectedId, a.ApplicationId }).IsUnique();
                // AccessLevel은 Enum이어야 함
            });
            #endregion

            #region OAuth & Token 설정
            modelBuilder.Entity<OAuthClient>(entity =>
            {
                entity.ToTable("oauth_clients");
                entity.HasIndex(c => c.ClientId).IsUnique();
            });

            // Guid와 Nullable<Guid> 비교 문제 해결
            modelBuilder.Entity<AccessToken>()
                .HasQueryFilter(e => e.OrganizationId != Guid.Empty);

            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<RefreshToken>(entity =>
            {
                entity.ToTable("refresh_tokens");
                entity.HasIndex(t => t.TokenHash).IsUnique();
                entity.HasIndex(t => t.ExpiresAt);
                entity.HasIndex(t => t.ConnectedId);
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
            });

            modelBuilder.Entity<AuditTrailDetail>(entity =>
            {
                entity.ToTable("audit_trail_details");
                entity.HasIndex(d => d.AuditLogId);
            });

            modelBuilder.Entity<AuthenticationAttemptLog>(entity =>
            {
                entity.ToTable("authentication_attempt_logs");
                entity.HasIndex(l => l.Username);
                entity.HasIndex(l => l.IpAddress);
                entity.HasIndex(l => l.AttemptedAt);
                entity.HasIndex(l => l.IsSuccess);
            });

            modelBuilder.Entity<AuthorizationAuditLog>(entity =>
            {
                entity.ToTable("authorization_audit_logs");
                entity.HasIndex(l => l.ConnectedId);
                entity.HasIndex(l => l.Resource);
                entity.HasIndex(l => l.Action);
                entity.HasIndex(l => l.Timestamp);
            });
            #endregion

            #region System 설정
            modelBuilder.Entity<SystemConfiguration>(entity =>
            {
                entity.ToTable("system_configurations");
                entity.HasIndex(c => c.ConfigurationKey).IsUnique();
                entity.HasIndex(c => c.Category);
            });
            #endregion

            base.OnModelCreating(modelBuilder);
        }
    }
}