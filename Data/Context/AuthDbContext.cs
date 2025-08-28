using Microsoft.EntityFrameworkCore;
using AuthHive.Core.Entities.User;
using AuthHive.Core.Entities.Auth;
using AuthHive.Core.Entities.Organization;
using AuthHive.Core.Entities.PlatformApplications;
using AuthHive.Core.Entities.Audit;

namespace AuthHive.Auth.Data.Context
{
    public class AuthDbContext : DbContext
    {
        // User 도메인
        public DbSet<User> Users { get; set; }
        public DbSet<UserProfile> UserProfiles { get; set; }
        public DbSet<UserActivityLog> UserActivityLogs { get; set; }
        public DbSet<UserFeatureProfile> UserFeatureProfiles { get; set; }

        // Auth 도메인 (핵심)
        public DbSet<ConnectedId> ConnectedIds { get; set; }
        public DbSet<ConnectedIdContext> ConnectedIdContexts { get; set; }
        public DbSet<ConnectedIdRole> ConnectedIdRoles { get; set; }
        public DbSet<SessionEntity> Sessions { get; set; }
        public DbSet<SessionActivityLog> SessionActivityLogs { get; set; }
        
        // 권한 관리
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<RolePermission> RolePermissions { get; set; }
        public DbSet<PermissionValidationLog> PermissionValidationLogs { get; set; }
        
        // 인증 관련
        public DbSet<AuthenticationAttemptLog> AuthenticationAttemptLogs { get; set; }
        public DbSet<AuthorizationAuditLog> AuthorizationAuditLogs { get; set; }
        
        // OAuth
        public DbSet<OAuthClient> OAuthClients { get; set; }
        public DbSet<OAuthAccessToken> OAuthAccessTokens { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        
        // Organization (기본)
        public DbSet<Organization> Organizations { get; set; }
        public DbSet<OrganizationMembership> OrganizationMemberships { get; set; }
        public DbSet<OrganizationMemberProfile> OrganizationMemberProfiles { get; set; }
        public DbSet<OrganizationSSO> OrganizationSSOs { get; set; }
        
        // Application Access
        public DbSet<UserPlatformApplicationAccess> UserApplicationAccesses { get; set; }
        
        // Audit
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<AuditTrailDetail> AuditTrailDetails { get; set; }

        public AuthDbContext(DbContextOptions<AuthDbContext> options) 
            : base(options)
        {
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            // PostgreSQL을 사용하도록 명시적으로 설정
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseNpgsql();
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // PostgreSQL을 위한 스키마 설정
            modelBuilder.HasDefaultSchema("auth");

            // 모든 문자열 속성을 varchar로 설정
            foreach (var entity in modelBuilder.Model.GetEntityTypes())
            {
                foreach (var property in entity.GetProperties())
                {
                    if (property.ClrType == typeof(string))
                    {
                        property.SetColumnType("varchar");
                    }
                }
            }

            // ConnectedId 관계들
            modelBuilder.Entity<ConnectedId>()
                .HasOne(c => c.MemberProfile)
                .WithOne()
                .HasForeignKey<OrganizationMemberProfile>(p => p.ConnectedId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ConnectedId>()
                .HasOne(c => c.User)
                .WithMany()
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ConnectedId>()
                .HasOne(c => c.Organization)
                .WithMany()
                .HasForeignKey(c => c.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ConnectedId>()
                .HasMany(c => c.RoleAssignments)
                .WithOne()
                .HasForeignKey(r => r.ConnectedId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ConnectedId>()
                .HasMany(c => c.Sessions)
                .WithOne()
                .HasForeignKey(s => s.ConnectedId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ConnectedId>()
                .HasOne(c => c.InvitedBy)
                .WithMany(c => c.InvitedMembers)
                .HasForeignKey(c => c.InvitedByConnectedId)
                .OnDelete(DeleteBehavior.Restrict);

            // Role 관계들
            modelBuilder.Entity<Role>()
                .HasMany(r => r.RolePermissions)
                .WithOne(rp => rp.Role)
                .HasForeignKey(rp => rp.RoleId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Role>()
                .HasOne(r => r.ParentRole)
                .WithMany(r => r.ChildRoles)
                .HasForeignKey(r => r.ParentRoleId)
                .OnDelete(DeleteBehavior.Restrict);

            // Permission 관계들
            modelBuilder.Entity<Permission>()
                .HasMany(p => p.RolePermissions)
                .WithOne(rp => rp.Permission)
                .HasForeignKey(rp => rp.PermissionId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<Permission>()
                .HasOne(p => p.ParentPermission)
                .WithMany(p => p.ChildPermissions)
                .HasForeignKey(p => p.ParentPermissionId)
                .OnDelete(DeleteBehavior.Restrict);

            // 기본 인덱스
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();

            modelBuilder.Entity<ConnectedId>()
                .HasIndex(c => new { c.UserId, c.OrganizationId })
                .IsUnique();

            modelBuilder.Entity<SessionEntity>()
                .HasIndex(s => s.SessionToken)
                .IsUnique();

            base.OnModelCreating(modelBuilder);
        }
    }
}
