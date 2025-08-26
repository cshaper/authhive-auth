CREATE TABLE IF NOT EXISTS "__EFMigrationsHistory" (
    "MigrationId" character varying(150) NOT NULL,
    "ProductVersion" character varying(32) NOT NULL,
    CONSTRAINT "PK___EFMigrationsHistory" PRIMARY KEY ("MigrationId")
);

START TRANSACTION;
DO $EF$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = 'auth') THEN
        CREATE SCHEMA auth;
    END IF;
END $EF$;

CREATE TABLE auth."Organizations" (
    "Id" uuid NOT NULL,
    "OrganizationKey" varchar NOT NULL,
    "ParentOrganizationId" uuid,
    "Name" varchar NOT NULL,
    "Category" integer NOT NULL,
    "Description" varchar,
    "Status" integer NOT NULL,
    "Type" integer NOT NULL,
    "HierarchyType" integer NOT NULL,
    "Region" varchar NOT NULL,
    "LogoUrl" varchar,
    "Website" varchar,
    "DashboardUrl" varchar,
    "InvitationRedirectUrl" varchar,
    "SsoRedirectUrl" varchar,
    "BrandColor" varchar,
    "EstablishedDate" timestamp with time zone,
    "EmployeeRange" varchar,
    "Industry" varchar,
    "ActivatedAt" timestamp with time zone,
    "SuspendedAt" timestamp with time zone,
    "SuspensionReason" varchar,
    "Metadata" varchar,
    "PolicyInheritanceMode" integer NOT NULL,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "ParentId" uuid,
    "Path" varchar NOT NULL,
    "Level" integer NOT NULL,
    "SortOrder" integer NOT NULL,
    CONSTRAINT "PK_Organizations" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_Organizations_Organizations_ParentId" FOREIGN KEY ("ParentId") REFERENCES auth."Organizations" ("Id")
);

CREATE TABLE auth."Permissions" (
    "Id" uuid NOT NULL,
    "Scope" varchar NOT NULL,
    "Name" varchar NOT NULL,
    "Description" varchar,
    "Category" integer NOT NULL,
    "ParentPermissionId" uuid,
    "Level" integer NOT NULL,
    "IsSystemPermission" boolean NOT NULL,
    "RequiredMembershipTypes" varchar,
    "IsActive" boolean NOT NULL,
    "ResourceType" varchar,
    "ActionType" varchar,
    "ScopeOrganization" varchar,
    "ScopeApplication" varchar,
    "ScopeResource" varchar NOT NULL,
    "ScopeAction" varchar NOT NULL,
    "HasWildcard" boolean NOT NULL,
    "ScopeLevel" integer NOT NULL,
    "NormalizedScope" varchar NOT NULL,
    "Metadata" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    CONSTRAINT "PK_Permissions" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_Permissions_Permissions_ParentPermissionId" FOREIGN KEY ("ParentPermissionId") REFERENCES auth."Permissions" ("Id") ON DELETE RESTRICT
);

CREATE TABLE auth."Users" (
    "Id" uuid NOT NULL,
    "Status" integer NOT NULL,
    "Email" varchar,
    "Username" varchar,
    "DisplayName" varchar,
    "ExternalUserId" varchar,
    "ExternalSystemType" varchar,
    "EmailVerified" boolean NOT NULL,
    "TwoFactorEnabled" boolean NOT NULL,
    "LastLoginAt" timestamp with time zone,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    CONSTRAINT "PK_Users" PRIMARY KEY ("Id")
);

CREATE TABLE auth."OrganizationDataPolicies" (
    "Id" uuid NOT NULL,
    "UserMetadataMode" integer NOT NULL,
    "CollectMemberProfile" boolean NOT NULL,
    "CollectUserProfile" boolean NOT NULL,
    "ApiKeyManagement" integer NOT NULL,
    "DataRetentionDays" integer NOT NULL,
    "AuditLogRetentionDays" integer NOT NULL,
    "PointTransactionRetentionDays" integer NOT NULL,
    "AllowDataExport" boolean NOT NULL,
    "AllowSqlDumpExport" boolean NOT NULL,
    "AllowBulkApiAccess" boolean NOT NULL,
    "EnableAutoAnonymization" boolean NOT NULL,
    "AnonymizationAfterDays" integer NOT NULL,
    "AllowExternalSync" boolean NOT NULL,
    "AllowedExternalSystems" varchar,
    "EncryptionLevel" integer NOT NULL,
    "PolicyVersion" integer NOT NULL,
    "LastReviewedAt" timestamp with time zone,
    "NextReviewDate" timestamp with time zone,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OrganizationDataPolicies" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OrganizationDataPolicies_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."PlatformApplications" (
    "Id" uuid NOT NULL,
    "Name" varchar NOT NULL,
    "Description" varchar,
    "ApplicationKey" varchar NOT NULL,
    "ApplicationType" integer NOT NULL,
    "Status" integer NOT NULL,
    "IsPublic" boolean NOT NULL,
    "Environment" integer NOT NULL,
    "CallbackUrls" varchar,
    "AllowedOrigins" varchar,
    "AllowedScopes" varchar,
    "AccessTokenLifetime" integer NOT NULL,
    "RefreshTokenLifetime" integer NOT NULL,
    "ApiRateLimitPerMinute" integer NOT NULL,
    "DailyApiQuota" bigint NOT NULL,
    "MonthlyApiQuota" bigint NOT NULL,
    "CurrentDailyApiUsage" bigint NOT NULL,
    "CurrentMonthlyApiUsage" bigint NOT NULL,
    "StorageQuotaGB" numeric NOT NULL,
    "CurrentStorageUsageGB" numeric NOT NULL,
    "BandwidthQuotaGB" numeric NOT NULL,
    "CurrentBandwidthUsageGB" numeric NOT NULL,
    "LastDailyResetAt" timestamp with time zone,
    "LastMonthlyResetAt" timestamp with time zone,
    "UsePointsForApiCalls" boolean NOT NULL,
    "PointsPerApiCall" numeric(18,4) NOT NULL,
    "BlockOnInsufficientPoints" boolean NOT NULL,
    "IconUrl" varchar,
    "HomepageUrl" varchar,
    "PrivacyPolicyUrl" varchar,
    "TermsOfServiceUrl" varchar,
    "AdditionalSettings" varchar,
    "DeployedAt" timestamp with time zone,
    "LastActivityAt" timestamp with time zone,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_PlatformApplications" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_PlatformApplications_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."ConnectedIds" (
    "Id" uuid NOT NULL,
    "UserId" uuid NOT NULL,
    "Status" integer NOT NULL,
    "Provider" varchar NOT NULL,
    "MembershipType" integer NOT NULL,
    "DisplayName" varchar,
    "JoinedAt" timestamp with time zone NOT NULL,
    "LastActiveAt" timestamp with time zone,
    "InvitedByConnectedId" uuid,
    "InvitedAt" timestamp with time zone,
    "MetadataMode" integer NOT NULL,
    "UserId1" uuid,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_ConnectedIds" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_ConnectedIds_ConnectedIds_InvitedByConnectedId" FOREIGN KEY ("InvitedByConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE RESTRICT,
    CONSTRAINT "FK_ConnectedIds_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_ConnectedIds_Users_UserId" FOREIGN KEY ("UserId") REFERENCES auth."Users" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_ConnectedIds_Users_UserId1" FOREIGN KEY ("UserId1") REFERENCES auth."Users" ("Id")
);

CREATE TABLE auth."UserProfiles" (
    "Id" uuid NOT NULL,
    "UserId" uuid NOT NULL,
    "PhoneNumber" varchar,
    "PhoneVerified" boolean NOT NULL,
    "ProfileImageUrl" varchar,
    "TimeZone" varchar,
    "PreferredLanguage" varchar,
    "Bio" varchar,
    "NotificationSettings" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    CONSTRAINT "PK_UserProfiles" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_UserProfiles_Users_UserId" FOREIGN KEY ("UserId") REFERENCES auth."Users" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."OAuthClients" (
    "Id" uuid NOT NULL,
    "ApplicationId" uuid NOT NULL,
    "ClientId" varchar NOT NULL,
    "ClientSecretHash" varchar,
    "ClientName" varchar NOT NULL,
    "Description" varchar,
    "ClientType" integer NOT NULL,
    "AllowedGrantTypes" varchar NOT NULL,
    "AllowedScopes" varchar NOT NULL,
    "RedirectUris" varchar,
    "PostLogoutRedirectUris" varchar,
    "AllowedCorsOrigins" varchar,
    "AccessTokenLifetime" integer NOT NULL,
    "RefreshTokenLifetime" integer NOT NULL,
    "AuthorizationCodeLifetime" integer NOT NULL,
    "IsActive" boolean NOT NULL,
    "RequirePkce" boolean NOT NULL,
    "RequireClientSecret" boolean NOT NULL,
    "RequireConsent" boolean NOT NULL,
    "AllowOfflineAccess" boolean NOT NULL,
    "AllowPlainTextPkce" boolean NOT NULL,
    "UpdateAccessTokenClaimsOnRefresh" boolean NOT NULL,
    "RefreshTokenUsage" integer NOT NULL,
    "RefreshTokenExpiration" integer NOT NULL,
    "AbsoluteRefreshTokenLifetime" integer NOT NULL,
    "SlidingRefreshTokenLifetime" integer NOT NULL,
    "LastUsedAt" timestamp with time zone,
    "AllowedResponseTypes" varchar,
    "LogoUri" varchar,
    "ClientUri" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OAuthClients" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OAuthClients_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."PlatformApplicationApiKeys" (
    "Id" uuid NOT NULL,
    "ApplicationId" uuid NOT NULL,
    "KeyName" varchar NOT NULL,
    "ApiKey" varchar,
    "KeyHash" varchar NOT NULL,
    "KeyPrefix" varchar NOT NULL,
    "KeyLastFour" varchar NOT NULL,
    "KeyManagementType" varchar NOT NULL,
    "GoogleSecretName" varchar,
    "Scopes" varchar NOT NULL,
    "RateLimitPerMinute" integer NOT NULL,
    "AllowedIPs" varchar,
    "KeySource" integer NOT NULL,
    "PermissionLevel" integer NOT NULL,
    "RelatedEntityId" uuid,
    "RelatedEntityType" varchar,
    "IsActive" boolean NOT NULL,
    "ExpiresAt" timestamp with time zone,
    "LastUsedAt" timestamp with time zone,
    "TotalRequestCount" bigint NOT NULL,
    "LastErrorAt" timestamp with time zone,
    "ErrorCount" integer NOT NULL,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_PlatformApplicationApiKeys" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_PlatformApplicationApiKeys_PlatformApplications_Application~" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."Roles" (
    "Id" uuid NOT NULL,
    "Name" varchar NOT NULL,
    "Description" varchar,
    "RoleKey" varchar NOT NULL,
    "Scope" integer NOT NULL,
    "ApplicationId" uuid,
    "IsActive" boolean NOT NULL,
    "Priority" integer NOT NULL,
    "Category" integer,
    "Level" integer NOT NULL,
    "ParentRoleId" uuid,
    "Metadata" varchar,
    "Tags" varchar,
    "MaxAssignments" integer NOT NULL,
    "ExpiresAt" timestamp with time zone,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_Roles" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_Roles_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_Roles_Roles_ParentRoleId" FOREIGN KEY ("ParentRoleId") REFERENCES auth."Roles" ("Id") ON DELETE RESTRICT
);

CREATE TABLE auth."UserFeatureProfiles" (
    "Id" uuid NOT NULL,
    "UserId" uuid NOT NULL,
    "ActiveAddons" varchar NOT NULL,
    "ApiAccess" varchar NOT NULL,
    "FeatureSettings" varchar,
    "FeatureUsageStats" varchar,
    "LastActivityAt" timestamp with time zone,
    "TotalApiCalls" integer NOT NULL,
    "ActiveAddonCount" integer NOT NULL,
    "ProfileCompleteness" integer NOT NULL,
    "MostUsedFeature" varchar,
    "RecommendedAddons" varchar,
    "Metadata" varchar,
    "PlatformApplicationId" uuid,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    CONSTRAINT "PK_UserFeatureProfiles" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_UserFeatureProfiles_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_UserFeatureProfiles_PlatformApplications_PlatformApplicatio~" FOREIGN KEY ("PlatformApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_UserFeatureProfiles_Users_UserId" FOREIGN KEY ("UserId") REFERENCES auth."Users" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."AuditLogs" (
    "Id" uuid NOT NULL,
    "PerformedByConnectedId" uuid,
    "ApplicationId" uuid,
    "ActionType" integer NOT NULL,
    "Action" varchar NOT NULL,
    "ResourceType" varchar,
    "ResourceId" varchar,
    "IPAddress" varchar,
    "UserAgent" varchar,
    "RequestId" varchar,
    "Success" boolean NOT NULL,
    "ErrorCode" varchar,
    "ErrorMessage" varchar,
    "Metadata" varchar,
    "DurationMs" integer,
    "Severity" integer NOT NULL,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    CONSTRAINT "PK_AuditLogs" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_AuditLogs_ConnectedIds_PerformedByConnectedId" FOREIGN KEY ("PerformedByConnectedId") REFERENCES auth."ConnectedIds" ("Id")
);

CREATE TABLE auth."OrganizationCapabilityAssignments" (
    "Id" uuid NOT NULL,
    "CapabilityType" integer NOT NULL,
    "IsActive" boolean NOT NULL,
    "IsPrimary" boolean NOT NULL,
    "AssignedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone,
    "AssignmentReason" varchar,
    "AssignedByConnectedId" uuid,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OrganizationCapabilityAssignments" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OrganizationCapabilityAssignments_ConnectedIds_AssignedByCo~" FOREIGN KEY ("AssignedByConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_OrganizationCapabilityAssignments_Organizations_Organizatio~" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."OrganizationDomains" (
    "Id" uuid NOT NULL,
    "Domain" varchar NOT NULL,
    "DomainType" integer NOT NULL,
    "IsVerified" boolean NOT NULL,
    "VerificationToken" varchar,
    "VerifiedAt" timestamp with time zone,
    "VerifiedByConnectedId" uuid,
    "SSLEnabled" boolean NOT NULL,
    "CertificateExpiry" timestamp with time zone,
    "IsActive" boolean NOT NULL,
    "VerificationMethod" varchar,
    "LastVerificationAttempt" timestamp with time zone,
    "VerificationAttemptCount" integer NOT NULL,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OrganizationDomains" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OrganizationDomains_ConnectedIds_VerifiedByConnectedId" FOREIGN KEY ("VerifiedByConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_OrganizationDomains_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."OrganizationMemberProfiles" (
    "Id" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "JobTitle" varchar,
    "Department" varchar,
    "EmployeeId" varchar,
    "OfficeLocation" varchar,
    "ManagerConnectedId" uuid,
    "ConnectedIdNavigationId" uuid NOT NULL,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OrganizationMemberProfiles" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OrganizationMemberProfiles_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_OrganizationMemberProfiles_ConnectedIds_ConnectedIdNavigati~" FOREIGN KEY ("ConnectedIdNavigationId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_OrganizationMemberProfiles_ConnectedIds_ManagerConnectedId" FOREIGN KEY ("ManagerConnectedId") REFERENCES auth."ConnectedIds" ("Id")
);

CREATE TABLE auth."OrganizationMemberships" (
    "Id" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "MemberRole" varchar NOT NULL,
    "Status" integer NOT NULL,
    "MembershipType" integer NOT NULL,
    "JoinedAt" timestamp with time zone NOT NULL,
    "InvitedByConnectedId" uuid,
    "InvitationToken" varchar,
    "AcceptedAt" timestamp with time zone,
    "ExpiresAt" timestamp with time zone,
    "LastActivityAt" timestamp with time zone,
    "JobTitle" varchar,
    "Department" varchar,
    "AccessLevel" integer NOT NULL,
    "AdditionalPermissions" varchar,
    "RestrictedPermissions" varchar,
    "NotificationPreferences" varchar,
    "Metadata" varchar,
    "DeactivationReason" varchar,
    "DeactivatedAt" timestamp with time zone,
    "DeactivatedByConnectedId" uuid,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OrganizationMemberships" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OrganizationMemberships_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_OrganizationMemberships_ConnectedIds_DeactivatedByConnected~" FOREIGN KEY ("DeactivatedByConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_OrganizationMemberships_ConnectedIds_InvitedByConnectedId" FOREIGN KEY ("InvitedByConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_OrganizationMemberships_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."OrganizationPolicies" (
    "Id" uuid NOT NULL,
    "PolicyType" integer NOT NULL,
    "PolicyName" varchar NOT NULL,
    "Description" varchar,
    "IsEnabled" boolean NOT NULL,
    "PolicyRules" varchar NOT NULL,
    "ApplicableCapabilities" varchar,
    "Priority" integer NOT NULL,
    "EffectiveFrom" timestamp with time zone NOT NULL,
    "EffectiveTo" timestamp with time zone,
    "IsSystemPolicy" boolean NOT NULL,
    "IsInheritable" boolean NOT NULL,
    "Version" integer NOT NULL,
    "LastValidatedAt" timestamp with time zone,
    "LastValidatedByConnectedId" uuid,
    "IsDetailedAuditEnabled" boolean NOT NULL,
    "IsActivityTrackingEnabled" boolean NOT NULL,
    "IsRealTimeMonitoringEnabled" boolean NOT NULL,
    "ComplianceStandards" varchar,
    "ViolationAction" varchar NOT NULL,
    "Metadata" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OrganizationPolicies" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OrganizationPolicies_ConnectedIds_LastValidatedByConnectedId" FOREIGN KEY ("LastValidatedByConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_OrganizationPolicies_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."OrganizationPricingPolicies" (
    "Id" uuid NOT NULL,
    "PolicyName" varchar NOT NULL,
    "Description" varchar,
    "PolicyType" integer NOT NULL,
    "TargetType" integer NOT NULL,
    "TargetKey" varchar,
    "DiscountRate" numeric(5,4) NOT NULL,
    "DiscountAmount" numeric(18,2) NOT NULL,
    "CustomPrice" numeric(18,2),
    "PointBonusRate" numeric(5,4) NOT NULL,
    "CustomMAUOverageRate" numeric(18,4),
    "CustomApiUsageRate" numeric(18,4),
    "IsActive" boolean NOT NULL,
    "EffectiveFrom" timestamp with time zone NOT NULL,
    "EffectiveTo" timestamp with time zone,
    "Priority" integer NOT NULL,
    "ApprovedByConnectedId" uuid,
    "ApprovedAt" timestamp with time zone,
    "ConditionRules" varchar,
    "Metadata" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OrganizationPricingPolicies" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OrganizationPricingPolicies_ConnectedIds_ApprovedByConnecte~" FOREIGN KEY ("ApprovedByConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_OrganizationPricingPolicies_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."Sessions" (
    "Id" uuid NOT NULL,
    "SessionToken" varchar NOT NULL,
    "UserId" uuid NOT NULL,
    "OrganizationId" uuid,
    "ConnectedId" uuid,
    "ParentSessionId" uuid,
    "SessionType" integer NOT NULL,
    "Level" integer NOT NULL,
    "Status" integer NOT NULL,
    "IPAddress" varchar,
    "UserAgent" varchar,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "LastActivityAt" timestamp with time zone NOT NULL,
    "ActiveChildSessionId" uuid,
    "RiskScore" integer NOT NULL,
    "GrpcEnabled" boolean NOT NULL,
    "PubSubNotifications" boolean NOT NULL,
    "TokenId" varchar,
    "TokenExpiresAt" timestamp with time zone,
    "ConnectedIdNavigationId" uuid,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    CONSTRAINT "PK_Sessions" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_Sessions_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_Sessions_ConnectedIds_ConnectedIdNavigationId" FOREIGN KEY ("ConnectedIdNavigationId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_Sessions_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id"),
    CONSTRAINT "FK_Sessions_Sessions_ParentSessionId" FOREIGN KEY ("ParentSessionId") REFERENCES auth."Sessions" ("Id"),
    CONSTRAINT "FK_Sessions_Users_UserId" FOREIGN KEY ("UserId") REFERENCES auth."Users" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."UserActivityLogs" (
    "Id" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "ApplicationId" uuid,
    "ActivityType" integer NOT NULL,
    "ActivityDescription" varchar,
    "ResourceType" varchar,
    "ResourceId" varchar,
    "IPAddress" varchar,
    "UserAgent" varchar,
    "Location" varchar,
    "DeviceFingerprint" varchar,
    "RiskScore" integer NOT NULL,
    "IsSuccessful" boolean NOT NULL,
    "ErrorCode" varchar,
    "ErrorMessage" varchar,
    "ActivityStatus" integer,
    "DurationMs" integer,
    "SessionId" varchar,
    "Metadata" varchar,
    "IsDetailedMonitoring" boolean NOT NULL,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_UserActivityLogs" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_UserActivityLogs_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_UserActivityLogs_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_UserActivityLogs_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id")
);

CREATE TABLE auth."ConnectedIdRoles" (
    "Id" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "RoleId" uuid NOT NULL,
    "ApplicationId" uuid,
    "AssignedByConnectedId" uuid NOT NULL,
    "AssignedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone,
    "Conditions" varchar,
    "IsActive" boolean NOT NULL,
    "Reason" varchar,
    "AssignmentType" integer NOT NULL,
    "InheritedFromId" uuid,
    "Priority" integer NOT NULL,
    "Metadata" varchar,
    "LastVerifiedAt" timestamp with time zone,
    "ConnectedId1" uuid NOT NULL,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_ConnectedIdRoles" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_ConnectedIdRoles_ConnectedIdRoles_InheritedFromId" FOREIGN KEY ("InheritedFromId") REFERENCES auth."ConnectedIdRoles" ("Id"),
    CONSTRAINT "FK_ConnectedIdRoles_ConnectedIds_AssignedByConnectedId" FOREIGN KEY ("AssignedByConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_ConnectedIdRoles_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_ConnectedIdRoles_ConnectedIds_ConnectedId1" FOREIGN KEY ("ConnectedId1") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_ConnectedIdRoles_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_ConnectedIdRoles_Roles_RoleId" FOREIGN KEY ("RoleId") REFERENCES auth."Roles" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."OrganizationSSO" (
    "Id" uuid NOT NULL,
    "SSOType" integer NOT NULL,
    "ProviderName" integer NOT NULL,
    "Configuration" varchar NOT NULL,
    "IsActive" boolean NOT NULL,
    "IsDefault" boolean NOT NULL,
    "AutoCreateUsers" boolean NOT NULL,
    "DefaultRoleId" uuid,
    "DisplayName" varchar,
    "IconUrl" varchar,
    "LastTestedAt" timestamp with time zone,
    "LastTestedByConnectedId" uuid,
    "Priority" integer NOT NULL,
    "AttributeMapping" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OrganizationSSO" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OrganizationSSO_ConnectedIds_LastTestedByConnectedId" FOREIGN KEY ("LastTestedByConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_OrganizationSSO_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_OrganizationSSO_Roles_DefaultRoleId" FOREIGN KEY ("DefaultRoleId") REFERENCES auth."Roles" ("Id")
);

CREATE TABLE auth."PlatformApplicationAccessTemplates" (
    "Id" uuid NOT NULL,
    "Level" integer NOT NULL,
    "Name" varchar NOT NULL,
    "Description" varchar,
    "DefaultRoleId" uuid,
    "PermissionPatterns" varchar NOT NULL,
    "Priority" integer NOT NULL,
    "IsActive" boolean NOT NULL,
    "IsSystemTemplate" boolean NOT NULL,
    "IncludesBillingAccess" boolean NOT NULL,
    "Metadata" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_PlatformApplicationAccessTemplates" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_PlatformApplicationAccessTemplates_Roles_DefaultRoleId" FOREIGN KEY ("DefaultRoleId") REFERENCES auth."Roles" ("Id")
);

CREATE TABLE auth."RolePermissions" (
    "Id" uuid NOT NULL,
    "RoleId" uuid NOT NULL,
    "PermissionId" uuid NOT NULL,
    "PermissionScope" varchar NOT NULL,
    "GrantedByConnectedId" uuid,
    "GrantedAt" timestamp with time zone NOT NULL,
    "Conditions" varchar,
    "ExpiresAt" timestamp with time zone,
    "IsActive" boolean NOT NULL,
    "Reason" varchar,
    "Priority" integer NOT NULL,
    "IsInherited" boolean NOT NULL,
    "InheritedFromId" uuid,
    "Metadata" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    CONSTRAINT "PK_RolePermissions" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_RolePermissions_ConnectedIds_GrantedByConnectedId" FOREIGN KEY ("GrantedByConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_RolePermissions_Permissions_PermissionId" FOREIGN KEY ("PermissionId") REFERENCES auth."Permissions" ("Id") ON DELETE RESTRICT,
    CONSTRAINT "FK_RolePermissions_RolePermissions_InheritedFromId" FOREIGN KEY ("InheritedFromId") REFERENCES auth."RolePermissions" ("Id"),
    CONSTRAINT "FK_RolePermissions_Roles_RoleId" FOREIGN KEY ("RoleId") REFERENCES auth."Roles" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."AuditTrailDetails" (
    "Id" uuid NOT NULL,
    "AuditLogId" uuid NOT NULL,
    "FieldName" varchar,
    "FieldType" integer NOT NULL,
    "OldValue" varchar,
    "NewValue" varchar,
    "ActionType" integer NOT NULL,
    "IsSecureField" boolean NOT NULL,
    "ValidationResult" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "IsSystemManaged" boolean NOT NULL,
    "SystemCode" varchar,
    CONSTRAINT "PK_AuditTrailDetails" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_AuditTrailDetails_AuditLogs_AuditLogId" FOREIGN KEY ("AuditLogId") REFERENCES auth."AuditLogs" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."AuthenticationAttemptLogs" (
    "Id" uuid NOT NULL,
    "UserId" uuid,
    "ConnectedId" uuid,
    "ApplicationId" uuid,
    "Method" integer NOT NULL,
    "Username" varchar,
    "Provider" varchar,
    "IsSuccess" boolean NOT NULL,
    "FailureReason" integer,
    "FailureMessage" varchar,
    "ErrorCode" varchar,
    "AttemptedAt" timestamp with time zone NOT NULL,
    "ProcessingTimeMs" integer,
    "IpAddress" varchar NOT NULL,
    "UserAgent" varchar,
    "DeviceId" varchar,
    "DeviceType" varchar,
    "Location" varchar,
    "CountryCode" varchar,
    "ConsecutiveFailures" integer NOT NULL,
    "TriggeredAccountLock" boolean NOT NULL,
    "MfaRequired" boolean NOT NULL,
    "MfaCompleted" boolean,
    "SessionId" uuid,
    "RiskScore" integer NOT NULL,
    "IsSuspicious" boolean NOT NULL,
    "AdditionalData" varchar,
    "RequestId" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    CONSTRAINT "PK_AuthenticationAttemptLogs" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_AuthenticationAttemptLogs_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_AuthenticationAttemptLogs_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_AuthenticationAttemptLogs_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_AuthenticationAttemptLogs_Sessions_SessionId" FOREIGN KEY ("SessionId") REFERENCES auth."Sessions" ("Id"),
    CONSTRAINT "FK_AuthenticationAttemptLogs_Users_UserId" FOREIGN KEY ("UserId") REFERENCES auth."Users" ("Id")
);

CREATE TABLE auth."AuthorizationAuditLogs" (
    "Id" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "ApplicationId" uuid,
    "Resource" varchar NOT NULL,
    "Action" varchar NOT NULL,
    "FullScope" varchar,
    "ResourceType" integer,
    "ResourceId" uuid,
    "ResourceName" varchar,
    "IsAllowed" boolean NOT NULL,
    "DenialReason" integer,
    "DenialMessage" varchar,
    "DenialCode" varchar,
    "Timestamp" timestamp with time zone NOT NULL,
    "ProcessingTimeMs" integer,
    "EvaluatedRoles" varchar,
    "EvaluatedPermissions" varchar,
    "EvaluatedPolicies" varchar,
    "IpAddress" varchar NOT NULL,
    "UserAgent" varchar,
    "SessionId" uuid,
    "HttpMethod" varchar,
    "ApiEndpoint" varchar,
    "CacheStatus" integer,
    "RiskScore" integer NOT NULL,
    "IsRepeatedFailure" boolean NOT NULL,
    "ConsecutiveFailures" integer NOT NULL,
    "SecurityAlert" boolean NOT NULL,
    "Context" varchar,
    "RequestId" varchar,
    "TraceId" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_AuthorizationAuditLogs" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_AuthorizationAuditLogs_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_AuthorizationAuditLogs_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_AuthorizationAuditLogs_Sessions_SessionId" FOREIGN KEY ("SessionId") REFERENCES auth."Sessions" ("Id")
);

CREATE TABLE auth."ConnectedIdContexts" (
    "Id" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "SessionId" uuid,
    "ApplicationId" uuid,
    "ContextKey" varchar NOT NULL,
    "ContextType" integer NOT NULL,
    "ContextData" varchar NOT NULL,
    "MetadataJson" varchar,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "LastAccessedAt" timestamp with time zone NOT NULL,
    "AccessCount" integer NOT NULL,
    "IsHotPath" boolean NOT NULL,
    "GrpcCacheEnabled" boolean NOT NULL,
    "AutoRefresh" boolean NOT NULL,
    "Priority" integer NOT NULL,
    "Checksum" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_ConnectedIdContexts" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_ConnectedIdContexts_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_ConnectedIdContexts_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_ConnectedIdContexts_Sessions_SessionId" FOREIGN KEY ("SessionId") REFERENCES auth."Sessions" ("Id")
);

CREATE TABLE auth."OAuthAccessTokens" (
    "Id" uuid NOT NULL,
    "ClientId" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "SessionId" uuid,
    "TokenValue" varchar NOT NULL,
    "TokenHash" varchar NOT NULL,
    "TokenType" integer NOT NULL,
    "Scopes" varchar NOT NULL,
    "IssuedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "IsActive" boolean NOT NULL,
    "IsRevoked" boolean NOT NULL,
    "RevokedAt" timestamp with time zone,
    "RevokedReason" varchar,
    "Issuer" varchar,
    "Audience" varchar,
    "Subject" varchar,
    "JwtId" varchar,
    "IPAddress" varchar,
    "UserAgent" varchar,
    "UsageCount" integer NOT NULL,
    "LastUsedAt" timestamp with time zone,
    "LastUsedIP" varchar,
    "GrantType" integer NOT NULL,
    "ParentTokenId" uuid,
    "AdditionalClaims" varchar,
    "ApplicationId" uuid,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OAuthAccessTokens" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OAuthAccessTokens_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_OAuthAccessTokens_OAuthAccessTokens_ParentTokenId" FOREIGN KEY ("ParentTokenId") REFERENCES auth."OAuthAccessTokens" ("Id"),
    CONSTRAINT "FK_OAuthAccessTokens_OAuthClients_ClientId" FOREIGN KEY ("ClientId") REFERENCES auth."OAuthClients" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_OAuthAccessTokens_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_OAuthAccessTokens_Sessions_SessionId" FOREIGN KEY ("SessionId") REFERENCES auth."Sessions" ("Id")
);

CREATE TABLE auth."PermissionValidationLogs" (
    "Id" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "ApplicationId" uuid,
    "RequestedScope" varchar NOT NULL,
    "RequestId" varchar,
    "IsAllowed" boolean NOT NULL,
    "ValidationResult" integer NOT NULL,
    "ConnectedIdValidationResult" integer,
    "ValidationStep" varchar,
    "RolesFound" varchar,
    "PermissionsChecked" varchar,
    "DenialReason" varchar,
    "ValidationDurationMs" integer,
    "CacheStatus" integer,
    "IPAddress" varchar,
    "UserAgent" varchar,
    "SessionId" uuid,
    "ResourceType" integer,
    "ResourceId" uuid,
    "RequestContext" varchar,
    "PermissionId" uuid,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_PermissionValidationLogs" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_PermissionValidationLogs_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_PermissionValidationLogs_Organizations_OrganizationId" FOREIGN KEY ("OrganizationId") REFERENCES auth."Organizations" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_PermissionValidationLogs_Permissions_PermissionId" FOREIGN KEY ("PermissionId") REFERENCES auth."Permissions" ("Id"),
    CONSTRAINT "FK_PermissionValidationLogs_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_PermissionValidationLogs_Sessions_SessionId" FOREIGN KEY ("SessionId") REFERENCES auth."Sessions" ("Id")
);

CREATE TABLE auth."SessionActivityLogs" (
    "Id" uuid NOT NULL,
    "SessionId" uuid NOT NULL,
    "UserId" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "ApplicationId" uuid,
    "ActivityType" integer NOT NULL,
    "Category" integer NOT NULL,
    "Description" varchar NOT NULL,
    "Details" varchar,
    "OccurredAt" timestamp with time zone NOT NULL,
    "CompletedAt" timestamp with time zone,
    "DurationMs" integer,
    "IsSuccess" boolean NOT NULL,
    "FailureReason" varchar,
    "ErrorCode" varchar,
    "ResourceType" varchar,
    "ResourceId" uuid,
    "ResourceName" varchar,
    "Action" varchar,
    "PageUrl" varchar,
    "PageTitle" varchar,
    "ReferrerUrl" varchar,
    "ApiEndpoint" varchar,
    "HttpMethod" varchar,
    "HttpStatusCode" integer,
    "ResponseTimeMs" integer,
    "IPAddress" varchar,
    "UserAgent" varchar,
    "DeviceType" integer,
    "Browser" integer,
    "BrowserVersion" varchar,
    "OperatingSystem" integer,
    "OSVersion" varchar,
    "DeviceInfo" varchar,
    "CountryCode" varchar,
    "Location" varchar,
    "Latitude" numeric(10,8),
    "Longitude" numeric(11,8),
    "RiskScore" integer NOT NULL,
    "IsSuspicious" boolean NOT NULL,
    "SecurityAlert" boolean NOT NULL,
    "SecurityContext" varchar,
    "TraceId" varchar,
    "SpanId" varchar,
    "ParentSpanId" varchar,
    "AnalyticsSessionId" varchar,
    "Metadata" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_SessionActivityLogs" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_SessionActivityLogs_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_SessionActivityLogs_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_SessionActivityLogs_Sessions_SessionId" FOREIGN KEY ("SessionId") REFERENCES auth."Sessions" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_SessionActivityLogs_Users_UserId" FOREIGN KEY ("UserId") REFERENCES auth."Users" ("Id") ON DELETE CASCADE
);

CREATE TABLE auth."UserPlatformApplicationAccess" (
    "Id" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "ApplicationId" uuid NOT NULL,
    "AccessLevel" integer NOT NULL,
    "AccessTemplateId" uuid,
    "RoleId" uuid,
    "AdditionalPermissions" varchar,
    "ExcludedPermissions" varchar,
    "Scopes" varchar NOT NULL,
    "GrantedAt" timestamp with time zone NOT NULL,
    "GrantedByConnectedId" uuid,
    "ExpiresAt" timestamp with time zone,
    "IsActive" boolean NOT NULL,
    "LastAccessedAt" timestamp with time zone,
    "GrantReason" varchar,
    "IsInherited" boolean NOT NULL,
    "InheritedFromId" uuid,
    "Metadata" varchar,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_UserPlatformApplicationAccess" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_UserPlatformApplicationAccess_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_UserPlatformApplicationAccess_ConnectedIds_GrantedByConnect~" FOREIGN KEY ("GrantedByConnectedId") REFERENCES auth."ConnectedIds" ("Id"),
    CONSTRAINT "FK_UserPlatformApplicationAccess_PlatformApplicationAccessTemp~" FOREIGN KEY ("AccessTemplateId") REFERENCES auth."PlatformApplicationAccessTemplates" ("Id"),
    CONSTRAINT "FK_UserPlatformApplicationAccess_PlatformApplications_Applicat~" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_UserPlatformApplicationAccess_Roles_RoleId" FOREIGN KEY ("RoleId") REFERENCES auth."Roles" ("Id")
);

CREATE TABLE auth."OAuthRefreshTokens" (
    "Id" uuid NOT NULL,
    "AccessTokenId" uuid NOT NULL,
    "ClientId" uuid NOT NULL,
    "ConnectedId" uuid NOT NULL,
    "TokenValue" varchar NOT NULL,
    "TokenHash" varchar NOT NULL,
    "IssuedAt" timestamp with time zone NOT NULL,
    "ExpiresAt" timestamp with time zone NOT NULL,
    "IsActive" boolean NOT NULL,
    "IsRevoked" boolean NOT NULL,
    "RevokedAt" timestamp with time zone,
    "RevokedReason" varchar,
    "UsageCount" integer NOT NULL,
    "LastUsedAt" timestamp with time zone,
    "LastUsedIP" varchar,
    "MaxUsageCount" integer NOT NULL,
    "Scopes" varchar NOT NULL,
    "AdditionalClaims" varchar,
    "SessionId" uuid,
    "ApplicationId" uuid,
    "IsDeleted" boolean NOT NULL,
    "DeletedAt" timestamp with time zone,
    "CreatedAt" timestamp with time zone NOT NULL,
    "OrganizationId" uuid NOT NULL,
    "CreatedByConnectedId" uuid,
    "UpdatedAt" timestamp with time zone,
    "UpdatedByConnectedId" uuid,
    "DeletedByConnectedId" uuid,
    "RowVersion" bytea,
    CONSTRAINT "PK_OAuthRefreshTokens" PRIMARY KEY ("Id"),
    CONSTRAINT "FK_OAuthRefreshTokens_ConnectedIds_ConnectedId" FOREIGN KEY ("ConnectedId") REFERENCES auth."ConnectedIds" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_OAuthRefreshTokens_OAuthAccessTokens_AccessTokenId" FOREIGN KEY ("AccessTokenId") REFERENCES auth."OAuthAccessTokens" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_OAuthRefreshTokens_OAuthClients_ClientId" FOREIGN KEY ("ClientId") REFERENCES auth."OAuthClients" ("Id") ON DELETE CASCADE,
    CONSTRAINT "FK_OAuthRefreshTokens_PlatformApplications_ApplicationId" FOREIGN KEY ("ApplicationId") REFERENCES auth."PlatformApplications" ("Id"),
    CONSTRAINT "FK_OAuthRefreshTokens_Sessions_SessionId" FOREIGN KEY ("SessionId") REFERENCES auth."Sessions" ("Id")
);

CREATE INDEX "IX_AuditLogs_PerformedByConnectedId" ON auth."AuditLogs" ("PerformedByConnectedId");

CREATE INDEX "IX_AuditTrailDetails_AuditLogId" ON auth."AuditTrailDetails" ("AuditLogId");

CREATE INDEX "IX_AuthenticationAttemptLogs_ApplicationId" ON auth."AuthenticationAttemptLogs" ("ApplicationId");

CREATE INDEX "IX_AuthenticationAttemptLogs_ConnectedId" ON auth."AuthenticationAttemptLogs" ("ConnectedId");

CREATE INDEX "IX_AuthenticationAttemptLogs_OrganizationId" ON auth."AuthenticationAttemptLogs" ("OrganizationId");

CREATE INDEX "IX_AuthenticationAttemptLogs_SessionId" ON auth."AuthenticationAttemptLogs" ("SessionId");

CREATE INDEX "IX_AuthenticationAttemptLogs_UserId" ON auth."AuthenticationAttemptLogs" ("UserId");

CREATE INDEX "IX_AuthorizationAuditLogs_ApplicationId" ON auth."AuthorizationAuditLogs" ("ApplicationId");

CREATE INDEX "IX_AuthorizationAuditLogs_ConnectedId" ON auth."AuthorizationAuditLogs" ("ConnectedId");

CREATE INDEX "IX_AuthorizationAuditLogs_SessionId" ON auth."AuthorizationAuditLogs" ("SessionId");

CREATE INDEX "IX_ConnectedIdContexts_ApplicationId" ON auth."ConnectedIdContexts" ("ApplicationId");

CREATE INDEX "IX_ConnectedIdContexts_ConnectedId" ON auth."ConnectedIdContexts" ("ConnectedId");

CREATE INDEX "IX_ConnectedIdContexts_SessionId" ON auth."ConnectedIdContexts" ("SessionId");

CREATE INDEX "IX_ConnectedIdRoles_ApplicationId" ON auth."ConnectedIdRoles" ("ApplicationId");

CREATE INDEX "IX_ConnectedIdRoles_AssignedByConnectedId" ON auth."ConnectedIdRoles" ("AssignedByConnectedId");

CREATE INDEX "IX_ConnectedIdRoles_ConnectedId" ON auth."ConnectedIdRoles" ("ConnectedId");

CREATE INDEX "IX_ConnectedIdRoles_ConnectedId1" ON auth."ConnectedIdRoles" ("ConnectedId1");

CREATE INDEX "IX_ConnectedIdRoles_InheritedFromId" ON auth."ConnectedIdRoles" ("InheritedFromId");

CREATE INDEX "IX_ConnectedIdRoles_RoleId" ON auth."ConnectedIdRoles" ("RoleId");

CREATE INDEX "IX_ConnectedIds_InvitedByConnectedId" ON auth."ConnectedIds" ("InvitedByConnectedId");

CREATE INDEX "IX_ConnectedIds_OrganizationId" ON auth."ConnectedIds" ("OrganizationId");

CREATE UNIQUE INDEX "IX_ConnectedIds_UserId_OrganizationId" ON auth."ConnectedIds" ("UserId", "OrganizationId");

CREATE INDEX "IX_ConnectedIds_UserId1" ON auth."ConnectedIds" ("UserId1");

CREATE INDEX "IX_OAuthAccessTokens_ApplicationId" ON auth."OAuthAccessTokens" ("ApplicationId");

CREATE INDEX "IX_OAuthAccessTokens_ClientId" ON auth."OAuthAccessTokens" ("ClientId");

CREATE INDEX "IX_OAuthAccessTokens_ConnectedId" ON auth."OAuthAccessTokens" ("ConnectedId");

CREATE INDEX "IX_OAuthAccessTokens_ParentTokenId" ON auth."OAuthAccessTokens" ("ParentTokenId");

CREATE INDEX "IX_OAuthAccessTokens_SessionId" ON auth."OAuthAccessTokens" ("SessionId");

CREATE INDEX "IX_OAuthClients_ApplicationId" ON auth."OAuthClients" ("ApplicationId");

CREATE INDEX "IX_OAuthRefreshTokens_AccessTokenId" ON auth."OAuthRefreshTokens" ("AccessTokenId");

CREATE INDEX "IX_OAuthRefreshTokens_ApplicationId" ON auth."OAuthRefreshTokens" ("ApplicationId");

CREATE INDEX "IX_OAuthRefreshTokens_ClientId" ON auth."OAuthRefreshTokens" ("ClientId");

CREATE INDEX "IX_OAuthRefreshTokens_ConnectedId" ON auth."OAuthRefreshTokens" ("ConnectedId");

CREATE INDEX "IX_OAuthRefreshTokens_SessionId" ON auth."OAuthRefreshTokens" ("SessionId");

CREATE INDEX "IX_OrganizationCapabilityAssignments_AssignedByConnectedId" ON auth."OrganizationCapabilityAssignments" ("AssignedByConnectedId");

CREATE INDEX "IX_OrganizationCapabilityAssignments_OrganizationId" ON auth."OrganizationCapabilityAssignments" ("OrganizationId");

CREATE UNIQUE INDEX "IX_OrganizationDataPolicies_OrganizationId" ON auth."OrganizationDataPolicies" ("OrganizationId");

CREATE INDEX "IX_OrganizationDomains_OrganizationId" ON auth."OrganizationDomains" ("OrganizationId");

CREATE INDEX "IX_OrganizationDomains_VerifiedByConnectedId" ON auth."OrganizationDomains" ("VerifiedByConnectedId");

CREATE UNIQUE INDEX "IX_OrganizationMemberProfiles_ConnectedId" ON auth."OrganizationMemberProfiles" ("ConnectedId");

CREATE INDEX "IX_OrganizationMemberProfiles_ConnectedIdNavigationId" ON auth."OrganizationMemberProfiles" ("ConnectedIdNavigationId");

CREATE INDEX "IX_OrganizationMemberProfiles_ManagerConnectedId" ON auth."OrganizationMemberProfiles" ("ManagerConnectedId");

CREATE INDEX "IX_OrganizationMemberships_ConnectedId" ON auth."OrganizationMemberships" ("ConnectedId");

CREATE INDEX "IX_OrganizationMemberships_DeactivatedByConnectedId" ON auth."OrganizationMemberships" ("DeactivatedByConnectedId");

CREATE INDEX "IX_OrganizationMemberships_InvitedByConnectedId" ON auth."OrganizationMemberships" ("InvitedByConnectedId");

CREATE INDEX "IX_OrganizationMemberships_OrganizationId" ON auth."OrganizationMemberships" ("OrganizationId");

CREATE INDEX "IX_OrganizationPolicies_LastValidatedByConnectedId" ON auth."OrganizationPolicies" ("LastValidatedByConnectedId");

CREATE INDEX "IX_OrganizationPolicies_OrganizationId" ON auth."OrganizationPolicies" ("OrganizationId");

CREATE INDEX "IX_OrganizationPricingPolicies_ApprovedByConnectedId" ON auth."OrganizationPricingPolicies" ("ApprovedByConnectedId");

CREATE INDEX "IX_OrganizationPricingPolicies_OrganizationId" ON auth."OrganizationPricingPolicies" ("OrganizationId");

CREATE INDEX "IX_Organizations_ParentId" ON auth."Organizations" ("ParentId");

CREATE INDEX "IX_OrganizationSSO_DefaultRoleId" ON auth."OrganizationSSO" ("DefaultRoleId");

CREATE INDEX "IX_OrganizationSSO_LastTestedByConnectedId" ON auth."OrganizationSSO" ("LastTestedByConnectedId");

CREATE INDEX "IX_OrganizationSSO_OrganizationId" ON auth."OrganizationSSO" ("OrganizationId");

CREATE INDEX "IX_Permissions_ParentPermissionId" ON auth."Permissions" ("ParentPermissionId");

CREATE INDEX "IX_PermissionValidationLogs_ApplicationId" ON auth."PermissionValidationLogs" ("ApplicationId");

CREATE INDEX "IX_PermissionValidationLogs_ConnectedId" ON auth."PermissionValidationLogs" ("ConnectedId");

CREATE INDEX "IX_PermissionValidationLogs_OrganizationId" ON auth."PermissionValidationLogs" ("OrganizationId");

CREATE INDEX "IX_PermissionValidationLogs_PermissionId" ON auth."PermissionValidationLogs" ("PermissionId");

CREATE INDEX "IX_PermissionValidationLogs_SessionId" ON auth."PermissionValidationLogs" ("SessionId");

CREATE INDEX "IX_PlatformApplicationAccessTemplates_DefaultRoleId" ON auth."PlatformApplicationAccessTemplates" ("DefaultRoleId");

CREATE INDEX "IX_PlatformApplicationApiKeys_ApplicationId" ON auth."PlatformApplicationApiKeys" ("ApplicationId");

CREATE INDEX "IX_PlatformApplications_OrganizationId" ON auth."PlatformApplications" ("OrganizationId");

CREATE INDEX "IX_RolePermissions_GrantedByConnectedId" ON auth."RolePermissions" ("GrantedByConnectedId");

CREATE INDEX "IX_RolePermissions_InheritedFromId" ON auth."RolePermissions" ("InheritedFromId");

CREATE INDEX "IX_RolePermissions_PermissionId" ON auth."RolePermissions" ("PermissionId");

CREATE INDEX "IX_RolePermissions_RoleId" ON auth."RolePermissions" ("RoleId");

CREATE INDEX "IX_Roles_ApplicationId" ON auth."Roles" ("ApplicationId");

CREATE INDEX "IX_Roles_ParentRoleId" ON auth."Roles" ("ParentRoleId");

CREATE INDEX "IX_SessionActivityLogs_ApplicationId" ON auth."SessionActivityLogs" ("ApplicationId");

CREATE INDEX "IX_SessionActivityLogs_ConnectedId" ON auth."SessionActivityLogs" ("ConnectedId");

CREATE INDEX "IX_SessionActivityLogs_SessionId" ON auth."SessionActivityLogs" ("SessionId");

CREATE INDEX "IX_SessionActivityLogs_UserId" ON auth."SessionActivityLogs" ("UserId");

CREATE INDEX "IX_Sessions_ConnectedId" ON auth."Sessions" ("ConnectedId");

CREATE INDEX "IX_Sessions_ConnectedIdNavigationId" ON auth."Sessions" ("ConnectedIdNavigationId");

CREATE INDEX "IX_Sessions_OrganizationId" ON auth."Sessions" ("OrganizationId");

CREATE INDEX "IX_Sessions_ParentSessionId" ON auth."Sessions" ("ParentSessionId");

CREATE UNIQUE INDEX "IX_Sessions_SessionToken" ON auth."Sessions" ("SessionToken");

CREATE INDEX "IX_Sessions_UserId" ON auth."Sessions" ("UserId");

CREATE INDEX "IX_UserActivityLogs_ApplicationId" ON auth."UserActivityLogs" ("ApplicationId");

CREATE INDEX "IX_UserActivityLogs_ConnectedId" ON auth."UserActivityLogs" ("ConnectedId");

CREATE INDEX "IX_UserActivityLogs_OrganizationId" ON auth."UserActivityLogs" ("OrganizationId");

CREATE INDEX "IX_UserFeatureProfiles_OrganizationId" ON auth."UserFeatureProfiles" ("OrganizationId");

CREATE INDEX "IX_UserFeatureProfiles_PlatformApplicationId" ON auth."UserFeatureProfiles" ("PlatformApplicationId");

CREATE UNIQUE INDEX "IX_UserFeatureProfiles_UserId" ON auth."UserFeatureProfiles" ("UserId");

CREATE INDEX "IX_UserPlatformApplicationAccess_AccessTemplateId" ON auth."UserPlatformApplicationAccess" ("AccessTemplateId");

CREATE INDEX "IX_UserPlatformApplicationAccess_ApplicationId" ON auth."UserPlatformApplicationAccess" ("ApplicationId");

CREATE INDEX "IX_UserPlatformApplicationAccess_ConnectedId" ON auth."UserPlatformApplicationAccess" ("ConnectedId");

CREATE INDEX "IX_UserPlatformApplicationAccess_GrantedByConnectedId" ON auth."UserPlatformApplicationAccess" ("GrantedByConnectedId");

CREATE INDEX "IX_UserPlatformApplicationAccess_RoleId" ON auth."UserPlatformApplicationAccess" ("RoleId");

CREATE UNIQUE INDEX "IX_UserProfiles_UserId" ON auth."UserProfiles" ("UserId");

CREATE UNIQUE INDEX "IX_Users_Email" ON auth."Users" ("Email");

INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
VALUES ('20250822171709_InitialCreate', '9.0.0');

COMMIT;

