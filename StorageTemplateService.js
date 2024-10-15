class StorageTemplateService {
    constructor() {
        this.templates = {
            aws_s3_template: this.getAwsS3Template(),
            azure_storage_template: this.getAzureStorageTemplate(),
            gcp_storage_template: this.getGcpStorageTemplate(),
        };
    }

    getAwsS3Template() {
        return `package aws.s3.policies

# 1. Enforce S3 Access Points in VPC Only
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_access_point"
    not resource.change.after.vpc_configuration
    msg = sprintf("S3 Access Point '%s' must be configured in a VPC", [resource.change.after.name])
}

# 2. Enforce Public Access Blocks on S3 Access Points
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_access_point"
    not resource.change.after.public_access_block
    msg = sprintf("S3 Access Point '%s' must have public access blocks enabled", [resource.change.after.name])
}

# 3. Enforce Account-Level Public Access Blocks
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.account_level_public_access_block
    msg = sprintf("S3 bucket '%s' must have account-level public access blocks enabled", [resource.change.after.bucket])
}

# 4. Prohibit ACLs on S3 Buckets
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.acl != "private"
    msg = sprintf("S3 bucket '%s' must not use ACLs", [resource.change.after.bucket])
}

# 5. Prohibit Blacklisted Actions on S3 Buckets
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    action := resource.change.after.blacklisted_actions[_]
    msg = sprintf("S3 bucket '%s' contains blacklisted action '%s'", [resource.change.after.bucket, action])
}

# 6. Enforce Cross-Region Replication Enabled
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.cross_region_replication.enabled
    msg = sprintf("S3 bucket '%s' must have cross-region replication enabled", [resource.change.after.bucket])
}

# 7. Enforce Default Lock on S3 Buckets
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.default_lock.enabled
    msg = sprintf("S3 bucket '%s' must have default lock enabled", [resource.change.after.bucket])
}

# 8. Prohibit Public Access at the Bucket Level
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.public_access_block.allow_public_acls == true
    msg = sprintf("S3 bucket '%s' must not allow public ACLs", [resource.change.after.bucket])
}

# 9. Enforce Bucket Logging Enabled
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.logging.enabled
    msg = sprintf("S3 bucket '%s' must have logging enabled", [resource.change.after.bucket])
}

# 10. Enforce MFA Delete on S3 Buckets
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.mfa_delete.enabled
    msg = sprintf("S3 bucket '%s' must have MFA Delete enabled", [resource.change.after.bucket])
}

# 11. Enforce Server-Side Encryption Enabled
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.server_side_encryption.enabled
    msg = sprintf("S3 bucket '%s' must have server-side encryption enabled", [resource.change.after.bucket])
}

# 12. Enforce SSL Requests Only
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.ssl_requests_only
    msg = sprintf("S3 bucket '%s' must enforce SSL requests only", [resource.change.after.bucket])
}

# 13. Enforce Versioning Enabled on S3 Buckets
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.versioning.enabled
    msg = sprintf("S3 bucket '%s' must have versioning enabled", [resource.change.after.bucket])
}

# 14. Enforce KMS Encryption for Default Encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.default_encryption.kms_key_id
    msg = sprintf("S3 bucket '%s' must use KMS for default encryption", [resource.change.after.bucket])
}

# 15. Enforce Event Notifications Enabled
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.event_notifications
    msg = sprintf("S3 bucket '%s' must have event notifications enabled", [resource.change.after.bucket])
}

# 16. Enforce Last Backup Recovery Point Created
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.last_backup_recovery_point
    msg = sprintf("S3 bucket '%s' must have a last backup recovery point created", [resource.change.after.bucket])
}

# 17. Enforce Lifecycle Policy Check
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.lifecycle_policy
    msg = sprintf("S3 bucket '%s' must have a lifecycle policy configured", [resource.change.after.bucket])
}

# 18. Enforce Restore Time Target
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.restore_time_target > 24
    msg = sprintf("S3 bucket '%s' must meet restore time target of 24 hours or less", [resource.change.after.bucket])
}

# 19. Enforce Air-Gapped Vault for S3 Resources
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.logically_air_gapped
    msg = sprintf("S3 bucket '%s' must be in a logically air-gapped vault", [resource.change.after.bucket])
}

# 20. Enforce Backup Plan Protection for S3 Resources
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.backup_plan_protection
    msg = sprintf("S3 bucket '%s' must be protected by a backup plan", [resource.change.after.bucket])
}

# 21. Enforce Version Lifecycle Policy Check
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.version_lifecycle_policy
    msg = sprintf("S3 bucket '%s' must have a version lifecycle policy configured", [resource.change.after.bucket])
}
`;
    }

    getAzureStorageTemplate() {
        return `package azure.storage.policies

# 1. Enforce HTTPS Traffic Only on Storage Accounts
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.enable_https_traffic_only
    msg = sprintf("Azure Storage Account '%s' must enforce HTTPS traffic only", [resource.change.after.name])
}

# 2. Enforce Public Access Block on Storage Accounts
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.public_access_block
    msg = sprintf("Azure Storage Account '%s' must have public access block enabled", [resource.change.after.name])
}

# 3. Enforce Default Encryption on Storage Accounts
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.encryption.services.blob.enabled
    msg = sprintf("Azure Storage Account '%s' must have default encryption enabled for blob services", [resource.change.after.name])
}

# 4. Enforce Soft Delete for Blob Services
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.blob_properties.delete_retention_policy.enabled
    msg = sprintf("Azure Storage Account '%s' must have soft delete enabled for blob services", [resource.change.after.name])
}

# 5. Enforce Logging on Storage Accounts
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.logging.read
    msg = sprintf("Azure Storage Account '%s' must have logging enabled", [resource.change.after.name])
}

# 6. Enforce Private Endpoint Connection
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.private_endpoint_connections[_].private_endpoint.id
    msg = sprintf("Azure Storage Account '%s' must have a private endpoint connection", [resource.change.after.name])
}

# 7. Enforce Replication for Storage Accounts
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.account_replication_type == "GRS" # Geo-Redundant Storage
    msg = sprintf("Azure Storage Account '%s' must use Geo-Redundant Storage (GRS) for replication", [resource.change.after.name])
}

# 8. Enforce Immutable Blob Storage
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.immutable_storage_with_versioning.enabled
    msg = sprintf("Azure Storage Account '%s' must have immutable blob storage with versioning enabled", [resource.change.after.name])
}

# 9. Enforce Customer-Managed Keys for Encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.encryption.key_source == "Microsoft.Keyvault"
    msg = sprintf("Azure Storage Account '%s' must use customer-managed keys from Key Vault for encryption", [resource.change.after.name])
}

# 10. Enforce Network Access Rules on Storage Accounts
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    count(resource.change.after.network_rules.default_action == "Deny") == 0
    msg = sprintf("Azure Storage Account '%s' must have network access rules configured to deny by default", [resource.change.after.name])
}
`;
    }

    getGcpStorageTemplate() {
        return `package gcp.storage.policies

# 1. Enforce Uniform Bucket-Level Access
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.uniform_bucket_level_access.enabled
    msg = sprintf("GCP Storage Bucket '%s' must have uniform bucket-level access enabled", [resource.change.after.name])
}

# 2. Enforce Default Encryption with Customer-Managed Keys
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.encryption.default_kms_key_name
    msg = sprintf("GCP Storage Bucket '%s' must use customer-managed encryption keys by default", [resource.change.after.name])
}

# 3. Enforce Logging for Storage Buckets
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.logging.log_bucket
    msg = sprintf("GCP Storage Bucket '%s' must have logging enabled", [resource.change.after.name])
}

# 4. Enforce Bucket Lock (Object Versioning)
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.versioning.enabled
    msg = sprintf("GCP Storage Bucket '%s' must have object versioning enabled", [resource.change.after.name])
}

# 5. Enforce Public Access Prevention
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.iam_configuration.public_access_prevention == "enforced"
    msg = sprintf("GCP Storage Bucket '%s' must enforce public access prevention", [resource.change.after.name])
}

# 6. Enforce Retention Policies
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.retention_policy
    msg = sprintf("GCP Storage Bucket '%s' must have a retention policy configured", [resource.change.after.name])
}

# 7. Enforce Lifecycle Management Rules
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    count(resource.change.after.lifecycle_rule) == 0
    msg = sprintf("GCP Storage Bucket '%s' must have lifecycle management rules configured", [resource.change.after.name])
}

# 8. Enforce Object Integrity (Hashing)
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.integrity_checks.enabled
    msg = sprintf("GCP Storage Bucket '%s' must have object integrity checks (hashing) enabled", [resource.change.after.name])
}

# 9. Enforce VPC Service Controls
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.vpc_service_controls
    msg = sprintf("GCP Storage Bucket '%s' must be protected by VPC Service Controls", [resource.change.after.name])
}

# 10. Enforce Access Logging for Bucket-Level Operations
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.logging.log_object_prefix
    msg = sprintf("GCP Storage Bucket '%s' must log all bucket-level operations", [resource.change.after.name])
}
`;
    }
}

module.exports = StorageTemplateService;
