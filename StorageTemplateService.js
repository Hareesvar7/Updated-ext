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

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.server_side_encryption.enabled
    msg = sprintf("S3 bucket '%s' must have server-side encryption enabled", [resource.change.after.bucket])
}
`;
    }

    getAzureStorageTemplate() {
        return `package azure.storage.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    not resource.change.after.enable_https_traffic_only
    msg = sprintf("Azure Storage Account '%s' must enforce HTTPS traffic only", [resource.change.after.name])
}
`;
    }

    getGcpStorageTemplate() {
        return `package gcp.storage.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.default_event_based_hold
    msg = sprintf("GCP Storage Bucket '%s' must have event-based hold enabled", [resource.change.after.name])
}
`;
    }

    getTemplate(keyword) {
        return this.templates[keyword] || null;
    }
}

// Exporting an instance of StorageTemplateService
const storageTemplateService = new StorageTemplateService();
module.exports = storageTemplateService.getTemplate.bind(storageTemplateService);
