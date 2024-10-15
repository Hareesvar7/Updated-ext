// StorageTemplateService.js

const vscode = require('vscode');

// Define the storage templates for different cloud providers
const templates = {
    aws_s3_template: `package aws.s3.policies

# S3 Bucket Policy
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    msg = sprintf("S3 bucket '%s' must have appropriate policies", [resource.change.after.bucket])
}
`,
    azure_storage_template: `package azure.storage.policies

# Azure Storage Account Policy
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    msg = sprintf("Azure Storage Account '%s' must comply with security policies", [resource.change.after.name])
}
`,
    gcp_storage_template: `package gcp.storage.policies

# GCP Cloud Storage Policy
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    msg = sprintf("GCP Cloud Storage Bucket '%s' must have secure settings", [resource.change.after.name])
}
};

// Function to get the template based on the keyword
function getTemplate(keyword) {
    return templates[keyword] || null;
}

// Export the function to be used in other files
module.exports = {
    getTemplate,
};
