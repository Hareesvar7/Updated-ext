const vscode = require('vscode');

function showStorageTemplateGenerator(context) {
    // Create and show a new webview
    const panel = vscode.window.createWebviewPanel(
        'storageTemplateGenerator',
        'Cloud Storage Template Generator',
        vscode.ViewColumn.One,
        {
            enableScripts: true,
            retainContextWhenHidden: true
        }
    );

    // Set the webview's HTML content
    panel.webview.html = getWebviewContent();

    // Handle messages from the webview
    panel.webview.onDidReceiveMessage(
        message => {
            switch (message.command) {
                case 'generateTemplate':
                    const selectedService = message.service;
                    const template = generateTemplateForService(selectedService);
                    panel.webview.postMessage({ command: 'showTemplate', template: template });
                    return;
            }
        },
        undefined,
        context.subscriptions
    );
}

function getWebviewContent() {
    return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Storage Template Generator</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    padding: 20px;
                    background-color: #f4f7fa;
                    color: #333;
                }
                h1 {
                    font-size: 24px;
                    color: #4A90E2;
                    text-align: center;
                    margin-bottom: 20px;
                }
                label {
                    font-size: 16px;
                    color: #333;
                    margin-bottom: 10px;
                    display: block;
                }
                select, button {
                    font-size: 16px;
                    padding: 10px;
                    border-radius: 8px;
                    border: 1px solid #d1d5db;
                    width: 100%;
                    margin-bottom: 20px;
                }
                button {
                    background-color: #4A90E2;
                    color: #fff;
                    cursor: pointer;
                }
                button:hover {
                    background-color: #357ABD;
                }
                .response {
                    margin-top: 20px;
                    padding: 20px;
                    border-radius: 8px;
                    background-color: #ffffff;
                    border: 1px solid #d1d5db;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                    white-space: pre-wrap;
                    font-size: 16px;
                    color: #333;
                }
            </style>
        </head>
        <body>
            <h1>Storage Template Generator</h1>
            <label for="cloudProvider">Select Cloud Provider:</label>
            <select id="cloudProvider">
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
                <option value="gcp">GCP</option>
            </select>
            <label for="storageService">Select Storage Service:</label>
            <select id="storageService">
                <option value="s3">AWS S3</option>
                <option value="azureStorage">Azure Storage</option>
                <option value="gcpStorage">GCP Cloud Storage</option>
            </select>
            <button id="generateTemplate">Generate Template</button>
            <div class="response" id="templateResponse"></div>

            <script>
                const vscode = acquireVsCodeApi();

                document.getElementById('generateTemplate').addEventListener('click', () => {
                    const cloudProvider = document.getElementById('cloudProvider').value;
                    const storageService = document.getElementById('storageService').value;
                    
                    vscode.postMessage({
                        command: 'generateTemplate',
                        service: storageService
                    });
                });

                // Listen for messages from the extension
                window.addEventListener('message', event => {
                    const message = event.data;
                    const responseDiv = document.getElementById('templateResponse');

                    if (message.command === 'showTemplate') {
                        responseDiv.innerHTML = '<strong>Generated Template:</strong><br>' + message.template;
                    }
                });
            </script>
        </body>
        </html>`;
}

// Dummy template generator function (you will update these templates)
function generateTemplateForService(service) {
    switch (service) {
        case 's3':
            return `# AWS S3 Template
package aws.s3.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    msg = "S3 bucket policy must be compliant"
}`;

        case 'azureStorage':
            return `# Azure Storage Template
package azure.storage.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azure_storage_account"
    msg = "Azure Storage policy must be compliant"
}`;

        case 'gcpStorage':
            return `# GCP Cloud Storage Template
package gcp.storage.policies

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "gcp_storage_bucket"
    msg = "GCP Cloud Storage policy must be compliant"
}`;

        default:
            return "Invalid service selected";
    }
}

module.exports = {
    showStorageTemplateGenerator
};
