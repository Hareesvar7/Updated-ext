const vscode = require('vscode');

function showStorageTemplateGenerator(context) {
    // Create a new webview panel
    const panel = vscode.window.createWebviewPanel(
        'storageTemplateGenerator', // Identifies the type of the webview
        'Storage Template Generator', // Title of the panel
        vscode.ViewColumn.One, // Editor column to show the new webview panel in
        {
            enableScripts: true,
        }
    );

    panel.webview.html = getWebviewContent();

    // Handle messages from the webview
    panel.webview.onDidReceiveMessage(
        message => {
            switch (message.command) {
                case 'insertTemplate':
                    const editor = vscode.window.activeTextEditor;
                    if (editor) {
                        editor.edit(editBuilder => {
                            editBuilder.insert(editor.selection.active, message.template);
                        });
                    }
                    break;
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
                    margin-top: 10px;
                    width: 100%;
                }
                button {
                    background-color: #4A90E2;
                    color: #fff;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    transition: background-color 0.3s ease;
                }
                button:hover {
                    background-color: #357ABD;
                }
                .response {
                    margin-top: 20px;
                    padding: 10px;
                    border: 1px solid #d1d5db;
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <h1>Storage Template Generator</h1>
            <label for="cloudProvider">Choose Cloud Provider:</label>
            <select id="cloudProvider">
                <option value="">Select...</option>
                <option value="aws">AWS</option>
                <option value="gcp">GCP</option>
                <option value="azure">Azure</option>
            </select>
            <label for="service">Choose Storage Service:</label>
            <select id="service" disabled>
                <option value="">Select a cloud provider first</option>
            </select>
            <button id="generateTemplate" disabled>Generate Template</button>
            <div class="response" id="response"></div>
            <script>
                const vscode = acquireVsCodeApi();

                const services = {
                    aws: {
                        "S3": "AWS S3",
                    },
                    gcp: {
                        "Cloud Storage": "GCP Cloud Storage",
                    },
                    azure: {
                        "Blob Storage": "Azure Blob Storage",
                    },
                };

                document.getElementById('cloudProvider').addEventListener('change', function() {
                    const provider = this.value;
                    const serviceSelect = document.getElementById('service');
                    serviceSelect.innerHTML = '<option value="">Select a service</option>';
                    if (provider) {
                        for (const service in services[provider]) {
                            serviceSelect.innerHTML += `<option value="${service}">${services[provider][service]}</option>`;
                        }
                        serviceSelect.disabled = false;
                    } else {
                        serviceSelect.disabled = true;
                    }
                });

                document.getElementById('service').addEventListener('change', function() {
                    const generateButton = document.getElementById('generateTemplate');
                    generateButton.disabled = !this.value;
                });

                document.getElementById('generateTemplate').addEventListener('click', () => {
                    const provider = document.getElementById('cloudProvider').value;
                    const service = document.getElementById('service').value;
                    const template = generateTemplate(provider, service);
                    vscode.postMessage({ command: 'insertTemplate', template });
                });

                function generateTemplate(provider, service) {
                    const templates = {
                        aws: {
                            "S3": `package aws.s3.policies\n\n# Dummy template for AWS S3 Storage Service\n\n# Example S3 policy...`,
                        },
                        gcp: {
                            "Cloud Storage": `package gcp.storage.policies\n\n# Dummy template for GCP Cloud Storage Service\n\n# Example GCP policy...`,
                        },
                        azure: {
                            "Blob Storage": `package azure.blob.policies\n\n# Dummy template for Azure Blob Storage Service\n\n# Example Azure policy...`,
                        },
                    };
                    return templates[provider][service] || '';
                }
            </script>
        </body>
        </html>`;
}

module.exports = {
    showStorageTemplateGenerator
};
