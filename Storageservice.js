const vscode = require('vscode');
const { getTemplate } = require('./StorageTemplateService');

function activate(context) {
    let disposable = vscode.commands.registerCommand('extension.insertTemplate', async () => {
        const editor = vscode.window.activeTextEditor;

        if (editor) {
            const document = editor.document;
            const position = editor.selection.active;
            const text = document.getText();
            const keywords = ['aws_s3_template', 'azure_storage_template', 'gcp_storage_template'];
            let templateFound = false;

            for (const keyword of keywords) {
                if (text.includes(keyword)) {
                    const template = getTemplate(keyword);
                    if (template) {
                        await editor.edit(editBuilder => {
                            editBuilder.insert(position, template);
                        });
                        templateFound = true;
                        break;
                    }
                }
            }

            if (!templateFound) {
                vscode.window.showWarningMessage('Template not found');
            }
        }
    });

    context.subscriptions.push(disposable);
}

module.exports = {
    activate,
};
