// StorageService.js
const vscode = require('vscode');
const { getTemplate } = require('./StorageTemplateService');

function activate(context) {
    let disposable = vscode.commands.registerCommand('extension.insertTemplate', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const document = editor.document;
            const position = editor.selection.active;

            // Get the text in the document
            const text = document.getText();

            // Check for specific keywords
            if (text.includes('aws_s3_template')) {
                const template = getTemplate('aws_s3_template');
                if (template) {
                    await editor.edit(editBuilder => {
                        editBuilder.insert(position, template);
                    });
                } else {
                    vscode.window.showWarningMessage('Template not found');
                }
            }
        }
    });

    context.subscriptions.push(disposable);
}

module.exports = {
    activate,
};
