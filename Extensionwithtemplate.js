const vscode = require('vscode');
const storageTemplateCommand = require('./commands/StorageTemplate');

function activate(context) {
    let disposable = vscode.commands.registerCommand('extension.insertTemplate', async () => {
        const editor = vscode.window.activeTextEditor;
        await storageTemplateCommand.insertTemplate(editor);
    });

    context.subscriptions.push(disposable);
}

module.exports = {
    activate,
};
