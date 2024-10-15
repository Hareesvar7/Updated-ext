const vscode = require('vscode');

class StorageService {
    constructor() {
        this.keywords = ['aws_s3_template', 'azure_storage_template', 'gcp_storage_template'];
    }

    isValidKeyword(keyword) {
        return this.keywords.includes(keyword);
    }
}

// Exporting an instance of StorageService
const storageService = new StorageService();
module.exports = storageService;
