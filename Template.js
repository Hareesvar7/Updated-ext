const StorageService = require('../services/StorageService');

module.exports = {
    generateStorageTemplate(context) {
        StorageService.showStorageTemplateGenerator(context);
    }
};
