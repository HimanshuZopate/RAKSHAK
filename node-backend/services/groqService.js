"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.askGroq = exports.getAIStatus = void 0;
const aiProviderService_1 = require("./aiProviderService");
Object.defineProperty(exports, "getAIStatus", { enumerable: true, get: function () { return aiProviderService_1.getAIStatus; } });
const askGroq = (messageOrMessages) => __awaiter(void 0, void 0, void 0, function* () {
    let messages = [];
    if (Array.isArray(messageOrMessages)) {
        messages = messageOrMessages;
    }
    else if (messageOrMessages && typeof messageOrMessages === 'object') {
        messages = [messageOrMessages];
    }
    else if (typeof messageOrMessages === 'string') {
        messages = [{ role: 'user', content: messageOrMessages }];
    }
    const result = yield (0, aiProviderService_1.askExternalLLM)(messages);
    return result.answer;
});
exports.askGroq = askGroq;
