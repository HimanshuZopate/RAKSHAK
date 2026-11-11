"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const aiController_1 = require("../controller/aiController");
const verifyToken_1 = require("../middleware/verifyToken");
const router = express_1.default.Router();
// Public / Optional-auth endpoints for smooth UX
router.get('/status', verifyToken_1.optionalVerifyToken, aiController_1.aiStatus);
router.post('/chat', verifyToken_1.optionalVerifyToken, aiController_1.chat);
router.post('/explain', verifyToken_1.optionalVerifyToken, aiController_1.explain);
// Protected endpoints
router.get('/recommendations', verifyToken_1.verifyToken, aiController_1.recommendations);
router.post('/configure', verifyToken_1.verifyToken, aiController_1.configureAI);
exports.default = router;
