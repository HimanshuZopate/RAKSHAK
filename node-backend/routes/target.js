"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const target_controller_1 = require("../controller/target.controller");
const verifyToken_1 = require("../middleware/verifyToken");
const router = express_1.default.Router();
router.use(verifyToken_1.verifyToken);
router.get('/', target_controller_1.getTargets);
router.post('/', target_controller_1.createTarget);
router.patch('/:id/tech-stack', target_controller_1.updateTargetTechStack);
exports.default = router;
