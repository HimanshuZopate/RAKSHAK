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
exports.updateTargetTechStack = exports.createTarget = exports.getTargets = void 0;
const target_model_1 = require("../model/target.model");
const getTargets = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const targets = yield target_model_1.TargetModel.find({ user: (_a = req.user) === null || _a === void 0 ? void 0 : _a.userId }).sort({ createdAt: -1 });
        return res.status(200).json({ success: true, targets });
    }
    catch (error) {
        console.error('[TargetController] getTargets error:', error);
        return res.status(500).json({ success: false, error: 'Failed to fetch targets' });
    }
});
exports.getTargets = getTargets;
const createTarget = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    try {
        const { name, host, environment, techStack } = req.body;
        if (!name || !host || !environment) {
            return res.status(400).json({ success: false, error: 'Name, host, and environment are required' });
        }
        const newTarget = yield target_model_1.TargetModel.create({
            user: (_b = req.user) === null || _b === void 0 ? void 0 : _b.userId,
            name,
            host,
            environment,
            techStack: techStack || []
        });
        return res.status(201).json({ success: true, target: newTarget });
    }
    catch (error) {
        console.error('[TargetController] createTarget error:', error);
        return res.status(500).json({ success: false, error: 'Failed to create target' });
    }
});
exports.createTarget = createTarget;
const updateTargetTechStack = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _c;
    try {
        const { id } = req.params;
        const { techStack } = req.body;
        const updatedTarget = yield target_model_1.TargetModel.findOneAndUpdate({ _id: id, user: (_c = req.user) === null || _c === void 0 ? void 0 : _c.userId }, { techStack }, { new: true });
        if (!updatedTarget) {
            return res.status(404).json({ success: false, error: 'Target not found' });
        }
        return res.status(200).json({ success: true, target: updatedTarget });
    }
    catch (error) {
        console.error('[TargetController] updateTargetTechStack error:', error);
        return res.status(500).json({ success: false, error: 'Failed to update tech stack' });
    }
});
exports.updateTargetTechStack = updateTargetTechStack;
