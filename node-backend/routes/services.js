"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const mongoose_1 = __importDefault(require("mongoose"));
const verifyToken_1 = require("../middleware/verifyToken");
const service_model_1 = __importStar(require("../model/service.model"));
const auditService_1 = require("../services/auditService");
const servicesRouter = express_1.default.Router();
// Guard all service endpoints with the verifyToken HTTP middleware
servicesRouter.use(verifyToken_1.verifyToken);
/**
 * GET /api/services
 * Returns all security services from the MongoDB database
 */
servicesRouter.get('/', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        let services = yield service_model_1.default.find().sort({ serviceId: 1 });
        // Auto-seed default 6 security tools if collection is empty
        if (services.length === 0) {
            yield (0, service_model_1.seedServices)();
            services = yield service_model_1.default.find().sort({ serviceId: 1 });
        }
        // Auto-migrate if service #2 still has legacy Access Management in database
        const service2 = services.find((s) => s.serviceId === 2);
        if (service2 && service2.name !== 'Phishing & Scam Detector') {
            yield (0, service_model_1.seedServices)();
            services = yield service_model_1.default.find().sort({ serviceId: 1 });
        }
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'security_services_viewed', category: 'security scan', source: 'services', requestId: (0, auditService_1.getRequestId)(req) }, (0, auditService_1.getActorContext)(req)), { resourceType: 'service_catalog', metadata: { serviceCount: services.length } }));
        return res.status(200).json({
            message: 'Security services retrieved successfully',
            count: services.length,
            accessedBy: (_a = req.user) === null || _a === void 0 ? void 0 : _a.email,
            services,
        });
    }
    catch (error) {
        console.error('Error fetching services:', error);
        return res.status(500).json({ error: 'Server error retrieving security services.' });
    }
}));
/**
 * GET /api/services/:id
 * Fetches specific service details by numeric serviceId or MongoDB ObjectId
 */
servicesRouter.get('/:id', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    try {
        const { id } = req.params;
        let service = null;
        // Check if numeric ID (1-6)
        if (!isNaN(Number(id))) {
            service = yield service_model_1.default.findOne({ serviceId: Number(id) });
        }
        // Check if MongoDB ObjectId
        if (!service && mongoose_1.default.isValidObjectId(id)) {
            service = yield service_model_1.default.findById(id);
        }
        if (!service) {
            yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'security_service_view_rejected', category: 'security scan', status: 'denied', severity: 'low', source: 'services', requestId: (0, auditService_1.getRequestId)(req) }, (0, auditService_1.getActorContext)(req)), { resourceType: 'service', resourceId: id, metadata: { reason: 'service_not_found' }, errorCode: 'SERVICE_NOT_FOUND' }));
            return res.status(404).json({
                error: `Security service with identifier "${id}" not found.`,
            });
        }
        yield (0, auditService_1.recordAuditEvent)(Object.assign(Object.assign({ action: 'security_service_viewed', category: 'security scan', source: 'services', requestId: (0, auditService_1.getRequestId)(req) }, (0, auditService_1.getActorContext)(req)), { resourceType: 'service', resourceId: String(service.serviceId), metadata: { serviceName: service.name } }));
        return res.status(200).json({
            service,
            accessedBy: (_b = req.user) === null || _b === void 0 ? void 0 : _b.email,
        });
    }
    catch (error) {
        console.error('Error fetching service details:', error);
        return res.status(500).json({ error: 'Server error retrieving service details.' });
    }
}));
exports.default = servicesRouter;
