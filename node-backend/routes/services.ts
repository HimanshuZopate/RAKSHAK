import express, { Request, Response } from 'express';
import mongoose from 'mongoose';
import { verifyToken } from '../middleware/verifyToken';
import ServiceModel, { seedServices } from '../model/service.model';
import { getActorContext, getRequestId, recordAuditEvent } from '../services/auditService';

const servicesRouter = express.Router();

// Guard all service endpoints with the verifyToken HTTP middleware
servicesRouter.use(verifyToken);

/**
 * GET /api/services
 * Returns all security services from the MongoDB database
 */
servicesRouter.get('/', async (req: Request, res: Response) => {
  try {
    let services = await ServiceModel.find().sort({ serviceId: 1 });

    // Auto-seed default 6 security tools if collection is empty
    if (services.length === 0) {
      await seedServices();
      services = await ServiceModel.find().sort({ serviceId: 1 });
    }

    // Auto-migrate if service #2 still has legacy Access Management in database
    const service2 = services.find((s) => s.serviceId === 2);
    if (service2 && service2.name !== 'Phishing & Scam Detector') {
      await seedServices();
      services = await ServiceModel.find().sort({ serviceId: 1 });
    }

    await recordAuditEvent({
      action: 'security_services_viewed',
      category: 'security scan',
      source: 'services',
      requestId: getRequestId(req),
      ...getActorContext(req),
      resourceType: 'service_catalog',
      metadata: { serviceCount: services.length },
    });

    return res.status(200).json({
      message: 'Security services retrieved successfully',
      count: services.length,
      accessedBy: req.user?.email,
      services,
    });
  } catch (error) {
    console.error('Error fetching services:', error);
    return res.status(500).json({ error: 'Server error retrieving security services.' });
  }
});

/**
 * GET /api/services/:id
 * Fetches specific service details by numeric serviceId or MongoDB ObjectId
 */
servicesRouter.get('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    let service = null;

    // Check if numeric ID (1-6)
    if (!isNaN(Number(id))) {
      service = await ServiceModel.findOne({ serviceId: Number(id) });
    }

    // Check if MongoDB ObjectId
    if (!service && mongoose.isValidObjectId(id)) {
      service = await ServiceModel.findById(id);
    }

    if (!service) {
      await recordAuditEvent({
        action: 'security_service_view_rejected',
        category: 'security scan',
        status: 'denied',
        severity: 'low',
        source: 'services',
        requestId: getRequestId(req),
        ...getActorContext(req),
        resourceType: 'service',
        resourceId: id,
        metadata: { reason: 'service_not_found' },
        errorCode: 'SERVICE_NOT_FOUND',
      });
      return res.status(404).json({
        error: `Security service with identifier "${id}" not found.`,
      });
    }

    await recordAuditEvent({
      action: 'security_service_viewed',
      category: 'security scan',
      source: 'services',
      requestId: getRequestId(req),
      ...getActorContext(req),
      resourceType: 'service',
      resourceId: String(service.serviceId),
      metadata: { serviceName: service.name },
    });

    return res.status(200).json({
      service,
      accessedBy: req.user?.email,
    });
  } catch (error) {
    console.error('Error fetching service details:', error);
    return res.status(500).json({ error: 'Server error retrieving service details.' });
  }
});

export default servicesRouter;
