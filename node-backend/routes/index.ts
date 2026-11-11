import express from 'express';
import authRouter from './auth';
import servicesRouter from './services';
import targetRouter from './target';
import scannersRouter from './scanners';
import auditsRouter from './audits';
import wafRouter from './waf';
import phishingRouter from './phishing';
import websiteSecurityRouter from './websiteSecurity';
import aiRouter from './ai';

const router = express.Router();

router.use('/auth', authRouter);
router.use('/services', servicesRouter);
router.use('/targets', targetRouter);
router.use('/scanners', scannersRouter);
router.use('/audits', auditsRouter);
router.use('/waf', wafRouter);
router.use('/phishing', phishingRouter);
router.use('/security', websiteSecurityRouter);
router.use('/website-security', websiteSecurityRouter);
router.use('/ai', aiRouter);

export default router;
