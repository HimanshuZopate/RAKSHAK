import express from 'express';
import { aiStatus, chat, explain, recommendations, configureAI } from '../controller/aiController';
import { verifyToken, optionalVerifyToken } from '../middleware/verifyToken';

const router = express.Router();

// Public / Optional-auth endpoints for smooth UX
router.get('/status', optionalVerifyToken, aiStatus);
router.post('/chat', optionalVerifyToken, chat);
router.post('/explain', optionalVerifyToken, explain);

// Protected endpoints
router.get('/recommendations', verifyToken, recommendations);
router.post('/configure', verifyToken, configureAI);

export default router;
