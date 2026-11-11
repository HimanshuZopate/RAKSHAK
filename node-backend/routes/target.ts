import express from 'express';
import { getTargets, createTarget, updateTargetTechStack } from '../controller/target.controller';
import { verifyToken } from '../middleware/verifyToken';

const router = express.Router();

router.use(verifyToken);

router.get('/', getTargets);
router.post('/', createTarget);
router.patch('/:id/tech-stack', updateTargetTechStack);

export default router;
