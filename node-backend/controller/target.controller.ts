import { Request, Response } from 'express';
import { TargetModel } from '../model/target.model';

export const getTargets = async (req: Request, res: Response) => {
  try {
    const targets = await TargetModel.find({ user: req.user?.userId }).sort({ createdAt: -1 });
    return res.status(200).json({ success: true, targets });
  } catch (error) {
    console.error('[TargetController] getTargets error:', error);
    return res.status(500).json({ success: false, error: 'Failed to fetch targets' });
  }
};

export const createTarget = async (req: Request, res: Response) => {
  try {
    const { name, host, environment, techStack } = req.body;
    
    if (!name || !host || !environment) {
      return res.status(400).json({ success: false, error: 'Name, host, and environment are required' });
    }

    const newTarget = await TargetModel.create({
      user: req.user?.userId,
      name,
      host,
      environment,
      techStack: techStack || []
    });

    return res.status(201).json({ success: true, target: newTarget });
  } catch (error) {
    console.error('[TargetController] createTarget error:', error);
    return res.status(500).json({ success: false, error: 'Failed to create target' });
  }
};

export const updateTargetTechStack = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { techStack } = req.body;

    const updatedTarget = await TargetModel.findOneAndUpdate(
      { _id: id, user: req.user?.userId },
      { techStack },
      { new: true }
    );

    if (!updatedTarget) {
      return res.status(404).json({ success: false, error: 'Target not found' });
    }

    return res.status(200).json({ success: true, target: updatedTarget });
  } catch (error) {
    console.error('[TargetController] updateTargetTechStack error:', error);
    return res.status(500).json({ success: false, error: 'Failed to update tech stack' });
  }
};
