// ─── Simulation Lab Progress — localStorage-backed ───────────────────────────
// Only stores simulation IDs, scores, and module completion flags.
// Never stores uploaded files, passwords, or personal content.

const STORAGE_KEY = 'sim_lab_progress_v1';

const DEFAULT_PROGRESS = {
  completedSims: [],    // Array of simulation IDs
  quizScores: {},       // { simId: score }
  topicsExplored: [],
  totalActivities: 0,
  level: 'Beginner',
  lastActivity: null,
};

export const getProgress = () => {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_PROGRESS };
    return { ...DEFAULT_PROGRESS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_PROGRESS };
  }
};

export const saveProgress = (progress) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      ...progress,
      lastActivity: new Date().toISOString(),
    }));
  } catch {
    // Storage unavailable — progress is session-only
  }
};

export const markSimulationComplete = (simId, score) => {
  const progress = getProgress();
  const completedSims = progress.completedSims.includes(simId)
    ? progress.completedSims
    : [...progress.completedSims, simId];
  const quizScores = { ...progress.quizScores, [simId]: score };
  const totalActivities = progress.totalActivities + 1;

  let level = 'Beginner';
  if (completedSims.length >= 5) level = 'Advanced';
  else if (completedSims.length >= 2) level = 'Intermediate';

  const newProgress = {
    ...progress,
    completedSims,
    quizScores,
    totalActivities,
    level,
  };
  saveProgress(newProgress);
  return newProgress;
};

export const addTopicExplored = (topic) => {
  const progress = getProgress();
  if (progress.topicsExplored.includes(topic)) return progress;
  const newProgress = {
    ...progress,
    topicsExplored: [...progress.topicsExplored, topic],
  };
  saveProgress(newProgress);
  return newProgress;
};

export const resetProgress = () => {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch { /* noop */ }
  return { ...DEFAULT_PROGRESS };
};
