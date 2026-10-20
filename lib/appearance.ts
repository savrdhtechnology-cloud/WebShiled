export type Appearance = {
  accent: string; background: 'aurora' | 'grid' | 'particles' | 'none';
  motion: boolean; speed: number; intensity: number; glow: number;
  hover: 'lift' | 'tilt' | 'none'; click: 'ripple' | 'pulse' | 'none';
  glass: number; radius: number; density: 'comfortable' | 'compact';
};
export const defaults: Appearance = { accent: '#00d5ff', background: 'aurora', motion: true, speed: 50, intensity: 55, glow: 50, hover: 'lift', click: 'ripple', glass: 75, radius: 12, density: 'comfortable' };

export function validSettings(value: unknown): Appearance {
  const result = { ...defaults };
  if (!value || typeof value !== 'object') return result;
  const v = value as Record<string, unknown>;
  if (typeof v.accent === 'string' && /^#[0-9a-f]{6}$/i.test(v.accent)) result.accent = v.accent;
  if (['aurora','grid','particles','none'].includes(String(v.background))) result.background = v.background as Appearance['background'];
  if (typeof v.motion === 'boolean') result.motion = v.motion;
  if (['lift','tilt','none'].includes(String(v.hover))) result.hover = v.hover as Appearance['hover'];
  if (['ripple','pulse','none'].includes(String(v.click))) result.click = v.click as Appearance['click'];
  if (['comfortable','compact'].includes(String(v.density))) result.density = v.density as Appearance['density'];
  for (const name of ['speed','intensity','glow','glass','radius'] as const) {
    if (typeof v[name] === 'number' && Number.isFinite(v[name])) result[name] = Math.max(0, Math.min(name === 'radius' ? 28 : 100, v[name] as number));
  }
  return result;
}

