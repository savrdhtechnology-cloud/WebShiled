'use client';

import { createContext, useContext, useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { Icon } from './icons';
import { apiPath } from '@/lib/base-path';

export type Appearance = {
  accent: string;
  background: 'aurora' | 'grid' | 'particles' | 'none';
  motion: boolean;
  speed: number;
  intensity: number;
  glow: number;
  hover: 'lift' | 'tilt' | 'none';
  click: 'ripple' | 'pulse' | 'none';
  glass: number;
  radius: number;
  density: 'comfortable' | 'compact';
};

export type AppearanceScope = 'landing' | 'admin' | 'workspace' | 'demo';

const defaults: Appearance = {
  accent: '#00d5ff', background: 'aurora', motion: true, speed: 50, intensity: 55,
  glow: 50, hover: 'lift', click: 'ripple', glass: 75, radius: 12, density: 'comfortable'
};

const presets: Record<string, Partial<Appearance>> = {
  WebShield: defaults,
  'Fintech Glass': { ...defaults, accent: '#79baf4', background: 'grid', glass: 45, glow: 35, hover: 'tilt' },
  Emerald: { ...defaults, accent: '#34e4b5', background: 'particles', glow: 65 },
  Quiet: { ...defaults, background: 'none', motion: false, hover: 'none', click: 'none', glow: 0 }
};

type StudioState = {
  settings: Appearance;
  setSettings: React.Dispatch<React.SetStateAction<Appearance>>;
  open: () => void;
  scope: AppearanceScope;
  setScope: (scope: AppearanceScope) => void;
  allowedScopes: AppearanceScope[];
  global: boolean;
  save: () => Promise<void>;
  status: string;
};

const StudioContext = createContext<StudioState | null>(null);

function validSettings(value: unknown): Appearance {
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
    if (typeof v[name] === 'number' && Number.isFinite(v[name])) {
      result[name] = Math.max(0, Math.min(name === 'radius' ? 28 : 100, v[name] as number));
    }
  }
  return result;
}

export function AppearanceProvider({
  children,
  initialScope = 'workspace',
  allowedScopes,
  showLauncher = true
}: {
  children: ReactNode;
  initialScope?: AppearanceScope;
  allowedScopes?: AppearanceScope[];
  showLauncher?: boolean;
}) {
  const scopes = allowedScopes?.length ? allowedScopes : [initialScope];
  const [scope, setScopeState] = useState<AppearanceScope>(initialScope);
  const [settings, setSettings] = useState<Appearance>(defaults);
  const [ready, setReady] = useState(false);
  const [visible, setVisible] = useState(false);
  const [status, setStatus] = useState('');
  const panel = useRef<HTMLElement>(null);
  const global = scope === 'landing' || scope === 'admin';

  function setScope(next: AppearanceScope) {
    if (!scopes.includes(next)) return;
    setScopeState(next);
  }

  useEffect(() => {
    let active = true;
    setReady(false);
    setStatus('');
    async function load() {
      try {
        if (scope === 'landing' || scope === 'admin') {
          const response = await fetch(apiPath('/api/appearance') + '?scope=' + encodeURIComponent(scope), { cache: 'no-store' });
          const body = await response.json();
          if (active && response.ok && body.ok) setSettings(validSettings(body.data));
          else if (active) setSettings({ ...defaults });
        } else {
          const raw = localStorage.getItem('webshield:appearance:v2:' + scope);
          if (active) setSettings(raw ? validSettings(JSON.parse(raw)) : { ...defaults });
        }
      } catch {
        if (active) setSettings({ ...defaults });
      } finally {
        if (active) setReady(true);
      }
    }
    load();
    return () => { active = false; };
  }, [scope]);

  useEffect(() => {
    if (!ready || global) return;
    try {
      localStorage.setItem('webshield:appearance:v2:' + scope, JSON.stringify(settings));
      setStatus('Saved automatically on this browser.');
    } catch {
      setStatus('Storage unavailable. Changes apply for this visit.');
    }
  }, [settings, ready, global, scope]);

  async function save() {
    if (!global) return;
    setStatus('Saving global theme…');
    try {
      const response = await fetch(apiPath('/api/appearance'), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ scope, settings })
      });
      const body = await response.json();
      if (!response.ok || !body.ok) throw new Error(body?.error?.message || 'Could not save theme.');
      setSettings(validSettings(body.data));
      setStatus(scope === 'landing' ? 'Landing theme published.' : 'Admin theme published.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Could not save theme.');
    }
  }

  useEffect(() => {
    if (!visible) return;
    const previous = document.activeElement as HTMLElement | null;
    const items = () => Array.from(panel.current?.querySelectorAll<HTMLElement>('button,input,select,a[href]') || []);
    items()[0]?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setVisible(false);
      if (event.key === 'Tab') {
        const list = items(), first = list[0], last = list[list.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    };
    document.addEventListener('keydown', onKey);
    const old = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = old;
      previous?.focus();
    };
  }, [visible]);

  const style = {
    '--studio-accent': settings.accent,
    '--studio-speed': `${30 - settings.speed * .23}s`,
    '--studio-intensity': settings.intensity / 100,
    '--studio-glow': `${settings.glow * .6}px`,
    '--studio-glass': settings.glass / 100,
    '--studio-radius': `${settings.radius}px`
  } as CSSProperties;

  function animateCard(event: React.MouseEvent<HTMLDivElement>) {
    if (!settings.motion || settings.click === 'none' || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const target = event.target as HTMLElement;
    if (target.closest('.studioDrawer,.studioLauncher,.studioPage,button,a,input,select,label')) return;
    const card = target.closest<HTMLElement>('.refPanel,.refMetric,.featureCard,.priceCard,.heroDashboard');
    if (!card) return;
    const rect = card.getBoundingClientRect();
    if (settings.click === 'pulse') {
      card.animate(
        [{ boxShadow: '0 0 0 transparent' }, { boxShadow: `0 0 35px ${settings.accent}66`, borderColor: settings.accent }, { boxShadow: '0 0 0 transparent' }],
        { duration: 650 }
      );
    } else {
      const ripple = document.createElement('span');
      ripple.className = 'studioRipple';
      const size = Math.max(rect.width, rect.height) * 2;
      Object.assign(ripple.style, {
        width: `${size}px`, height: `${size}px`,
        left: `${event.clientX - rect.left - size / 2}px`,
        top: `${event.clientY - rect.top - size / 2}px`
      });
      card.appendChild(ripple);
      const animation = ripple.animate([{ transform: 'scale(0)', opacity: .35 }, { transform: 'scale(1)', opacity: 0 }], { duration: 800, easing: 'ease-out' });
      animation.onfinish = () => ripple.remove();
    }
  }

  function tilt(event: React.PointerEvent<HTMLDivElement>) {
    if (settings.hover !== 'tilt' || !settings.motion || event.pointerType !== 'mouse' || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const card = (event.target as HTMLElement).closest<HTMLElement>('.refPanel,.refMetric,.featureCard,.priceCard,.heroDashboard');
    if (!card) return;
    const box = card.getBoundingClientRect();
    card.style.setProperty('--tilt-x', `${((event.clientY - box.top) / box.height - .5) * -5}deg`);
    card.style.setProperty('--tilt-y', `${((event.clientX - box.left) / box.width - .5) * 5}deg`);
  }

  return <StudioContext.Provider value={{ settings, setSettings, open: () => setVisible(true), scope, setScope, allowedScopes: scopes, global, save, status }}>
    <div className="appearanceRoot" style={style} data-motion={settings.motion} data-background={settings.background} data-hover={settings.hover} data-density={settings.density} data-scope={scope} onClick={animateCard} onPointerMove={tilt} onPointerOut={event => {
      const card = (event.target as HTMLElement).closest<HTMLElement>('.refPanel,.refMetric,.featureCard,.priceCard,.heroDashboard');
      if (card && !card.contains(event.relatedTarget as Node | null)) {
        card.style.removeProperty('--tilt-x');
        card.style.removeProperty('--tilt-y');
      }
    }}>
      <div className="studioBackground" aria-hidden="true">
        <div className="studioAurora a1"/><div className="studioAurora a2"/><div className="studioPerspective"/>
        <div className="studioParticles">{Array.from({length:24},(_,i)=><i key={i} style={{left:`${(i*37)%100}%`,top:`${(i*23)%100}%`,animationDelay:`-${i*.71}s`}}/>)}</div>
        <div className="studioScanBeam"/>
      </div>
      {children}
      {showLauncher && <button className="studioLauncher" onClick={() => setVisible(true)} aria-label="Open Appearance Studio"><Icon name="settings" size={18}/><span>Appearance Studio</span></button>}
      {visible && <div className="studioBackdrop" onClick={() => setVisible(false)}>
        <aside ref={panel} className="studioDrawer" role="dialog" aria-modal="true" aria-label="Appearance Studio" onClick={e => e.stopPropagation()}>
          <header><div><span>MAKE IT YOURS</span><h2>Appearance Studio</h2><p>Shape the atmosphere of your WebShield experience.</p></div><button aria-label="Close Appearance Studio" onClick={() => setVisible(false)}>×</button></header>
          <StudioControls/>
          <footer role="status">{status || (global ? 'Choose a theme and publish it.' : 'Changes save automatically on this browser.')}</footer>
        </aside>
      </div>}
    </div>
  </StudioContext.Provider>;
}

function ScopeChooser() {
  const studio = useContext(StudioContext)!;
  if (studio.allowedScopes.length < 2) return null;
  return <section className="studioScope"><h3>Theme target</h3><p className="studioHint">Landing and Super Admin themes are independent.</p><div className="studioPresets">
    {studio.allowedScopes.map(scope => <button key={scope} className={studio.scope===scope?'active':''} onClick={() => studio.setScope(scope)}>
      <Icon name={scope==='landing'?'globe':'settings'} size={16}/>{scope==='landing'?'Landing Theme':'Admin Theme'}
    </button>)}
  </div></section>;
}

function StudioControls() {
  const studio = useContext(StudioContext)!;
  const { settings:s, setSettings } = studio;
  const update = <K extends keyof Appearance>(field: K, value: Appearance[K]) => setSettings(current => ({ ...current, [field]: value }));
  function range(field: 'speed'|'intensity'|'glow'|'glass'|'radius', label: string, max=100) {
    return <label className="studioRange">{label}<output>{s[field]}{field==='radius'?'px':'%'}</output><input aria-label={label} type="range" min="0" max={max} value={s[field]} onChange={e=>update(field,Number(e.target.value))}/></label>;
  }
  return <div className="studioControls">
    <ScopeChooser/>
    <section><h3>Curated presets</h3><div className="studioPresets">{Object.entries(presets).map(([name,value])=><button key={name} onClick={()=>setSettings({...defaults,...value})}><i style={{background:value.accent}}/>{name}</button>)}</div></section>
    <section><h3>Colour & atmosphere</h3><label className="studioColor">Accent colour<input aria-label="Accent colour" type="color" value={s.accent} onChange={e=>update('accent',e.target.value)}/><span>{s.accent}</span></label><div className="studioSwatches">{['#00d5ff','#79baf4','#34e4b5','#aa86ff','#ffb65c','#ff708f'].map(c=><button key={c} aria-label={`Use ${c} accent`} aria-pressed={s.accent===c} style={{background:c}} onClick={()=>update('accent',c)}/>)}</div><label>Background<select value={s.background} onChange={e=>update('background',e.target.value as Appearance['background'])}><option value="aurora">Aurora glow</option><option value="grid">Fintech perspective grid</option><option value="particles">Floating particles</option><option value="none">Clean / no background</option></select></label>{range('intensity','Background intensity')}{range('glow','Glow strength')}</section>
    <section><h3>Motion & interaction</h3><label className="studioToggle">Enable animations<input type="checkbox" role="switch" checked={s.motion} onChange={e=>update('motion',e.target.checked)}/></label>{range('speed','Motion speed')}<label>Card hover<select value={s.hover} onChange={e=>update('hover',e.target.value as Appearance['hover'])}><option value="lift">Lift & glow</option><option value="tilt">3D tilt</option><option value="none">None</option></select></label><label>Card click<select value={s.click} onChange={e=>update('click',e.target.value as Appearance['click'])}><option value="ripple">Expanding ripple</option><option value="pulse">Glow pulse</option><option value="none">None</option></select></label><p className="studioHint">Reduced-motion device settings are always respected.</p></section>
    <section><h3>Surfaces & layout</h3>{range('glass','Card opacity')}{range('radius','Corner radius',28)}<label>Layout density<select value={s.density} onChange={e=>update('density',e.target.value as Appearance['density'])}><option value="comfortable">Comfortable</option><option value="compact">Compact</option></select></label></section>
    <div className="studioLiveSample"><span>LIVE PREVIEW · {studio.scope.toUpperCase()}</span><strong>Your WebShield, your atmosphere.</strong><p>Colour, depth and motion update instantly before publishing.</p><button onClick={e=>{if(s.motion&&!matchMedia('(prefers-reduced-motion: reduce)').matches)e.currentTarget.animate([{transform:'scale(1)'},{transform:'scale(.93)'},{transform:'scale(1)'}],{duration:350})}}>Try interaction</button></div>
    {studio.global && <button className="studioPublish" onClick={studio.save}>Save & Publish {studio.scope==='landing'?'Landing':'Admin'} Theme</button>}
    {studio.status && <p className="studioStatus" role="status">{studio.status}</p>}
    <button className="studioReset" onClick={()=>setSettings({...defaults})}>Reset to WebShield defaults</button>
  </div>;
}

export function AppearanceStudioPage() {
  const studio = useContext(StudioContext)!;
  return <section className="studioPage"><header><span>APPEARANCE CONTROL</span><h1>Appearance Studio</h1><p>{studio.allowedScopes.length>1?'Control Landing and Super Admin styles independently, then publish the selected theme.':'Customise colours, backgrounds, motion and card effects for this workspace.'}</p></header><StudioControls/></section>;
}
