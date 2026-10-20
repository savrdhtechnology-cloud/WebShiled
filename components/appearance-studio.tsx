'use client';

import { createContext, useContext, useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { Icon } from './icons';

import {defaults,validSettings,type Appearance} from '@/lib/appearance';
const key = 'webshield:appearance:v1';
const presets: Record<string, Partial<Appearance>> = {
  'WebShield': defaults,
  'Fintech Glass': { ...defaults, accent: '#79baf4', background: 'grid', glass: 45, glow: 35, hover: 'tilt' },
  'Emerald': { ...defaults, accent: '#34e4b5', background: 'particles', glow: 65 },
  'Quiet': { ...defaults, background: 'none', motion: false, hover: 'none', click: 'none', glow: 0 },
};
const StudioContext = createContext<null | { settings: Appearance; setSettings: React.Dispatch<React.SetStateAction<Appearance>>; open: () => void; apply: () => Promise<void>; status: string; saving: boolean }>(null);


export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Appearance>(defaults);
  const [ready, setReady] = useState(false);
  const [visible, setVisible] = useState(false);
  const [status,setStatus]=useState('');
  const [saving,setSaving]=useState(false);
  const [applied,setApplied]=useState('');
  const root = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    let active=true;
    try {const raw=localStorage.getItem(key);if(raw){const value=validSettings(JSON.parse(raw));setSettings(value);}}catch{}
    fetch('/api/appearance',{cache:'no-store'}).then(r=>r.ok?r.json():null).then(body=>{if(active&&body?.data){const value=validSettings(body.data);setSettings(value);setApplied(JSON.stringify(value));localStorage.setItem(key,JSON.stringify(value));}}).catch(()=>{}).finally(()=>{if(active)setReady(true)});
    const sync=(event:StorageEvent)=>{if(event.key===key&&event.newValue){try{const value=validSettings(JSON.parse(event.newValue));setSettings(value);setApplied(JSON.stringify(value));}catch{}}};
    window.addEventListener('storage',sync);return()=>{active=false;window.removeEventListener('storage',sync)};
  }, []);
  useEffect(()=>{setStatus('')},[settings]);
  async function apply(){
    setSaving(true);setStatus('');const snapshot=validSettings(settings);
    try{const response=await fetch('/api/appearance',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(snapshot)});const body=await response.json();if(!response.ok)throw Error(body.error||'Unable to apply appearance.');
      try{localStorage.setItem(key,JSON.stringify(snapshot));}catch{}
      setApplied(JSON.stringify(snapshot));setStatus('Applied across your account.');
    }catch(error){setStatus(error instanceof Error?error.message:'Unable to apply appearance.');}finally{setSaving(false)}
  }
  useEffect(() => {
    if (!visible) return;
    const previous = document.activeElement as HTMLElement | null;
    const items = () => Array.from(panel.current?.querySelectorAll<HTMLElement>('button,input,select,a[href]') || []);
    items()[0]?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setVisible(false);
      if (event.key === 'Tab') { const list = items(), first = list[0], last = list[list.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    };
    document.addEventListener('keydown', onKey);
    const old = document.body.style.overflow; document.body.style.overflow = 'hidden';
    return () => { document.removeEventListener('keydown', onKey); document.body.style.overflow = old; previous?.focus(); };
  }, [visible]);
  const style = { '--studio-accent': settings.accent, '--studio-speed': `${30 - settings.speed * .23}s`, '--studio-intensity': settings.intensity / 100, '--studio-glow': `${settings.glow * .6}px`, '--studio-glass': settings.glass / 100, '--studio-radius': `${settings.radius}px` } as CSSProperties;
  function animateCard(event: React.MouseEvent<HTMLDivElement>) {
    if (!settings.motion || settings.click === 'none' || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const target = event.target as HTMLElement;
    if (target.closest('.studioLauncher,button,a,input,select,label')) return;
    const card = target.closest<HTMLElement>('.refPanel,.refMetric,.studioControls>section,.studioLiveSample');
    if (!card) return;
    const rect = card.getBoundingClientRect();
    if (settings.click === 'pulse') {
      card.animate([{ boxShadow: '0 0 0 transparent' }, { boxShadow: `0 0 35px ${settings.accent}66`, borderColor: settings.accent }, { boxShadow: '0 0 0 transparent' }], { duration: 650 });
    } else {
      const ripple = document.createElement('span'); ripple.className = 'studioRipple';
      const size = Math.max(rect.width, rect.height) * 2;
      Object.assign(ripple.style, { width: `${size}px`, height: `${size}px`, left: `${event.clientX - rect.left - size / 2}px`, top: `${event.clientY - rect.top - size / 2}px` });
      card.appendChild(ripple);
      const animation = ripple.animate([{ transform: 'scale(0)', opacity: .35 }, { transform: 'scale(1)', opacity: 0 }], { duration: 800, easing: 'ease-out' });
      animation.onfinish = () => ripple.remove();
    }
  }
  function tilt(event: React.PointerEvent<HTMLDivElement>) {
    if (settings.hover !== 'tilt' || !settings.motion || event.pointerType !== 'mouse' || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const card = (event.target as HTMLElement).closest<HTMLElement>('.refPanel,.refMetric,.studioControls>section,.studioLiveSample');
    if (!card) return;
    const box = card.getBoundingClientRect();
    card.style.setProperty('--tilt-x', `${((event.clientY - box.top) / box.height - .5) * -5}deg`);
    card.style.setProperty('--tilt-y', `${((event.clientX - box.left) / box.width - .5) * 5}deg`);
  }
  return <StudioContext.Provider value={{ settings, setSettings, apply, saving, status: status || (ready && applied===JSON.stringify(settings)?'Applied':'Unapplied changes'), open: () => setVisible(true) }}>
    <div ref={root} className="appearanceRoot" style={style} data-motion={settings.motion} data-background={settings.background} data-hover={settings.hover} data-density={settings.density} onClick={animateCard} onPointerMove={tilt} onPointerOut={event => { const card = (event.target as HTMLElement).closest<HTMLElement>('.refPanel,.refMetric,.studioControls>section,.studioLiveSample'); if (card && !card.contains(event.relatedTarget as Node | null)) { card.style.removeProperty('--tilt-x'); card.style.removeProperty('--tilt-y'); } }}>
      <div className="studioBackground" aria-hidden="true"><div className="studioAurora a1"/><div className="studioAurora a2"/><div className="studioPerspective"/><div className="studioParticles">{Array.from({length:24},(_,i)=><i key={i} style={{left:`${(i*37)%100}%`,top:`${(i*23)%100}%`,animationDelay:`-${i*.71}s`}}/>)}</div><div className="studioScanBeam"/></div>
      {children}
      <button className="studioLauncher" onClick={() => setVisible(true)} aria-label="Open Appearance Studio"><Icon name="settings" size={18}/><span>Appearance Studio</span></button>
      {visible && <div className="studioBackdrop" onClick={() => setVisible(false)}><aside ref={panel} className="studioDrawer" role="dialog" aria-modal="true" aria-label="Appearance Studio" onClick={e => e.stopPropagation()}><header><div><span>MAKE IT YOURS</span><h2>Appearance Studio</h2><p>Shape the atmosphere of your workspace.</p></div><button aria-label="Close Appearance Studio" onClick={() => setVisible(false)}>×</button></header><StudioControls/><footer role="status">{status || 'Apply to save these settings across your account.'}</footer></aside></div>}
    </div>
  </StudioContext.Provider>;
}

function StudioControls() {
  const studio = useContext(StudioContext)!;
  const {settings:s, setSettings} = studio;
  const update = <K extends keyof Appearance>(field: K, value: Appearance[K]) => setSettings(current => ({ ...current, [field]: value }));
  function range(field: 'speed'|'intensity'|'glow'|'glass'|'radius', label: string, max=100) { return <label className="studioRange">{label}<output>{s[field]}{field==='radius'?'px':'%'}</output><input aria-label={label} type="range" min="0" max={max} value={s[field]} onChange={e=>update(field,Number(e.target.value))}/></label>; }
  return <div className="studioControls"><section><h3>Curated presets</h3><div className="studioPresets">{Object.entries(presets).map(([name,value])=><button key={name} onClick={()=>setSettings({...defaults,...value})}><i style={{background:value.accent}}/>{name}</button>)}</div></section>
    <section><h3>Colour & atmosphere</h3><label className="studioColor">Accent colour<input aria-label="Accent colour" type="color" value={s.accent} onChange={e=>update('accent',e.target.value)}/><span>{s.accent}</span></label><div className="studioSwatches">{['#00d5ff','#79baf4','#34e4b5','#aa86ff','#ffb65c','#ff708f'].map(c=><button key={c} aria-label={`Use ${c} accent`} aria-pressed={s.accent===c} style={{background:c}} onClick={()=>update('accent',c)}/>)}</div><label>Background<select value={s.background} onChange={e=>update('background',e.target.value as Appearance['background'])}><option value="aurora">Aurora glow</option><option value="grid">Fintech perspective grid</option><option value="particles">Floating particles</option><option value="none">Clean / no background</option></select></label>{range('intensity','Background intensity')}{range('glow','Glow strength')}</section>
    <section><h3>Motion & interaction</h3><label className="studioToggle">Enable animations<input type="checkbox" role="switch" checked={s.motion} onChange={e=>update('motion',e.target.checked)}/></label>{range('speed','Motion speed')}<label>Card hover<select value={s.hover} onChange={e=>update('hover',e.target.value as Appearance['hover'])}><option value="lift">Lift & glow</option><option value="tilt">3D tilt</option><option value="none">None</option></select></label><label>Card click<select value={s.click} onChange={e=>update('click',e.target.value as Appearance['click'])}><option value="ripple">Expanding ripple</option><option value="pulse">Glow pulse</option><option value="none">None</option></select></label><p className="studioHint">Click a card surface to try the effect. Your device’s reduced-motion setting is always respected.</p></section>
    <section><h3>Surfaces & layout</h3>{range('glass','Card opacity')}{range('radius','Corner radius',28)}<label>Layout density<select value={s.density} onChange={e=>update('density',e.target.value as Appearance['density'])}><option value="comfortable">Comfortable</option><option value="compact">Compact</option></select></label></section>
    <div className="studioLiveSample"><span>LIVE PREVIEW</span><strong>Your workspace, your atmosphere.</strong><p>Colour, depth and motion update instantly.</p><button onClick={e=>{if(s.motion&&!matchMedia('(prefers-reduced-motion: reduce)').matches)e.currentTarget.animate([{transform:'scale(1)'},{transform:'scale(.93)'},{transform:'scale(1)'}],{duration:350})}}>Try interaction</button></div><div className="studioApply"><button type="button" disabled={studio.saving} onClick={()=>void studio.apply()}>{studio.saving?'Applying…':studio.status.startsWith('Applied')?'Applied':'Apply globally'}</button>{studio.status!=='Unapplied changes'&&!studio.status.startsWith('Applied')&&<p role="alert">{studio.status}</p>}</div><button className="studioReset" onClick={()=>setSettings({...defaults})}>Reset to WebShield defaults</button>
  </div>;
}
export function AppearanceStudioPage({showHeader=true}:{showHeader?:boolean}) { return <section className="studioPage">{showHeader&&<header><span>WORKSPACE PERSONALISATION</span><h2>Appearance Studio</h2><p>One place for colours, backgrounds, motion and card effects. Apply your settings across all WebShield pages and browsers signed in to your account.</p></header>}<StudioControls/></section>; }
