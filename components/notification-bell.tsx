'use client';
import {useEffect,useState} from 'react';
import Link from 'next/link';
import {Icon} from './icons';
export function NotificationBell(){const [count,setCount]=useState(0);useEffect(()=>{let active=true;async function load(){try{const response=await fetch('/api/alerts',{cache:'no-store'});const body=await response.json();if(active&&response.ok&&Array.isArray(body.data))setCount(body.data.filter((a:{acknowledged_at?:string})=>!a.acknowledged_at).length)}catch{}}void load();const changed=()=>void load();window.addEventListener('webshield:monitoring-updated',changed);const timer=setInterval(()=>void load(),30000);return()=>{active=false;clearInterval(timer);window.removeEventListener('webshield:monitoring-updated',changed)}},[]);return <Link className="refBell" href="/app/alerts" aria-label={count?`Notifications: ${count} open alerts`:'Notifications'}><Icon name="bell"/>{count>0&&<em>{count}</em>}</Link>}
