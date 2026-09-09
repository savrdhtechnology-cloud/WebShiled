export function Sparkline({ values, label }: { values: number[]; label: string }) {
  const max = Math.max(...values);
  const min = Math.min(...values);
  const range = Math.max(1, max - min);
  const points = values.map((v,i)=>`${(i/(values.length-1))*100},${100-((v-min)/range)*82-8}`).join(" ");
  return <svg className="sparkline" role="img" aria-label={label} viewBox="0 0 100 100" preserveAspectRatio="none"><polyline points={points}/></svg>;
}

export function BarChart({ data }: { data: readonly (readonly [string,number])[] }) {
  const max = Math.max(...data.map(x=>x[1]));
  return <div className="barChart">{data.map(([label,value])=><div key={label} className="barRow"><span>{label}</span><div><i style={{width:`${(value/max)*100}%`}}/></div><b>{value}%</b></div>)}</div>;
}

export function Donut({ value, label }: { value: number; label: string }) {
  return <div className="donut" style={{"--value":`${value*3.6}deg`} as React.CSSProperties}><div><strong>{value}%</strong><span>{label}</span></div></div>;
}
