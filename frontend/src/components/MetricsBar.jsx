import React from 'react';
import { Activity, ShieldCheck, AlertTriangle, Skull } from 'lucide-react';

const MetricCard = ({ title, value, icon: Icon, colorClass }) => (
  <div className="bg-white/80 backdrop-blur-md border border-white/60 shadow-xl rounded-lg p-4 flex items-center space-x-4">
    <div className={`p-3 rounded-full bg-slate-100 ${colorClass}`}>
      <Icon className="w-6 h-6" />
    </div>
    <div>
      <p className="text-slate-500 text-sm font-medium">{title}</p>
      <p className="text-2xl font-bold text-slate-950">{value}</p>
    </div>
  </div>
);

const MetricsBar = ({ metrics }) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      <MetricCard title="Packets Inspected" value={metrics.totalInspected} icon={Activity} colorClass="text-blue-600" />
      <MetricCard title="Normal Traffic" value={metrics.normalCount} icon={ShieldCheck} colorClass="text-emerald-600" />
      <MetricCard title="Known Threats" value={metrics.anomalies} icon={AlertTriangle} colorClass="text-amber-500" />
      <MetricCard title="Zero-Day Alerts" value={metrics.zeroDay} icon={Skull} colorClass="text-red-600" />
    </div>
  );
};

export default MetricsBar;
