import React from 'react';
import { ShieldAlert, Info } from 'lucide-react';

const LiveTrafficFeed = ({ alerts, onViewAlert }) => {
  return (
    <div className="bg-white/80 backdrop-blur-md border border-white/60 shadow-xl rounded-lg p-6 h-[600px] flex flex-col">
      <h2 className="text-lg font-semibold mb-4 flex items-center text-slate-950">
        <ShieldAlert className="w-5 h-5 mr-2 text-blue-600" /> Live Threat Feed
      </h2>
      <div className="flex-1 overflow-auto pr-2">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-200 text-slate-500 text-sm">
              <th className="pb-3 font-medium">Time</th>
              <th className="pb-3 font-medium">Packet ID</th>
              <th className="pb-3 font-medium">Classification</th>
              <th className="pb-3 font-medium">Severity</th>
              <th className="pb-3 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 ? (
              <tr>
                <td colSpan="5" className="text-center py-8 text-slate-500">Listening for threats...</td>
              </tr>
            ) : (
              alerts.map((alert) => (
                <tr key={alert.alertId} className="border-b border-slate-200 hover:bg-slate-100/50 transition-colors">
                  <td className="py-3 text-sm text-slate-950">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-3 font-mono text-xs text-slate-500">{alert.packetId}</td>
                  <td className="py-3 text-sm">
                    {alert.type === 'Novel Zero-Day Attack' ? (
                      <span className="text-red-600 font-medium flex items-center">
                        {alert.type}
                      </span>
                    ) : (
                      <span className="text-amber-600">{alert.type}</span>
                    )}
                  </td>
                  <td className="py-3">
                    <span className={`px-2 py-1 text-xs rounded-full font-medium ${
                      alert.severity === 'CRITICAL' ? 'bg-red-50 text-red-600 border border-red-200' : 'bg-amber-50 text-amber-600 border border-amber-200'
                    }`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="py-3 text-right">
                    <button 
                      onClick={() => onViewAlert(alert)}
                      className="p-1.5 bg-slate-100 hover:bg-blue-50 rounded text-blue-600 transition-colors border border-slate-200 hover:border-blue-200"
                      title="View Details"
                    >
                      <Info className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default LiveTrafficFeed;
