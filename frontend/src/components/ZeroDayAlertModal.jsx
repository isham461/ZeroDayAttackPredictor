import React from 'react';
import { X, AlertOctagon, Terminal } from 'lucide-react';

const ZeroDayAlertModal = ({ alert, onClose }) => {
  return (
    <div className="fixed inset-0 bg-slate-900/20 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white/80 backdrop-blur-md border border-white/60 shadow-xl rounded-xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        <div className="p-4 border-b border-slate-200 flex justify-between items-center bg-slate-50/50">
          <div className="flex items-center space-x-2 text-red-600">
            <AlertOctagon className="w-5 h-5" />
            <h3 className="font-bold tracking-wide">ZERO-DAY DETECTED</h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <div className="p-6 space-y-6">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-sm text-slate-500 mb-1">Alert ID</p>
              <p className="font-mono text-xs text-slate-600 bg-slate-100 px-2 py-1 rounded inline-block border border-slate-200">
                {alert.alertId}
              </p>
            </div>
            <div className="text-right">
              <p className="text-sm text-slate-500 mb-1">Timestamp</p>
              <p className="text-sm text-slate-950 font-medium">
                {new Date(alert.timestamp).toLocaleString()}
              </p>
            </div>
          </div>

          <div className="bg-slate-50 rounded-lg p-4 font-mono text-sm border border-slate-200 shadow-inner">
            <div className="flex items-center space-x-2 mb-3 text-slate-500">
              <Terminal className="w-4 h-4" />
              <span>Diagnostic Data</span>
            </div>
            <div className="space-y-2 text-slate-700">
              <p><span className="text-blue-600 font-semibold">Target Packet:</span> {alert.packetId}</p>
              <p><span className="text-blue-600 font-semibold">Classification:</span> <span className="text-red-600 font-bold">{alert.type}</span></p>
              <p><span className="text-blue-600 font-semibold">Analysis:</span> {alert.details}</p>
            </div>
          </div>

          <div className="pt-2">
            <h4 className="text-sm font-medium text-slate-500 mb-3">ML Inference Pipeline</h4>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm text-slate-700 font-medium">Stage 1: Isolation Forest (Anomaly)</span>
                <span className="text-xs bg-emerald-50 text-emerald-600 px-2 py-1 rounded border border-emerald-200 font-bold">FLAGGED</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-slate-700 font-medium">Stage 2: Random Forest (Confidence)</span>
                <span className="text-xs bg-red-50 text-red-600 px-2 py-1 rounded border border-red-200 font-bold">&lt; THRESHOLD</span>
              </div>
            </div>
          </div>
        </div>
        
        <div className="p-4 border-t border-slate-200 bg-slate-50/50 flex justify-end space-x-3">
          <button 
            onClick={() => {
              alert("Source IP Null-Routed: " + (alert.details.match(/from ([0-9.]+)/)?.[1] || "Unknown"));
            }}
            className="px-4 py-2 bg-emerald-50 hover:bg-emerald-100 text-emerald-600 border border-emerald-200 rounded-md transition-colors text-sm font-medium shadow-sm"
          >
            Quarantine Flow
          </button>
          <button 
            onClick={() => {
              const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(alert, null, 2));
              const downloadAnchorNode = document.createElement('a');
              downloadAnchorNode.setAttribute("href", dataStr);
              downloadAnchorNode.setAttribute("download", "signature_" + alert.alertId + ".json");
              document.body.appendChild(downloadAnchorNode);
              downloadAnchorNode.click();
              downloadAnchorNode.remove();
            }}
            className="px-4 py-2 bg-blue-50 hover:bg-blue-100 text-blue-600 border border-blue-200 rounded-md transition-colors text-sm font-medium shadow-sm"
          >
            Export Signature
          </button>
          <button 
            onClick={onClose}
            className="px-4 py-2 bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 rounded-md transition-colors text-sm font-medium shadow-sm"
          >
            Acknowledge & Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default ZeroDayAlertModal;
