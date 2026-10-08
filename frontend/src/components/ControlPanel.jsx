import React, { useState } from 'react';
import { Play, Square, UploadCloud, Settings2, Zap } from 'lucide-react';
import { startStream, stopStream, injectAttack, updateThreshold } from '../services/api';

const ControlPanel = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [loading, setLoading] = useState(false);
  
  const [threshold, setThreshold] = useState(70);
  const [injectParams, setInjectParams] = useState({
    packet_size: 8500,
    error_rate: 0.95,
    protocol: 'TCP'
  });

  const handleStart = async () => {
    setLoading(true);
    try {
      await startStream();
      setIsRunning(true);
    } catch (error) {
      console.error("Failed to start stream", error);
    }
    setLoading(false);
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      await stopStream();
      setIsRunning(false);
    } catch (error) {
      console.error("Failed to stop stream", error);
    }
    setLoading(false);
  };

  const handleThresholdChange = async (e) => {
    const val = parseInt(e.target.value);
    setThreshold(val);
    try {
      await updateThreshold(val);
    } catch (error) {
      console.error("Failed to update threshold", error);
    }
  };

  const handleInject = async () => {
    try {
      await injectAttack(injectParams);
    } catch (error) {
      console.error("Failed to inject", error);
    }
  };

  return (
    <div className="bg-white/80 backdrop-blur-md border border-white/60 shadow-xl rounded-lg p-6 h-full text-slate-950">
      <h2 className="text-lg font-semibold mb-6 flex items-center">
        <Settings2 className="w-5 h-5 mr-2 text-slate-500" /> Controls
      </h2>

      <div className="space-y-6">
        <div>
          <h3 className="text-sm font-medium text-slate-500 mb-3 uppercase tracking-wider">Engine Status</h3>
          <div className="flex space-x-3">
            <button
              onClick={handleStart}
              disabled={isRunning || loading}
              className={`flex-1 flex justify-center items-center py-2 px-4 rounded-md font-medium transition-all ${isRunning
                  ? 'bg-slate-100 text-slate-400 cursor-not-allowed border border-slate-200'
                  : 'bg-emerald-50 text-emerald-600 hover:bg-emerald-100 border border-emerald-200'
                }`}
            >
              <Play className="w-4 h-4 mr-2" /> Start
            </button>
            <button
              onClick={handleStop}
              disabled={!isRunning || loading}
              className={`flex-1 flex justify-center items-center py-2 px-4 rounded-md font-medium transition-all ${!isRunning
                  ? 'bg-slate-100 text-slate-400 cursor-not-allowed border border-slate-200'
                  : 'bg-rose-50 text-rose-600 hover:bg-rose-100 border border-rose-200'
                }`}
            >
              <Square className="w-4 h-4 mr-2" /> Stop
            </button>
          </div>
        </div>

        <div className="pt-4 border-t border-slate-200">
          <h3 className="text-sm font-medium text-slate-500 mb-3 uppercase tracking-wider">Dataset</h3>
          <button className="w-full flex items-center justify-center py-2 px-4 bg-slate-100 hover:bg-slate-200 text-slate-600 rounded-md transition-colors font-medium border border-slate-200">
            <UploadCloud className="w-4 h-4 mr-2" />
            Upload Benchmark PCAP
          </button>
        </div>

        <div className="pt-4 border-t border-slate-200">
          <h3 className="text-sm font-medium text-slate-500 mb-3 uppercase tracking-wider">Manual Testing Payload</h3>
          <div className="space-y-3 mb-4 text-sm">
            <div className="flex justify-between items-center">
              <span className="text-slate-600">Packet Size</span>
              <input type="number" value={injectParams.packet_size} onChange={e => setInjectParams({...injectParams, packet_size: parseInt(e.target.value)})} className="bg-white border border-slate-300 rounded px-2 py-1 w-20 text-slate-950 outline-none focus:border-blue-500" />
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-600">Error Rate</span>
              <input type="number" step="0.01" value={injectParams.error_rate} onChange={e => setInjectParams({...injectParams, error_rate: parseFloat(e.target.value)})} className="bg-white border border-slate-300 rounded px-2 py-1 w-20 text-slate-950 outline-none focus:border-blue-500" />
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-600">Protocol</span>
              <select value={injectParams.protocol} onChange={e => setInjectParams({...injectParams, protocol: e.target.value})} className="bg-white border border-slate-300 rounded px-2 py-1 w-20 text-slate-950 outline-none focus:border-blue-500">
                <option>TCP</option>
                <option>UDP</option>
              </select>
            </div>
          </div>
          <button 
            onClick={handleInject}
            className="w-full flex items-center justify-center py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors font-medium border border-blue-700 shadow-sm"
          >
            <Zap className="w-4 h-4 mr-2" />
            Inject Zero-Day Attack
          </button>
        </div>

        <div className="pt-4 border-t border-slate-200">
          <h3 className="text-sm font-medium text-slate-500 mb-3 uppercase tracking-wider">Parameters</h3>
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-slate-600">Confidence Threshold</span>
                <span className="text-blue-600 font-mono font-medium">{threshold}%</span>
              </div>
              <input
                type="range"
                min="50" max="95" value={threshold} onChange={handleThresholdChange}
                className="w-full accent-blue-600 cursor-pointer"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ControlPanel;
