import React, { useState, useEffect } from 'react';
import MetricsBar from './components/MetricsBar';
import LiveTrafficFeed from './components/LiveTrafficFeed';
import ControlPanel from './components/ControlPanel';
import ZeroDayAlertModal from './components/ZeroDayAlertModal';
import { fetchAlerts } from './services/api';
import { Shield } from 'lucide-react';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState({
    totalInspected: 0,
    normalCount: 0,
    anomalies: 0,
    zeroDay: 0
  });
  const [selectedAlert, setSelectedAlert] = useState(null);

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const fetchedAlerts = await fetchAlerts();
        setAlerts(fetchedAlerts);
        
        const newZeroDay = fetchedAlerts.filter(a => a.type === 'Novel Zero-Day Attack').length;
        const newAnomalies = fetchedAlerts.filter(a => a.severity === 'HIGH').length;
        
        setMetrics(prev => ({
          totalInspected: prev.totalInspected + 1,
          normalCount: prev.totalInspected + 1 - (newAnomalies + newZeroDay),
          anomalies: newAnomalies,
          zeroDay: newZeroDay
        }));
      } catch (error) {
        console.error("Error fetching alerts", error);
      }
    }, 2000); 

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-950 p-6 font-sans">
      <header className="flex items-center space-x-3 mb-8 border-b border-slate-200 pb-4">
        <Shield className="w-8 h-8 text-blue-600" />
        <h1 className="text-2xl font-bold tracking-wider text-slate-950">
          ZeroGuard <span className="text-blue-600 font-light">SOC Dashboard</span>
        </h1>
      </header>

      <div className="grid grid-cols-12 gap-6">
        <div className="col-span-12">
          <MetricsBar metrics={metrics} />
        </div>

        <div className="col-span-12 lg:col-span-3">
          <ControlPanel />
        </div>

        <div className="col-span-12 lg:col-span-9">
          <LiveTrafficFeed alerts={alerts} onViewAlert={setSelectedAlert} />
        </div>
      </div>

      {selectedAlert && (
        <ZeroDayAlertModal 
          alert={selectedAlert} 
          onClose={() => setSelectedAlert(null)} 
        />
      )}
    </div>
  );
}

export default App;
