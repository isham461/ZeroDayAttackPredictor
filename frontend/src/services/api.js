import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080/api';
export const startStream = async () => {
    const response = await axios.post(`${API_BASE_URL}/stream/start`);
    return response.data;
};

export const stopStream = async () => {
    const response = await axios.post(`${API_BASE_URL}/stream/stop`);
    return response.data;
};

export const fetchAlerts = async () => {
    const response = await axios.get(`${API_BASE_URL}/alerts`);
    return response.data;
};

export const injectAttack = async (payload) => {
    const response = await axios.post(`${API_BASE_URL}/stream/inject`, payload || {});
    return response.data;
};

export const updateThreshold = async (thresholdValue) => {
    const response = await axios.post(`${API_BASE_URL}/config/threshold`, { threshold: thresholdValue / 100.0 });
    return response.data;
};
