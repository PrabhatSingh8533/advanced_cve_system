import axios from "axios";

// Auto-detect API URL
// Development: http://localhost:8000
// Production: Your Render URL
const BASE_URL =
    process.env.REACT_APP_API_URL ||
    "http://localhost:8000";

const api = axios.create({
    baseURL: BASE_URL,
    timeout: 30000,
    headers: { "Content-Type": "application/json" },
});

api.interceptors.response.use(
    (r) => r.data,
    (error) => {
        const msg =
            error.response?.data?.detail ||
            error.message ||
            "Request failed";
        return Promise.reject(msg);
    }
);

export const cveApi = {
    list: (params) => api.get("/api/cves/", { params }),
    search: (q, page = 1, pageSize = 20) =>
        api.get("/api/cves/search", {
            params: { q, page, page_size: pageSize },
        }),
    getById: (id) => api.get(`/api/cves/${id}`),
    stats: () => api.get("/api/cves/stats"),
    recent: (days = 7, limit = 20) =>
        api.get("/api/cves/recent", { params: { days, limit } }),
    critical: (limit = 20) =>
        api.get("/api/cves/critical", { params: { limit } }),
};

export const analyticsApi = {
    summary: () => api.get("/api/analytics/summary"),
    overview: () => api.get("/api/analytics/overview"),
    monthlyChart: () => api.get("/api/analytics/charts/monthly"),
    severityChart: () => api.get("/api/analytics/charts/severity"),
    rce: () => api.get("/api/analytics/rce"),
    os: () => api.get("/api/analytics/os"),
    forecast: (steps = 12) =>
        api.get("/api/analytics/forecast", { params: { steps } }),
    heatmap: () => api.get("/api/analytics/heatmap"),
};

export const bertApi = {
    status: () => api.get("/api/bert/status"),
    labels: () => api.get("/api/bert/labels"),
    dataReport: () => api.get("/api/bert/data-report"),
    trainReal: (settings) =>
        api.post("/api/bert/train-real", settings),
    predict: (text) =>
        api.post("/api/bert/predict-real", null, {
            params: { text },
        }),
};

export const severityApi = {
    status: () => api.get("/api/severity/status"),
    train: (settings) =>
        api.post("/api/severity/train", settings),
    predict: (text, method = "ensemble") =>
        api.post("/api/severity/predict", { text, method }),
    compare: (text) =>
        api.post("/api/severity/compare", { text }),
};

export const collectApi = {
    status: () => api.get("/api/collect/status"),
    recent: (days = 7) =>
        api.post(`/api/collect/recent?days=${days}`),
    byYear: (year) => api.post(`/api/collect/year/${year}`),
};

export const systemApi = {
    health: () => api.get("/health"),
};

export default api;
