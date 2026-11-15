
const API_BASE_URL = (
    import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

export async function apiRequest(path, options = {}) {
    let response;
    try {
        response = await fetch(`${API_BASE_URL}${path}`, {
            ...options,
            headers: {
                ...(options.body ? { "Content-Type": "application/json" } : {}),
                ...options.headers,
            },
        });
    } catch (error) {
        if (error instanceof TypeError) {
            throw new Error(
                `Could not reach ${API_BASE_URL}. Check that FastAPI is running and that its CORS settings allow this dashboard origin.`
            );
        }
        throw error;
    }

    const text = await response.text();
    let data = null;

    try {
        data = text ? JSON.parse(text) : null;
    } catch {
        data = { detail: text };
    }

    if (!response.ok) {
        const detail =
            data?.detail ||
            data?.message ||
            `Request failed with HTTP ${response.status}`;

        throw new Error(
            typeof detail === "string" ? detail : JSON.stringify(detail)
        );
    }

    return data;
}

export function getApiBaseUrl() {
    return API_BASE_URL;
}

export async function downloadApiFile(path, filename) {
    let response;
    try {
        response = await fetch(`${API_BASE_URL}${path}`);
    } catch (error) {
        if (error instanceof TypeError) {
            throw new Error(
                `Could not reach ${API_BASE_URL}. Check that FastAPI is running and that its CORS settings allow this dashboard origin.`
            );
        }
        throw error;
    }

    if (!response.ok) {
        const text = await response.text();
        throw new Error(
            text || `Export failed with HTTP ${response.status}`
        );
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function checkBackend() {
    return apiRequest("/openapi.json");
}

export const endpoints = {
    networkTopology: "/api/v1/network/topology",
    networkStats: "/api/v1/network/stats",
    recentEvents: "/api/v1/metrics/events?limit=8",
    experimentHistory: "/api/v1/experiments/history?limit=100",
    simulateRequest: "/api/v1/network/simulate-request",
    resetNetwork: "/api/v1/network/reset",
    replayDataset: "/api/v1/datasets/replay",
    cacheStrategy: (edgeId) => `/api/v1/cache/${edgeId}/strategy`,
    cacheStats: "/api/v1/cache/stats",
    metrics: "/api/v1/metrics",
    exportMetricsJson: "/api/v1/metrics/export/json",
    exportMetricsCsv: "/api/v1/metrics/export/csv",
    trainDemand: "/api/v1/ai/demand/train",
    evaluateDemand: "/api/v1/ai/demand/evaluate",
    demandPredictions: "/api/v1/ai/demand/predictions",
    trainAnomaly: "/api/v1/ai/anomaly/train",
    evaluateAnomaly: "/api/v1/ai/anomaly/evaluate",
    analyzeAnomaly: "/api/v1/ai/anomaly/analyze",
    attackSimulation: "/api/v1/security/attacks/simulate",
    discriminationAnalyze: "/api/v1/security/discrimination/analyze",
    discriminationEvaluate: "/api/v1/security/discrimination/evaluate",
    trustedDemand: "/api/v1/security/trusted-demand/estimate",
    placement: "/api/v1/cache/placement/optimize",
    recovery: "/api/v1/cache/recovery/run",
    recoveryHistory: "/api/v1/cache/recovery/history",
};
