import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App.jsx";
import { endpoints } from "./api";

const { apiRequestMock, checkBackendMock } = vi.hoisted(() => ({
  apiRequestMock: vi.fn(),
  checkBackendMock: vi.fn(),
}));

vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    apiRequest: apiRequestMock,
    checkBackend: checkBackendMock,
    downloadApiFile: vi.fn(),
    getApiBaseUrl: vi.fn(() => "http://127.0.0.1:8000"),
  };
});

const topology = {
  origin: {
    id: "origin-01",
    name: "Central Origin",
    location: "Origin",
    bandwidth_mbps: 1000,
    processing_latency_ms: 5,
  },
  edges: [
    {
      id: "edge-hyd",
      name: "Hyderabad Edge",
      location: "Hyderabad",
      cache_capacity_mb: 512,
      origin_rtt_ms: 12,
      bandwidth_mbps: 100,
      processing_latency_ms: 1.5,
      cache: {
        used_bytes: 0,
        capacity_bytes: 512 * 1024 * 1024,
        utilization_percent: 0,
        strategy: "LRU",
      },
    },
    {
      id: "edge-mum",
      name: "Mumbai Edge",
      location: "Mumbai",
      cache_capacity_mb: 768,
      origin_rtt_ms: 18,
      bandwidth_mbps: 150,
      processing_latency_ms: 1.5,
      cache: {
        used_bytes: 0,
        capacity_bytes: 768 * 1024 * 1024,
        utilization_percent: 0,
        strategy: "LRU",
      },
    },
    {
      id: "edge-del",
      name: "Delhi Edge",
      location: "Delhi",
      cache_capacity_mb: 640,
      origin_rtt_ms: 24,
      bandwidth_mbps: 120,
      processing_latency_ms: 1.5,
      cache: {
        used_bytes: 0,
        capacity_bytes: 640 * 1024 * 1024,
        utilization_percent: 0,
        strategy: "LRU",
      },
    },
  ],
};

let networkEvents;
let savedRuns;

beforeEach(() => {
  networkEvents = [];
  savedRuns = [];
  checkBackendMock.mockResolvedValue({ paths: { "/": {} } });
  apiRequestMock.mockImplementation(async (path, options = {}) => {
    if (path === endpoints.networkTopology) return topology;
    if (path === endpoints.networkStats) {
      return {
        requests: networkEvents.length,
        cache_hit_ratio: 0,
        origin_requests: networkEvents.length,
        average_latency_ms: 19.5,
        origin_bytes_transferred: networkEvents.length * 131072,
      };
    }
    if (path === endpoints.recentEvents) {
      return { events: [...networkEvents] };
    }
    if (path === endpoints.experimentHistory) {
      return { runs: savedRuns, count: savedRuns.length, limit: 100 };
    }
    if (path === endpoints.simulateRequest) {
      const request = JSON.parse(options.body);
      const result = {
        request_id: "request-1",
        ...request,
        cache_hit: false,
        served_by: "origin",
        total_latency_ms: 19.5,
      };
      networkEvents = [
        {
          ...result,
          timestamp: "2026-01-01T00:00:00.000Z",
          recorded_at: "2026-01-01T00:00:00.000Z",
        },
      ];
      return result;
    }
    return {};
  });
});

afterEach(() => {
  cleanup();
  apiRequestMock.mockReset();
  checkBackendMock.mockReset();
});

describe("EdgeGuard dashboard", () => {
  it("omits developer module and API discovery panels", async () => {
    render(<App />);

    expect(await screen.findByText("Distributed CDN Network")).toBeTruthy();
    expect(screen.queryByText("Module pipeline")).toBeNull();
    expect(screen.queryByText("Backend API discovery")).toBeNull();
    expect(screen.queryByText("13 modules")).toBeNull();
    expect(screen.queryByText(/Module \d+/)).toBeNull();
    expect(screen.queryByText("React · Tailwind CSS · FastAPI")).toBeNull();
  });

  it("shows a simulated origin miss in the request timeline", async () => {
    render(<App />);

    const sendButton = await screen.findByRole("button", {
      name: "Send test request",
    });
    await waitFor(() => expect(sendButton.disabled).toBe(false));
    const edgeSelector = screen.getByRole("combobox", {
      name: "Route requests and attacks to",
    });
    await screen.findByRole("option", { name: "Hyderabad Edge" });
    expect(edgeSelector.value).toBe("edge-hyd");
    fireEvent.change(edgeSelector, { target: { value: "edge-mum" } });
    await waitFor(() => expect(edgeSelector.value).toBe("edge-mum"));
    fireEvent.click(sendButton);

    expect(await screen.findByText("MISS")).toBeTruthy();
    expect(screen.getByText("edgeguard-demo-content")).toBeTruthy();
    expect(apiRequestMock).toHaveBeenCalledWith(
      endpoints.simulateRequest,
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          edge_id: "edge-mum",
          content_id: "edgeguard-demo-content",
          response_size_bytes: 131072,
        }),
      }),
    );
  });

  it("sends an attack scenario to the selected edge", async () => {
    render(<App />);

    const edgeSelector = await screen.findByRole("combobox", {
      name: "Route requests and attacks to",
    });
    await screen.findByRole("option", { name: "Mumbai Edge" });
    fireEvent.change(edgeSelector, { target: { value: "edge-mum" } });
    await waitFor(() => expect(edgeSelector.value).toBe("edge-mum"));

    fireEvent.click(
      await screen.findByRole("button", { name: "Run attack scenario" }),
    );

    await waitFor(() => {
      expect(apiRequestMock).toHaveBeenCalledWith(
        endpoints.attackSimulation,
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            scenario: "cache_pollution",
            edge_id: "edge-mum",
            request_count: 200,
            seed: 42,
          }),
        }),
      );
    });
  });

  it("shows selected-edge attack traffic in the Attack Simulation network view", async () => {
    render(<App />);

    fireEvent.click(
      (await screen.findAllByRole("button", { name: "Attack Simulation" }))[0],
    );

    expect(await screen.findByText("Request flow")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Send test request" })).toBeNull();

    const edgeSelector = await screen.findByRole("combobox", { name: "Edge ID" });
    await screen.findByRole("option", { name: "edge-mum — Mumbai" });
    fireEvent.change(edgeSelector, { target: { value: "edge-mum" } });
    fireEvent.click(
      screen.getByRole("button", { name: "Run traffic simulation" }),
    );

    expect(
      await screen.findByText("Attack traffic targeting edge-mum"),
    ).toBeTruthy();
    expect(screen.getByText("ATTACK")).toBeTruthy();
  });

  it("renders persisted runs on the experiment history page", async () => {
    savedRuns = [
      {
        id: 1,
        created_at: "2026-01-01T00:00:00.000Z",
        operation: "manual_request",
        configuration: { edge_id: "edge-hyd" },
        result: { content_id: "saved-content", cache_hit: false },
      },
    ];
    render(<App />);

    const experimentButtons = await screen.findAllByRole("button", {
      name: "Experiments",
    });
    fireEvent.click(experimentButtons[0]);

    expect(await screen.findByText("manual_request")).toBeTruthy();
    await waitFor(() => {
      expect(apiRequestMock).toHaveBeenCalledWith(endpoints.experimentHistory);
    });
  });
});
