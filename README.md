# EdgeGuard

EdgeGuard is a FastAPI and React/Vite CDN simulator for cache-policy
experiments, request replay, traffic classification, demand prediction,
trusted-demand estimation, placement, and dry-run-first recovery.

## Run the backend

From the project root in PowerShell:

```powershell
Set-Location backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`; interactive API
documentation is at `http://127.0.0.1:8000/docs`.

## Run the dashboard

In a second terminal, from the project root:

```powershell
Set-Location frontend
npm ci
npm run dev
```

Open the Vite address shown in the terminal (by default
`http://127.0.0.1:5173`). `VITE_API_BASE_URL` can override the backend
base URL. The backend allows both localhost and 127.0.0.1 Vite origins;
set `EDGEGUARD_CORS_ORIGINS` to a comma-separated origin list when
serving the dashboard elsewhere.

## Tests and production build

From the project root:

```powershell
Set-Location backend
python -m unittest discover -s tests -v
```

In a second terminal:

```powershell
Set-Location frontend
npm run test
npm run build
npm run lint
```

The frontend test command runs the dashboard interactions in jsdom with the
backend API mocked; it does not start a server or contact external services.

## Offline experiment evaluation

The project does not call hosted APIs or require cloud services. Its benchmark
runner uses the bundled request traces and simulated attack generators. Start
with a small replay limit, especially for the large Wikimedia and web-log files.

From the project root, run all four cache policies against the bundled
synthetic trace:

```powershell
Set-Location backend
python -m app.benchmark --datasets synthetic --limit 10000
```

Add controlled scenarios and repeat them with fixed seeds:

```powershell
python -m app.benchmark `
  --datasets synthetic `
  --limit 10000 `
  --scenarios cache_pollution distributed_low_rate flash_crowd `
  --seeds 42 17 99 `
  --request-count 2000 `
  --cache-capacity-mb 64
```

Each cache-policy run starts with an empty edge cache and replays the same
ordered input. The runner reports hit ratio, origin bytes, average and p95
latency, evictions, and elapsed time. Throughput and elapsed time depend on the
machine; compare the other metrics as the primary simulation outcomes. For
generated scenarios, each seed's results are retained and the CSV and console
also report per-scenario/policy means and population standard deviations for
hit ratio, origin bytes, p95 latency, and evictions. The summary deliberately
does not aggregate throughput. The optional `--cache-capacity-mb` overrides
the selected edge's capacity for the benchmark only; the configured capacity
is restored afterward. A constrained capacity can create eviction pressure
and reveal policy differences that a large cache and short trace may hide.
Results are written to `backend/data/cache_benchmark.csv` and saved in
`backend/data/edgeguard_experiments.sqlite3`. Set `EDGEGUARD_EXPERIMENT_DB` to
choose another local SQLite file.

For model workflows, first replay traffic from **Experiments** and verify it
appears in backend metrics. Request events and trained models are held in
memory; restarting the backend or using **Reset backend state** clears them.

- **Demand forecast evaluation:** In **Traffic Detection & Trusted Demand**,
  click **Evaluate demand forecast**. It uses complete chronological windows
  and compares the Random Forest with a recency-weighted baseline using MAE
  and RMSE (lower is better). An incomplete trailing window is ignored. Sparse
  zero-demand windows are deterministically sampled and weighted so fitting
  remains bounded.
- **Demand predictions:** Click **Train demand model**, wait for the training
  response, then click **Predict demand**. The resulting candidate scores are
  computed in a batch before the top results are returned.
- **Anomaly analysis:** Replay enough requests on an edge, generate any attack
  traffic you want to inspect, then click **Train anomaly detector** followed
  by **Analyze anomalies**. The dashboard uses a 10-request window. Training
  needs at least 20 valid events as an initial check and at least 10 complete
  historical training windows; aim for at least 110 valid events on the edge.
  Train after generating the traffic to inspect so the latest window is
  included in the analysis history.
- **Anomaly evaluation:** **Evaluate anomaly detector** is a separate labeled
  holdout evaluation. Replay the synthetic dataset, then generate labeled
  scenario traffic. It reports precision, recall, F1, and a confusion matrix
  for those scenario labels only, not real-world attack-detection accuracy.

If a model button reports too few events, use **Experiments → Refresh backend
metrics** to check the current event count, replay traffic to the intended
edge, and try again without restarting or resetting the backend.

The Overview request trace displays recent hit/miss events. Manual requests,
dataset replays, generated attack runs, and model evaluations are also saved
locally. View these persisted runs on **Experiments → Saved local experiment
history** or through `GET /api/v1/experiments/history`. Resetting the simulated
network does not erase the experiment history.
Use the Overview's **Route requests and attacks to** selector to choose the
edge used by test requests and attack scenarios. They continue to target
Hyderabad by default.

## Typical workflow

1. Generate traffic with **Attack Simulation** or replay `synthetic`,
   `wikimedia`, or `web_logs` from **Experiments**.
2. Train and evaluate the demand model and anomaly detector in **Traffic Detection**.
   Demand prediction can return a documented recency-based fallback when
   history is too small to fit the Random Forest.
3. Analyze traffic, evaluate synthetic scenario labels, and estimate trusted
   demand. The rule-based classification is reported separately from the ML
   anomaly detector.
4. Compare cache policies with the offline benchmark runner; run cache
   placement in recommendation-only mode first.
5. Recovery is dry-run by default. Enable apply mode only when cache
   mutation is intended.
6. Export the frontend session log or the backend JSON/CSV metrics from
   **Experiments**.

The preserved source datasets are streamed during preview and replay;
they are not copied or regenerated by these commands.
The synthetic trace is generated from popularity information in the bundled
Wikimedia trace. The simulator replays requests sequentially using configured
cache sizes, fixed edge/origin latencies, bandwidth, and content sizes; it does
not model concurrent queues, packet loss, live network measurements, or actual
CDN servers. All benchmark and evaluation results—including repeated seeded
runs—are simulator experiments, not production CDN performance or claims of
real-world model accuracy.
