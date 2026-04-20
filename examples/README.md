# APPLICATION EXAMPLES REPOSITORY

**CIBIOS/CIBOS/HIP — Complete Example Applications**
**Location:** `examples/` in the CIBOS repository
**Audience:** Application developers learning CIBOS patterns

---

## Repository Structure

```
examples/
├── README.md                   This file
├── hello-lane/                 Minimal lane example
├── channel-communication/      Two containers communicating
├── parallel-computation/       Multiple lanes, all results collected
├── pipeline-processing/        Read → Process → Write pipeline
├── compute-intensive/          Scientific computation with dynamic weights
├── event-driven-ui/            State buffering UI pattern
├── mobile-sensor/              Camera, microphone, GPS access
└── profile-flexible/           Works correctly on all profiles
```

Each example is a complete, buildable, runnable application. Each has its own `Cargo.toml` and `src/main.rs`. Each demonstrates specific HIP/CIBOS patterns with extensive inline comments.
