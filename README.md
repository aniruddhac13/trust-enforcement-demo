# Trust Enforcement Demo Prototype

This repository contains a demonstration prototype for automated trust enforcement in a consent-aware data exchange setting.

The prototype makes the trust flow explicit and observable across a modular system. It is designed to show how authentication, certificate issuance, consent verification, key release and resource access can be linked through concrete cryptographic artifacts rather than implicit trust assumptions.

## Overview

The system is organized as five independent backend services and one frontend interface:

- **AAA** - Authentication, session lifecycle and token validation
- **CA** - Session and transaction certificate issuance and revocation
- **CM** - Consent evaluation and signed approval generation
- **KM** - Protected data-key release and transaction-key re-encryption
- **RM** - Encrypted resource storage and retrieval coordination
- **Frontend** - Interactive multi-workspace interface for live system operation, artifact visibility and stepwise execution of legitimate and adversarial flows

## Highlights

This prototype is intended to make trust enforcement visible rather than implicit. In particular, it shows:

- **Explicit trust propagation** - Identities are bound to session certificates and then to transaction certificates.
- **Consent-bound key release** - Consent approval is tied to a specific transaction certificate before key release is allowed.
- **Policy-decoupled enforcement** - Consent evaluation and cryptographic enforcement remain modular rather than being collapsed into a single component.
- **Data-blind storage** - Encrypted resources are stored separately from usable decryption keys.
- **Inspectable legitimate and adversarial executions** - Secured flows and representative attack scenarios can be observed step by step through the same interface.

The frontend exposes the main cryptographic and protocol artifacts directly including CSRs, certificates, signatures, encrypted resources, encrypted data keys, re-encrypted data keys and final plaintext recovery.

## Architecture

```text
common/                  Shared configuration, cryptographic helpers, models, storage helpers
services/aaa_service/    Authentication and session lifecycle
services/ca_service/     Certificate issuance, revocation and replay artifacts
services/cm_service/     Consent policy and signed approval generation
services/km_service/     Key release enforcement and re-encryption
services/rm_service/     Encrypted resource storage and coordination
frontend/                Interactive multi-workspace demonstration interface
scripts/                 Install, bootstrap, start, stop and cleanup
artifacts/               Generated PKI and runtime artifacts
sample_data/             Sample plaintext input
```

## Prerequisites

Before running the prototype, make sure the following are available on the machine:

- Linux shell environment
- Python 3.11 or newer
- Git
- A modern web browser

Check the installed versions:

```bash
python3 --version
git --version
```

## Getting the Code

Clone the repository and enter the project root:

```bash
git clone https://github.com/aniruddhac13/trust-enforcement-demo.git
cd trust-enforcement-demo
```

## Installation

Make the helper scripts executable:

```bash
chmod +x scripts/*.sh
```

Create a local Python virtual environment and install dependencies:

```bash
./scripts/install_python_env.sh
```

This creates a `.venv/` directory and installs the required Python packages from `requirements.txt`.

Manual activation of the virtual environment is optional because the startup script uses `.venv` automatically when it exists. For debugging or running commands manually, activate it with:

```bash
source .venv/bin/activate
```

Deactivate it with:

```bash
deactivate
```

## Starting the System

Start all backend services and the frontend:

```bash
./scripts/start_all.sh
```

This script:

1. Prepares generated state and PKI artifacts if needed
2. Starts AAA, CA, CM, KM, RM and the frontend
3. Writes logs under `demo_runtime/logs/`
4. Writes process IDs under `demo_runtime/pids/`

Open the frontend in a browser:

```text
http://127.0.0.1:8080
```

## Configurable Ports

If frontend port `8080` is already in use, choose another port:

```bash
FRONTEND_PORT=8081 ./scripts/start_all.sh
```

All service ports can be configured through environment variables:

- `AAA_PORT`
- `CA_PORT`
- `CM_PORT`
- `KM_PORT`
- `RM_PORT`
- `FRONTEND_PORT`

Example:

```bash
AAA_PORT=8501 CA_PORT=8502 CM_PORT=8503 KM_PORT=8504 RM_PORT=8505 FRONTEND_PORT=8081 ./scripts/start_all.sh
```

Then open:

```text
http://127.0.0.1:8081
```

## Personas

The frontend includes the following built-in personas:

| Persona | Username | Password | Role |
|---|---|---|---|
| Alice | `alice` | `alice123` | Legitimate Data Owner |
| Bob | `bob` | `bob123` | Legitimate Data Requester |
| Mallory | `mallory` | `mallory123` | Malicious Data Requester |
| DT | `dt` | `dt123` | Malicious Data Trust / Internal Adversary |

## Frontend Workspaces

The frontend is organized as a single-window tabbed interface:

- **Home** - System entry point and service health overview
- **Legitimate Flow** - Alice and Bob perform the main data exchange flow
- **Malicious Requester** - Replay-oriented requester attacks
- **Malicious DT** - Post-consent certificate substitution attack
- **Mission Control** - Live service health and event traces

## Walkthrough

A typical run is:

1. Open the frontend.
2. Go to **Legitimate Flow**.
3. Log in as **Alice**.
4. Upload an encrypted resource and register consent.
5. Log in as **Bob**.
6. Issue Bob's transaction certificate for a selected resource.
7. Request CM approval.
8. Inspect the generated certificates, signatures, approval payload, encrypted resource and encrypted key artifacts.
9. Complete Bob's download and verify plaintext recovery.
10. Use **Mission Control** to observe service-level events across AAA, CA, CM, KM and RM.

For adversarial scenarios:

- Use **Malicious Requester** after Bob has in-progress session and transaction certificates.
- Use **Malicious DT** after Bob has obtained CM approval but before Bob completes key release.
- Return to **Mission Control** to inspect the corresponding validation outcomes.

## Stopping the System

Stop all running services:

```bash
./scripts/stop_all.sh
```

This stops processes recorded under `demo_runtime/pids/`. It does not remove generated state, logs, PKI artifacts or the virtual environment.

## Full Cleanup

To remove generated runtime artifacts and return to a clean state:

```bash
./scripts/cleanup_generated_state.sh
```

This removes:

- Running service processes
- Runtime logs
- PID files
- Generated service state
- Stored encrypted resources
- Generated PKI artifacts
- Python cache files
- Local `.venv/` virtual environment

After running full cleanup, reinstall dependencies before the next run:

```bash
./scripts/install_python_env.sh
./scripts/start_all.sh
```

## Important Implementation Notes

- The default local run path uses HTTP on localhost.
- Certificate and artifact validation is performed at the application layer by the prototype.
- Generated PKI and runtime state are recreated automatically when the system is bootstrapped again.
- Logs are written to `demo_runtime/logs/` and are useful for debugging service startup or flow execution.

## Troubleshooting

### Frontend does not open on port 8080

Start the frontend on a different port:

```bash
FRONTEND_PORT=8081 ./scripts/start_all.sh
```

Then open:

```text
http://127.0.0.1:8081
```

### A service does not appear healthy

Check the logs:

```bash
ls demo_runtime/logs
cat demo_runtime/logs/frontend.log
cat demo_runtime/logs/aaa.log
cat demo_runtime/logs/ca.log
cat demo_runtime/logs/cm.log
cat demo_runtime/logs/km.log
cat demo_runtime/logs/rm.log
```

### Need to restart without deleting state

```bash
./scripts/stop_all.sh
./scripts/start_all.sh
```

### Need a completely fresh run

```bash
./scripts/cleanup_generated_state.sh
./scripts/install_python_env.sh
./scripts/start_all.sh
```

## Repository Purpose

This codebase is a local, runnable prototype for exploring automated trust enforcement in consent-aware data exchange. It is designed to make the system behavior, cryptographic artifacts and validation points visible across both legitimate and adversarial execution paths.

