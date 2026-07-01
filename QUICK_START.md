# Quick Start

## Launch from a GitHub clone

### Windows

Double-click `run_windows.bat`. On the first run, it reconstructs the checksum-verified source ZIP, extracts it, and launches the application.

### macOS or Linux

```bash
chmod +x run_mac_linux.sh
./run_mac_linux.sh
```

The application opens at `http://127.0.0.1:8765`.

## First guided assessment

1. Leave **Guided learning** enabled.
2. Open **Assessment campaign** and identify the APIM, GWM, and TCU software baseline.
3. Open **Applicability matrix** and read why the GWM diagnostic-isolation requirement applies.
4. Open **Evidence request plan** and compare requested evidence with received evidence.
5. Open **Control evaluation** and review the seeded GWM result:
   - design effective;
   - implemented;
   - operating effectiveness partially effective;
   - overall partially met.
6. Inspect `EVD-TCU-001`, `EVD-GWM-001`, and `EVD-LOG-001` in **Evidence library**.
7. Open **Findings & actions** to follow the gap through root cause, remediation, retest, and approval.
8. Complete the **Audit defense** questions without revealing expected points.
9. Use **Interview walkthrough** for a five-minute demonstration.

After one guided run, use `run_windows_reset_demo.bat` or run `python server.py --reset` inside the extracted application folder, then repeat in **Analyst mode** before asking the local assistant.
