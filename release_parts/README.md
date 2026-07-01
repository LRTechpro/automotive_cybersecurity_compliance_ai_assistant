# Reconstruct the tested v2 source package

From the repository root, run:

```bash
python assemble_v2_release.py
```

The script concatenates the Base64 parts, creates `AutoCyber_Traceability_Workbench_v2.0_source.zip`, and verifies SHA-256:

`73ac09951150f5751f9385190312815a8cc53366496900218e3d45d874d5abc3`

Extract the resulting ZIP, enter `AutoCyber_Traceability_Workbench`, and run `python server.py` or `run_windows.bat`.
