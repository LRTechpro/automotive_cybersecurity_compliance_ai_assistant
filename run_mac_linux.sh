#!/usr/bin/env sh
set -e
cd "$(dirname "$0")"

if [ ! -f "AutoCyber_Traceability_Workbench/server.py" ]; then
  echo "Reconstructing the tested v2.0 source package..."
  python3 assemble_v2_release.py
  python3 -m zipfile -e AutoCyber_Traceability_Workbench_v2.0_source.zip .
fi

cd AutoCyber_Traceability_Workbench
python3 server.py
