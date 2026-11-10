# PQC Security Monitoring Dashboard

A Streamlit dashboard for tracking an organization's migration to ML-KEM post-quantum cryptography. It uses synthetic data only.

## Setup (first time only)

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
py -m pip install streamlit plotly pandas
```

## Run

```powershell
.\venv\Scripts\Activate.ps1
py -m streamlit run app.py
```

The app opens at http://localhost:8501. Use the sidebar to filter by department and risk level.

If PowerShell blocks the activation script, run this once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```
