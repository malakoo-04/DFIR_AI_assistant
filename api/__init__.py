"""
Web API layer.

Exposes the DFIR pipeline (scripts/) over HTTP via FastAPI. Contains
no pipeline logic itself -- `modules/` is the actual application
backend; this package only wraps it for the browser GUI.

Run: uvicorn api.main:app --reload
"""
