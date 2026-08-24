import shutil
from pathlib import Path
from typing import List

from fastapi import Depends, FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session

from config import UPLOAD_DIR, SECRET_KEY
from database import init_db, get_db
from auth import router as auth_router, require_user, get_current_user, User
from job_manager import job_manager
from pipeline_adapter import run_analysis

app = FastAPI(title="DFIR Kill Chain Platform")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax")

init_db()

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app.include_router(auth_router)


@app.get("/")
def index(request: Request, db: Session = Depends(get_db)):
    # Server-side gate: no session -> straight to the login page, so the
    # SPA's fetch() calls never even get a chance to 401.
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login")
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        return RedirectResponse("/")
    return FileResponse(FRONTEND_DIR / "login.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.post("/api/jobs")
async def create_job(files: List[UploadFile] = File(...), user: User = Depends(require_user)):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    job = job_manager.create_job(filenames=[f.filename for f in files], owner_id=user.id)
    job_dir = UPLOAD_DIR / job.id
    job_dir.mkdir(parents=True, exist_ok=True)

    saved_paths: List[Path] = []
    for f in files:
        dest = job_dir / f.filename
        with dest.open("wb") as out:
            shutil.copyfileobj(f.file, out)
        saved_paths.append(dest)

    job_manager.submit(job.id, run_analysis, saved_paths, job_manager.update_stage)
    return job.to_summary()


@app.get("/api/jobs")
def list_jobs(user: User = Depends(require_user)):
    return [j.to_summary() for j in job_manager.list_jobs(owner_id=user.id)]


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str, user: User = Depends(require_user)):
    job = job_manager.get(job_id)
    # 404 (not 403) on a job that exists but belongs to someone else, so job
    # IDs can't be used to probe which jobs exist for other users.
    if job is None or job.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.to_full()


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str, user: User = Depends(require_user)):
    job = job_manager.get(job_id)
    if job is None or job.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Job not found")

    ok = job_manager.cancel(job_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Job already finished and can't be cancelled.")
    return job_manager.get(job_id).to_summary()
