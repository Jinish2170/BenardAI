"""Bernard FastAPI server: REST + NDJSON streaming."""
from __future__ import annotations
import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from ..config import CONFIG
from ..orchestrator import analyze, detect_kind
from ..store import STORE
from ..types import AnalysisInput, ProgressEvent

app = FastAPI(
    title="Bernard",
    description="Self-hosted AI threat triage workstation",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent.parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/health")
async def health():
    return {"status": "ok", "model": CONFIG.llm.model, "vt_configured": bool(CONFIG.intel.vt_api_key)}


def _save_upload(upload: UploadFile) -> Path:
    suffix = Path(upload.filename or "sample").suffix
    fd = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, dir=UPLOAD_DIR)
    try:
        shutil.copyfileobj(upload.file, fd)
        fd.flush()
    finally:
        fd.close()
        upload.file.close()
    return Path(fd.name)


def _build_input(*, file: Optional[UploadFile], value: Optional[str]) -> AnalysisInput:
    if file is not None and (file.filename or "").strip():
        path = _save_upload(file)
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > CONFIG.server.max_upload_mb:
            path.unlink(missing_ok=True)
            raise HTTPException(413, f"Upload exceeds MAX_UPLOAD_MB={CONFIG.server.max_upload_mb}")
        return AnalysisInput(
            kind="file",
            value=file.filename or path.name,
            filename=file.filename,
            file_path=str(path),
        )
    if not value or not value.strip():
        raise HTTPException(400, "Provide either a file upload or a `value` (url/ip/domain/hash)")
    try:
        kind = detect_kind(value)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return AnalysisInput(kind=kind, value=value.strip())


@app.post("/analyze")
async def analyze_endpoint(
    file: Optional[UploadFile] = File(None),
    value: Optional[str] = Form(None),
):
    inp = _build_input(file=file, value=value)
    try:
        record = await asyncio.wait_for(analyze(inp), timeout=CONFIG.server.analysis_timeout_s)
    except asyncio.TimeoutError:
        raise HTTPException(504, f"Analysis exceeded {CONFIG.server.analysis_timeout_s}s timeout")
    except Exception as exc:
        raise HTTPException(500, f"Analysis failed: {exc}")
    return record.model_dump(mode="json")


@app.post("/analyze/stream")
async def analyze_stream_endpoint(
    file: Optional[UploadFile] = File(None),
    value: Optional[str] = Form(None),
):
    inp = _build_input(file=file, value=value)

    async def gen() -> AsyncIterator[bytes]:
        queue: asyncio.Queue[ProgressEvent | None] = asyncio.Queue()

        def emit(ev: ProgressEvent) -> None:
            # called from sync analyzer threads; put_nowait is fine
            try:
                queue.put_nowait(ev)
            except Exception:
                pass

        task = asyncio.create_task(analyze(inp, emit=emit))

        try:
            while True:
                if task.done() and queue.empty():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                if ev is None:
                    break
                yield (json.dumps({"event": "progress", "data": ev.model_dump(mode="json")}) + "\n").encode()
        finally:
            try:
                record = await task
                yield (json.dumps({"event": "result", "data": record.model_dump(mode="json")}) + "\n").encode()
            except Exception as exc:
                yield (json.dumps({"event": "error", "data": {"message": str(exc)}}) + "\n").encode()

    return StreamingResponse(gen(), media_type="application/x-ndjson")


@app.get("/analyses")
async def list_analyses(limit: int = 50):
    summaries = STORE.list(limit=min(limit, 200))
    return {"success": True, "count": len(summaries), "analyses": [s.model_dump(mode="json") for s in summaries]}


@app.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    rec = STORE.get(analysis_id)
    if not rec:
        raise HTTPException(404, f"Analysis not found: {analysis_id}")
    return rec.model_dump(mode="json")


def main() -> None:
    import uvicorn
    uvicorn.run(
        "bernard.api.server:app",
        host="0.0.0.0",
        port=CONFIG.server.port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
