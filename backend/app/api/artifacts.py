"""Artifact Management API Endpoints."""

import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
import aiosqlite

from app.config import settings
from app.database import get_db
from app.models.artifact import Artifact, ArtifactType, ParsingStatus
from app.utils.audit import log_action
from app.utils.hashing import compute_sha256

router = APIRouter(tags=["Artifacts"])


def detect_artifact_type(filename: str) -> ArtifactType:
    """Heuristic identification of artifact type based on filename and extension."""
    lower_name = filename.lower()
    if lower_name.endswith(".evtx"):
        return ArtifactType.EVTX
    if lower_name.endswith(".pf"):
        return ArtifactType.PREFETCH
    if "amcache" in lower_name:
        return ArtifactType.AMCACHE
    if lower_name in ["system", "software", "sam", "security", "ntuser.dat", "usrclass.dat"] or lower_name.endswith(".hiv") or lower_name.endswith(".reg"):
        return ArtifactType.REGISTRY
    return ArtifactType.YARA_TARGET


@router.post("/cases/{case_id}/artifacts", response_model=Artifact, status_code=status.HTTP_201_CREATED)
async def upload_artifact(
    case_id: str,
    file: UploadFile = File(...),
    source_host: Optional[str] = Form(None),
    imported_by: Optional[str] = Form("analyst"),
    artifact_type: Optional[ArtifactType] = Form(None),
    db: aiosqlite.Connection = Depends(get_db),
):
    """Upload a forensic artifact file to a case."""
    # Verify case exists
    c = await db.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not await c.fetchone():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

    artifact_id = str(uuid.uuid4())
    case_evidence_dir = settings.evidence_dir / case_id
    case_evidence_dir.mkdir(parents=True, exist_ok=True)

    dest_filename = f"{artifact_id[:8]}_{file.filename}"
    dest_path = case_evidence_dir / dest_filename

    # Save uploaded file safely
    try:
        with open(dest_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    finally:
        await file.close()

    # Compute forensic SHA-256
    sha256 = compute_sha256(dest_path)
    file_size = dest_path.stat().st_size

    # Auto-detect type if not provided
    inferred_type = artifact_type or detect_artifact_type(file.filename or "")

    now = datetime.now(timezone.utc).isoformat()

    await db.execute(
        """
        INSERT INTO artifacts (
            id, case_id, filename, filepath, artifact_type, file_size,
            sha256, import_time, imported_by, source_host, parsing_status,
            parsing_error, event_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            artifact_id,
            case_id,
            file.filename,
            str(dest_path),
            inferred_type.value,
            file_size,
            sha256,
            now,
            imported_by,
            source_host,
            ParsingStatus.PENDING.value,
            None,
            0,
        ),
    )
    await db.commit()

    await log_action(
        db,
        action="import",
        user_name=imported_by or "analyst",
        entity_type="artifact",
        entity_id=artifact_id,
        details={
            "filename": file.filename,
            "sha256": sha256,
            "size": file_size,
            "type": inferred_type.value,
        },
    )

    return Artifact(
        id=artifact_id,
        case_id=case_id,
        filename=file.filename or "unknown",
        filepath=str(dest_path),
        artifact_type=inferred_type,
        file_size=file_size,
        sha256=sha256,
        import_time=datetime.fromisoformat(now),
        imported_by=imported_by,
        source_host=source_host,
        parsing_status=ParsingStatus.PENDING,
        parsing_error=None,
        event_count=0,
    )


@router.get("/cases/{case_id}/artifacts", response_model=list[Artifact])
async def list_artifacts(case_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """List all ingested artifacts for a case."""
    cursor = await db.execute(
        "SELECT * FROM artifacts WHERE case_id = ? ORDER BY import_time DESC",
        (case_id,),
    )
    rows = await cursor.fetchall()
    return [
        Artifact(
            id=r["id"],
            case_id=r["case_id"],
            filename=r["filename"],
            filepath=r["filepath"],
            artifact_type=ArtifactType(r["artifact_type"]),
            file_size=r["file_size"],
            sha256=r["sha256"],
            import_time=datetime.fromisoformat(r["import_time"]),
            imported_by=r["imported_by"],
            source_host=r["source_host"],
            parsing_status=ParsingStatus(r["parsing_status"]),
            parsing_error=r["parsing_error"],
            event_count=r["event_count"],
        )
        for r in rows
    ]


@router.get("/artifacts/{artifact_id}", response_model=Artifact)
async def get_artifact(artifact_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Get single artifact metadata."""
    cursor = await db.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
    r = await cursor.fetchone()
    if not r:
        raise HTTPException(status_code=404, detail=f"Artifact {artifact_id} not found")

    return Artifact(
        id=r["id"],
        case_id=r["case_id"],
        filename=r["filename"],
        filepath=r["filepath"],
        artifact_type=ArtifactType(r["artifact_type"]),
        file_size=r["file_size"],
        sha256=r["sha256"],
        import_time=datetime.fromisoformat(r["import_time"]),
        imported_by=r["imported_by"],
        source_host=r["source_host"],
        parsing_status=ParsingStatus(r["parsing_status"]),
        parsing_error=r["parsing_error"],
        event_count=r["event_count"],
    )


@router.delete("/artifacts/{artifact_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_artifact(artifact_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Delete an artifact record and remove its physical file."""
    cursor = await db.execute("SELECT filepath, case_id FROM artifacts WHERE id = ?", (artifact_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Artifact {artifact_id} not found")

    filepath = Path(row["filepath"])
    if filepath.exists():
        try:
            filepath.unlink()
        except OSError:
            pass

    await db.execute("DELETE FROM artifacts WHERE id = ?", (artifact_id,))
    await db.commit()

    await log_action(
        db,
        action="delete",
        entity_type="artifact",
        entity_id=artifact_id,
        details={"case_id": row["case_id"]},
    )


@router.post("/artifacts/{artifact_id}/parse")
async def parse_artifact(artifact_id: str, db: aiosqlite.Connection = Depends(get_db)):
    """Trigger parsing of an uploaded artifact file and populate events."""
    cursor = await db.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Artifact {artifact_id} not found")

    filepath = Path(row["filepath"])
    if not filepath.exists():
        raise HTTPException(status_code=400, detail="Artifact file no longer exists on disk")

    art_type = row["artifact_type"]
    case_id = row["case_id"]

    # Mark as parsing
    await db.execute(
        "UPDATE artifacts SET parsing_status = ? WHERE id = ?",
        (ParsingStatus.PARSING.value, artifact_id),
    )
    await db.commit()

    events_inserted = 0
    try:
        parser = None
        if art_type == ArtifactType.EVTX.value:
            from app.parsers.evtx_parser import EvtxParser
            parser = EvtxParser()
        elif art_type == ArtifactType.PREFETCH.value:
            from app.parsers.prefetch_parser import PrefetchParser
            parser = PrefetchParser()
        elif art_type == ArtifactType.REGISTRY.value:
            from app.parsers.registry_parser import RegistryParser
            parser = RegistryParser()
        elif art_type == ArtifactType.AMCACHE.value:
            from app.parsers.amcache_parser import AmcacheParser
            parser = AmcacheParser()

        if parser is not None:
            batch = []
            insert_sql = """
                INSERT INTO events (
                    id, case_id, artifact_id, timestamp, source_type, event_type, severity,
                    source_host, source_user, source_ip, dest_host, dest_ip, dest_port,
                    process_name, process_path, process_pid, parent_process, parent_pid,
                    command_line, file_path, file_hash, registry_key, registry_value,
                    raw_data, channel, event_id, is_suspicious, is_ioc_match
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            for ev in parser.parse(filepath, case_id=case_id, artifact_id=artifact_id):
                record = (
                    ev.id, ev.case_id, ev.artifact_id, ev.timestamp.isoformat(),
                    ev.source_type.value, ev.event_type.value, ev.severity.value,
                    ev.source_host, ev.source_user, ev.source_ip, ev.dest_host,
                    ev.dest_ip, ev.dest_port, ev.process_name, ev.process_path,
                    ev.process_pid, ev.parent_process, ev.parent_pid, ev.command_line,
                    ev.file_path, ev.file_hash, ev.registry_key, ev.registry_value,
                    ev.raw_data, ev.channel, ev.event_id,
                    1 if ev.is_suspicious else 0,
                    1 if ev.is_ioc_match else 0,
                )
                batch.append(record)
                if len(batch) >= 1000:
                    await db.executemany(insert_sql, batch)
                    events_inserted += len(batch)
                    batch.clear()

            if batch:
                await db.executemany(insert_sql, batch)
                events_inserted += len(batch)

        # Mark done
        await db.execute(
            """
            UPDATE artifacts 
            SET parsing_status = ?, event_count = ?, parsing_error = NULL 
            WHERE id = ?
            """,
            (ParsingStatus.DONE.value, events_inserted, artifact_id),
        )
        await db.commit()

        await log_action(
            db,
            action="parse",
            entity_type="artifact",
            entity_id=artifact_id,
            details={"events_extracted": events_inserted, "artifact_type": art_type},
        )

        return {
            "artifact_id": artifact_id,
            "status": "done",
            "events_extracted": events_inserted,
        }

    except Exception as exc:
        await db.execute(
            """
            UPDATE artifacts 
            SET parsing_status = ?, parsing_error = ? 
            WHERE id = ?
            """,
            (ParsingStatus.ERROR.value, str(exc), artifact_id),
        )
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Parsing error: {exc}")

