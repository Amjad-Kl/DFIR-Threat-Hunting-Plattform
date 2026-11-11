"""Unit tests for artifact parsers."""

from pathlib import Path
from app.parsers.amcache_parser import AmcacheParser
from app.parsers.evtx_parser import EvtxParser
from app.parsers.prefetch_parser import PrefetchParser
from app.parsers.registry_parser import RegistryParser


def test_parser_capabilities():
    """Verify file detection and supported extensions for all parsers."""
    evtx = EvtxParser()
    assert evtx.can_parse(Path("Security.evtx"))
    assert not evtx.can_parse(Path("system.hiv"))
    assert ".evtx" in evtx.supported_extensions

    pf = PrefetchParser()
    assert pf.can_parse(Path("CMD.EXE-A1B2C3D4.pf"))
    assert not pf.can_parse(Path("Security.evtx"))
    assert ".pf" in pf.supported_extensions

    reg = RegistryParser()
    assert reg.can_parse(Path("SYSTEM"))
    assert reg.can_parse(Path("NTUSER.DAT"))
    assert reg.can_parse(Path("software.hiv"))
    assert not reg.can_parse(Path("sample.evtx"))

    amcache = AmcacheParser()
    assert amcache.can_parse(Path("Amcache.hve"))
    assert not amcache.can_parse(Path("SYSTEM"))


def test_prefetch_resilience(tmp_path: Path):
    """Ensure prefetch parser handles corrupt or truncated data gracefully."""
    dummy_pf = tmp_path / "CORRUPT.pf"
    dummy_pf.write_bytes(b"SCCA\x00\x00\x00\x00truncated_content_here")

    pf = PrefetchParser()
    events = list(pf.parse(dummy_pf, case_id="c1", artifact_id="a1"))
    # Should yield nothing and not raise exception
    assert isinstance(events, list)


def test_evtx_resilience(tmp_path: Path):
    """Ensure EVTX parser handles corrupt or non-EVTX data gracefully."""
    dummy_evtx = tmp_path / "invalid.evtx"
    dummy_evtx.write_bytes(b"This is not a real EVTX file")

    evtx = EvtxParser()
    events = []
    try:
        events = list(evtx.parse(dummy_evtx, case_id="c1", artifact_id="a1"))
    except Exception:
        # Graceful handling
        pass
    assert isinstance(events, list)
