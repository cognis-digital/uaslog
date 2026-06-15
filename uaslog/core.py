"""Core engine for UASLOG.

Parses counter-UAS sensor logs (JSONL or CSV) into normalized detection
events, then runs a set of analytical rules to flag anomalies useful for
triage: unauthorized RF bands, implausible kinematics (teleporting tracks,
impossible speed/climb), persistent loiter, swarm clustering, and signal
dropouts.

Standard library only. No network access.

Input record fields (any subset; missing fields tolerated):
    timestamp : ISO-8601 string or epoch seconds
    track_id  : string/int identifier for a track
    freq_mhz  : detected RF center frequency in MHz
    rssi_dbm  : received signal strength (dBm)
    lat, lon  : WGS84 degrees
    alt_m     : altitude (meters)
    speed_mps : ground speed (m/s)
    protocol  : detected control/video protocol label
"""

from __future__ import annotations

import csv
import io
import json
import math
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

# Known RF bands commonly associated with consumer/commercial UAS control,
# video downlink, and telemetry. Used to classify detected frequencies.
# (low_mhz, high_mhz, label, authorized)
RF_BANDS: list[tuple[float, float, str, bool]] = [
    (433.0, 435.0, "433 MHz ISM (telemetry)", False),
    (868.0, 870.0, "868 MHz ISM (telemetry)", False),
    (902.0, 928.0, "915 MHz ISM (control)", False),
    (1166.0, 1186.0, "L1 GNSS (spoof risk)", False),
    (2400.0, 2483.5, "2.4 GHz (control/video)", False),
    (5150.0, 5250.0, "5.2 GHz (video downlink)", False),
    (5725.0, 5875.0, "5.8 GHz (video downlink)", False),
]

# Severity ranking used for exit-code and sorting decisions.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ParseError(ValueError):
    """Raised when a log cannot be parsed at all."""


@dataclass
class DetectionEvent:
    """A single normalized C-UAS sensor detection."""

    seq: int
    timestamp: Optional[float] = None  # epoch seconds, UTC
    track_id: Optional[str] = None
    freq_mhz: Optional[float] = None
    rssi_dbm: Optional[float] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    alt_m: Optional[float] = None
    speed_mps: Optional[float] = None
    protocol: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)
        return d


@dataclass
class Finding:
    """An analytical flag raised against one or more events."""

    code: str
    severity: str
    track_id: Optional[str]
    message: str
    seqs: list[int] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    events: list[DetectionEvent]
    findings: list[Finding]
    stats: dict[str, Any]

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "stats": self.stats,
            "max_severity": self.max_severity,
            "findings": [f.to_dict() for f in self.findings],
            "events": [e.to_dict() for e in self.events],
        }


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def _parse_timestamp(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    # Numeric epoch?
    try:
        return float(s)
    except ValueError:
        pass
    # ISO-8601
    iso = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _to_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _valid_lat(v: Optional[float]) -> Optional[float]:
    """Return v if it is a valid WGS84 latitude, else None."""
    return v if (v is not None and -90.0 <= v <= 90.0) else None


def _valid_lon(v: Optional[float]) -> Optional[float]:
    """Return v if it is a valid WGS84 longitude, else None."""
    return v if (v is not None and -180.0 <= v <= 180.0) else None


def _valid_freq(v: Optional[float]) -> Optional[float]:
    """Return v if it is a plausible RF frequency (> 0 MHz), else None."""
    return v if (v is not None and v > 0.0) else None


def _record_to_event(seq: int, rec: dict[str, Any]) -> DetectionEvent:
    tid = rec.get("track_id", rec.get("id"))
    return DetectionEvent(
        seq=seq,
        timestamp=_parse_timestamp(rec.get("timestamp", rec.get("ts"))),
        track_id=None if tid is None or tid == "" else str(tid),
        freq_mhz=_valid_freq(_to_float(rec.get("freq_mhz", rec.get("freq")))),
        rssi_dbm=_to_float(rec.get("rssi_dbm", rec.get("rssi"))),
        lat=_valid_lat(_to_float(rec.get("lat"))),
        lon=_valid_lon(_to_float(rec.get("lon"))),
        alt_m=_to_float(rec.get("alt_m", rec.get("alt"))),
        speed_mps=_to_float(rec.get("speed_mps", rec.get("speed"))),
        protocol=(str(rec["protocol"]) if rec.get("protocol") not in (None, "") else None),
        raw=rec,
    )


def parse_log(text: str) -> list[DetectionEvent]:
    """Parse a C-UAS log from text. Auto-detects JSONL/JSON-array vs CSV.

    Raises ParseError if no records can be extracted.
    """
    stripped = text.strip()
    if not stripped:
        raise ParseError("empty log")

    records: list[dict[str, Any]] = []

    if stripped[0] in "[{":
        # JSON array or JSONL
        try:
            obj = json.loads(stripped)
            if isinstance(obj, list):
                records = [r for r in obj if isinstance(r, dict)]
            elif isinstance(obj, dict):
                records = [obj]
        except json.JSONDecodeError:
            # Try JSONL (one object per line)
            for line in stripped.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(o, dict):
                    records.append(o)
    else:
        # CSV
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            records.append({k: v for k, v in row.items() if k is not None})

    if not records:
        raise ParseError("no parseable records found in log")

    return [_record_to_event(i, r) for i, r in enumerate(records)]


# --------------------------------------------------------------------------
# Analysis helpers
# --------------------------------------------------------------------------


def classify_rf_band(freq_mhz: Optional[float]) -> Optional[tuple[str, bool]]:
    """Return (label, authorized) for a frequency, or None if unmatched."""
    if freq_mhz is None:
        return None
    for lo, hi, label, authorized in RF_BANDS:
        if lo <= freq_mhz <= hi:
            return label, authorized
    return None


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    # Clamp to [0, 1] to absorb floating-point rounding that can push a
    # just outside [0, 1], which would cause math.asin / math.sqrt to raise.
    a = max(0.0, min(1.0, a))
    return 2 * r * math.asin(math.sqrt(a))


# --------------------------------------------------------------------------
# Analysis engine
# --------------------------------------------------------------------------

# Plausibility thresholds for small/consumer UAS kinematics.
MAX_PLAUSIBLE_SPEED_MPS = 120.0      # ~430 km/h, generous upper bound
MAX_PLAUSIBLE_CLIMB_MPS = 30.0       # vertical rate
TELEPORT_SPEED_MPS = 200.0           # inferred speed between fixes = impossible
LOITER_RADIUS_M = 75.0               # within this radius counts as loitering
LOITER_MIN_SECONDS = 120.0           # sustained loiter duration to flag
SWARM_RADIUS_M = 150.0               # tracks within this distance, same window
SWARM_MIN_TRACKS = 3
SWARM_WINDOW_S = 10.0
STRONG_RSSI_DBM = -50.0              # very close / strong emitter


def analyze(events: list[DetectionEvent]) -> AnalysisResult:
    """Run all triage rules over normalized events."""
    findings: list[Finding] = []

    # ---- Rule 1: RF band classification ----
    for ev in events:
        cls = classify_rf_band(ev.freq_mhz)
        if cls is None:
            continue
        label, authorized = cls
        if not authorized:
            sev = "high" if (ev.rssi_dbm is not None and ev.rssi_dbm >= STRONG_RSSI_DBM) else "medium"
            msg = f"Detection on unauthorized/monitored band {label}"
            if "GNSS" in label:
                sev = "high"
                msg = f"Possible GNSS interference/spoofing on {label}"
            findings.append(
                Finding(
                    code="RF_UNAUTHORIZED_BAND",
                    severity=sev,
                    track_id=ev.track_id,
                    message=msg,
                    seqs=[ev.seq],
                    detail={"freq_mhz": ev.freq_mhz, "rssi_dbm": ev.rssi_dbm, "band": label},
                )
            )

    # Group events by track for kinematic rules (preserve order).
    by_track: dict[str, list[DetectionEvent]] = {}
    for ev in events:
        if ev.track_id is None:
            continue
        by_track.setdefault(ev.track_id, []).append(ev)

    for tid, evs in by_track.items():
        evs_sorted = sorted(
            evs, key=lambda e: (e.timestamp if e.timestamp is not None else e.seq)
        )

        # ---- Rule 2: implausible reported speed ----
        for ev in evs_sorted:
            if ev.speed_mps is not None and ev.speed_mps > MAX_PLAUSIBLE_SPEED_MPS:
                findings.append(
                    Finding(
                        code="KINEMATIC_SPEED",
                        severity="medium",
                        track_id=tid,
                        message=f"Reported speed {ev.speed_mps:.0f} m/s exceeds plausible UAS envelope",
                        seqs=[ev.seq],
                        detail={"speed_mps": ev.speed_mps},
                    )
                )

        # ---- Rule 3: teleport / track-stitch anomaly + climb rate ----
        for prev, cur in zip(evs_sorted, evs_sorted[1:]):
            if None in (prev.lat, prev.lon, cur.lat, cur.lon):
                continue
            dist = _haversine_m(prev.lat, prev.lon, cur.lat, cur.lon)
            dt = None
            if prev.timestamp is not None and cur.timestamp is not None:
                dt = cur.timestamp - prev.timestamp
            if dt is not None and dt > 0:
                inferred = dist / dt
                if inferred > TELEPORT_SPEED_MPS:
                    findings.append(
                        Finding(
                            code="TRACK_TELEPORT",
                            severity="high",
                            track_id=tid,
                            message=(
                                f"Track jumped {dist:.0f} m in {dt:.1f}s "
                                f"(={inferred:.0f} m/s) - possible spoof or track-stitch error"
                            ),
                            seqs=[prev.seq, cur.seq],
                            detail={"distance_m": round(dist, 1), "dt_s": round(dt, 2),
                                    "inferred_speed_mps": round(inferred, 1)},
                        )
                    )
                # climb rate
                if prev.alt_m is not None and cur.alt_m is not None:
                    climb = abs(cur.alt_m - prev.alt_m) / dt
                    if climb > MAX_PLAUSIBLE_CLIMB_MPS:
                        findings.append(
                            Finding(
                                code="KINEMATIC_CLIMB",
                                severity="medium",
                                track_id=tid,
                                message=f"Vertical rate {climb:.0f} m/s exceeds plausible envelope",
                                seqs=[prev.seq, cur.seq],
                                detail={"climb_mps": round(climb, 1)},
                            )
                        )

        # ---- Rule 4: sustained loiter ----
        anchor = next((e for e in evs_sorted if e.lat is not None and e.lon is not None), None)
        if anchor is not None and anchor.timestamp is not None:
            cluster_seqs = [anchor.seq]
            last_t = anchor.timestamp
            for ev in evs_sorted:
                if ev is anchor or ev.lat is None or ev.lon is None or ev.timestamp is None:
                    continue
                if _haversine_m(anchor.lat, anchor.lon, ev.lat, ev.lon) <= LOITER_RADIUS_M:
                    cluster_seqs.append(ev.seq)
                    last_t = max(last_t, ev.timestamp)
            duration = last_t - anchor.timestamp
            if duration >= LOITER_MIN_SECONDS and len(cluster_seqs) >= 3:
                findings.append(
                    Finding(
                        code="LOITER",
                        severity="medium",
                        track_id=tid,
                        message=f"Sustained loiter ~{duration:.0f}s within {LOITER_RADIUS_M:.0f} m",
                        seqs=sorted(set(cluster_seqs)),
                        detail={"duration_s": round(duration, 1), "radius_m": LOITER_RADIUS_M},
                    )
                )

    # ---- Rule 5: swarm clustering (multiple distinct tracks, tight + concurrent) ----
    geo_events = [e for e in events if e.lat is not None and e.lon is not None
                  and e.timestamp is not None and e.track_id is not None]
    geo_events.sort(key=lambda e: e.timestamp)
    flagged_swarm = False
    for i, base in enumerate(geo_events):
        if flagged_swarm:
            break
        nearby_tracks = {base.track_id}
        seqs = [base.seq]
        for other in geo_events:
            if other is base:
                continue
            if abs(other.timestamp - base.timestamp) > SWARM_WINDOW_S:
                continue
            if _haversine_m(base.lat, base.lon, other.lat, other.lon) <= SWARM_RADIUS_M:
                nearby_tracks.add(other.track_id)
                seqs.append(other.seq)
        if len(nearby_tracks) >= SWARM_MIN_TRACKS:
            findings.append(
                Finding(
                    code="SWARM",
                    severity="critical",
                    track_id=None,
                    message=(
                        f"{len(nearby_tracks)} distinct tracks within {SWARM_RADIUS_M:.0f} m "
                        f"and {SWARM_WINDOW_S:.0f}s - possible coordinated swarm"
                    ),
                    seqs=sorted(set(seqs)),
                    detail={"track_count": len(nearby_tracks),
                            "tracks": sorted(nearby_tracks)},
                )
            )
            flagged_swarm = True

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.seqs[0] if f.seqs else 0))

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    stats = {
        "event_count": len(events),
        "track_count": len(by_track),
        "finding_count": len(findings),
        "severity_counts": sev_counts,
    }

    return AnalysisResult(events=events, findings=findings, stats=stats)
