# Demo 01 - Basic C-UAS Log Triage

This scenario exercises UASLOG against a small JSONL counter-UAS detection log
captured by a perimeter RF/track sensor. It is synthetic data crafted to trip
each analytical rule so you can see the triage output.

## Input

`detections.jsonl` - one detection record per line with fields:
`timestamp, track_id, freq_mhz, rssi_dbm, lat, lon, alt_m, speed_mps, protocol`.

The log contains three tracks:

- **drone-A** - emits on 2.4 GHz control band (monitored/unauthorized) and
  loiters in a tight radius for several minutes near the perimeter.
- **drone-B** - shows a physically impossible position jump between two fixes
  (a *teleport* / track-stitch anomaly), plus a 5.8 GHz video downlink hit.
- **drone-C** - appears alongside A and B inside a tight space/time window,
  tripping the **swarm** rule (3 distinct tracks, <150 m, <10 s).

There is also a GNSS-band (L1) detection indicating possible spoofing.

## Run it

Table view (human triage):

```
python -m uaslog analyze demos/01-basic/detections.jsonl
```

Machine-readable JSON (for piping into a SIEM / dashboard):

```
python -m uaslog analyze demos/01-basic/detections.jsonl --format json
```

Only show high-and-above and treat those as the failure condition:

```
python -m uaslog analyze demos/01-basic/detections.jsonl --min-severity high
```

## Expected

- A `SWARM` finding at **critical** severity.
- `TRACK_TELEPORT` and a GNSS-spoof `RF_UNAUTHORIZED_BAND` at **high**.
- `RF_UNAUTHORIZED_BAND` (2.4/5.8 GHz) and `LOITER` at **medium**.
- Process exits non-zero (findings present), suitable for use in a monitoring
  pipeline that should alert when anything actionable is detected.

This tool is for **analysis and monitoring only**. It does not command,
jam, or target anything.
