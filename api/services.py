from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Iterable, List

from fastapi import HTTPException, WebSocket
from fastapi.responses import FileResponse, HTMLResponse

from api.dependencies import rate_limit_stats, reset_rate_limits
from api.logging_utils import logfmt
from api.runtime import runtime_state
from config import config

logger = logging.getLogger("honeypot_api")

_decay_task: Optional[asyncio.Task] = None


# ------------------------------------------------------------------
# Queue batch handler (the core ingestion path)
# ------------------------------------------------------------------

async def process_event_batch(batch: List[Dict[str, Any]]) -> None:
    """Process a batch of telemetry events from the event queue.

    This is the handler registered with ``event_queue.start()``.
    For each event it runs publish_pheromone + correlation, then
    broadcasts a single graph update for the entire batch.
    """
    from correlation import evaluate_correlation
    from swarm import publish_pheromone

    all_incidents: List[Dict[str, Any]] = []

    for event in batch:
        try:
            publish_pheromone(event)
        except Exception as exc:
            logger.exception(logfmt("batch_event_failed", error=str(exc), entity_id=event.get("entity_id")))
            continue

    # Correlate once per batch, not per event
    try:
        incidents = evaluate_correlation()
        all_incidents.extend(incidents)
        runtime_state.metrics.incidents_created += len(incidents)
    except Exception as exc:
        logger.exception(logfmt("batch_correlation_failed", error=str(exc)))

    # Single graph broadcast per batch
    await broadcast_graph_update()
    if all_incidents:
        await broadcast_incidents(all_incidents)

    logger.info(logfmt("batch_processed", batch_size=len(batch), incidents=len(all_incidents)))


# ------------------------------------------------------------------
# Lifecycle: startup / shutdown
# ------------------------------------------------------------------

async def startup() -> None:
    """Start the event queue processor and periodic decay task."""
    from event_queue import event_queue

    await event_queue.start(process_event_batch)
    _start_decay_loop()
    await start_swarm_service()
    logger.info(logfmt("lifecycle_startup", queue_max=config.queue.max_size))


async def shutdown() -> None:
    """Gracefully stop the event queue and decay loop."""
    global _decay_task
    from event_queue import event_queue

    await event_queue.stop()
    if _decay_task and not _decay_task.done():
        _decay_task.cancel()
        try:
            await _decay_task
        except asyncio.CancelledError:
            pass
    _decay_task = None
    logger.info(logfmt("lifecycle_shutdown"))


def _start_decay_loop() -> None:
    global _decay_task
    _decay_task = asyncio.create_task(_decay_loop())


async def _decay_loop() -> None:
    """Periodically run graph decay to prevent unbounded growth."""
    from swarm_graph import pheromone_graph

    interval = pheromone_graph.decay_interval
    logger.info(logfmt("decay_loop_start", interval_seconds=interval))
    while True:
        try:
            await asyncio.sleep(interval)
            pruned = pheromone_graph.decay_all()
            if pruned > 0:
                await broadcast_graph_update()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.exception(logfmt("decay_loop_error", error=str(exc)))
            await asyncio.sleep(5.0)


def build_health_payload() -> Dict[str, Any]:
    from event_queue import event_queue
    from swarm_graph import pheromone_graph

    graph_stats = pheromone_graph.get_stats()
    queue_stats = event_queue.stats()

    return {
        "status": "healthy",
        "service": "SwarmSentinel",
        "version": config.version,
        "environment": config.environment,
        "graph": {
            "nodes": graph_stats["node_count"],
            "edges": graph_stats["edge_count"],
            "total_pheromone": round(graph_stats["total_pheromone"], 1),
            "backend": config.graph.backend,
        },
        "queue": {
            "depth": queue_stats["current_depth"],
            "throughput_eps": queue_stats["throughput_eps"],
            "backpressure": queue_stats.get("backpressure_active", False),
        },
        "simulation_running": runtime_state.simulation_running,
        "uptime_seconds": runtime_state.uptime_seconds(),
        "api": {
            "rate_limits": rate_limit_stats(),
            "metrics": runtime_state.metrics.snapshot(),
        },
    }


def build_metrics_payload() -> Dict[str, Any]:
    from containment import containment_engine
    from event_queue import event_queue
    from ingestion import ingestion_engine
    from swarm_graph import pheromone_graph
    from storage import storage_stats

    return {
        "system": {
            "version": config.version,
            "environment": config.environment,
            "uptime_seconds": runtime_state.uptime_seconds(),
            "pid": os.getpid(),
        },
        "graph": pheromone_graph.get_stats(),
        "queue": event_queue.stats(),
        "ingestion": ingestion_engine.stats(),
        "containment": containment_engine.stats(),
        "storage": storage_stats(),
        "api": {
            "rate_limits": rate_limit_stats(),
            "metrics": runtime_state.metrics.snapshot(),
        },
        "config": config.to_dict(),
    }


async def broadcast_message(message_type: str, data: Any) -> None:
    await runtime_state.ws_manager.broadcast(
        {
            "type": message_type,
            "data": data,
            "timestamp": time.time(),
        },
        runtime_state.metrics,
    )


async def broadcast_graph_update() -> None:
    from swarm_graph import pheromone_graph

    await broadcast_message("graph_update", pheromone_graph.to_snapshot())


async def broadcast_incidents(incidents: Iterable[Dict[str, Any]]) -> None:
    for incident in incidents:
        await broadcast_message("incident", incident)


async def reset_runtime_state() -> Dict[str, Any]:
    from detectors import reset_detectors
    from event_queue import event_queue
    from storage import clear_all_state
    from swarm_graph import pheromone_graph

    pheromone_graph.reset_state()
    clear_all_state()
    reset_detectors()
    event_queue.reset()
    from api.services import process_event_batch
    await event_queue.start(process_event_batch)
    reset_rate_limits()
    runtime_state.reset()
    await broadcast_graph_update()

    logger.info(logfmt("runtime_reset", status="ok"))
    return {"status": "reset", "graph": pheromone_graph.get_stats()}


async def start_swarm_service() -> Dict[str, Any]:
    from ant_agents import swarm_coordinator
    from swarm_graph import pheromone_graph

    if swarm_coordinator.is_running:
        return {"status": "already_running"}

    swarm_coordinator.on_graph_update = on_swarm_graph_update
    swarm_coordinator.on_ant_activity = on_ant_activity
    await swarm_coordinator.start(pheromone_graph)
    logger.info(logfmt("swarm_start", scouts=swarm_coordinator.num_scouts))
    return {"status": "started", "scouts": swarm_coordinator.num_scouts}


async def stop_swarm_service() -> Dict[str, Any]:
    from ant_agents import swarm_coordinator

    await swarm_coordinator.stop()
    logger.info(logfmt("swarm_stop", status="stopped"))
    return {"status": "stopped"}


async def control_simulation_service(action: str, scenario: str, events_per_second: float) -> Dict[str, Any]:
    if action == "stop":
        runtime_state.simulation_running = False
        if runtime_state.simulation_task and not runtime_state.simulation_task.done():
            runtime_state.simulation_task.cancel()
        logger.info(logfmt("simulation_stop", scenario=scenario))
        return {"status": "stopped"}

    if action in ("start", "scenario"):
        if runtime_state.simulation_running:
            return {"status": "already_running"}

        runtime_state.simulation_running = True
        runtime_state.metrics.simulation_runs += 1
        runtime_state.simulation_task = asyncio.create_task(_run_simulation(scenario, events_per_second))
        logger.info(logfmt("simulation_queued", scenario=scenario, events_per_second=events_per_second))
        return {"status": "started", "scenario": scenario}

    raise HTTPException(status_code=400, detail=f"Unknown action: {action}")


async def _run_simulation(scenario_name: str, events_per_second: float = 2.0) -> None:
    from event_queue import event_queue
    from telemetry_simulator import TelemetrySimulator

    sim = TelemetrySimulator()
    generators = {
        "normal_traffic": sim.generate_normal_traffic,
        "port_scan": sim.generate_port_scan,
        "credential_stuffing": sim.generate_credential_stuffing,
        "lateral_movement": sim.generate_lateral_movement,
        "data_exfiltration": sim.generate_data_exfiltration,
        "phishing_campaign": sim.generate_phishing_campaign,
        "apt_killchain": sim.generate_apt_killchain,
        "coordinated_attack": sim.generate_coordinated_attack,
    }

    generator = generators.get(scenario_name)
    if not generator:
        runtime_state.simulation_running = False
        runtime_state.metrics.simulation_failures += 1
        logger.error(logfmt("simulation_unknown_scenario", scenario=scenario_name))
        return

    events = generator()
    delay = 1.0 / min(events_per_second, 100.0)  # cap at 100 eps
    logger.info(logfmt("simulation_start", scenario=scenario_name, event_count=len(events), events_per_second=events_per_second))
    await broadcast_message("simulation_start", {"scenario": scenario_name, "event_count": len(events)})

    for index, event in enumerate(events, start=1):
        if not runtime_state.simulation_running:
            break
        try:
            event["ts"] = time.time()
            accepted = await event_queue.enqueue(event)
            if not accepted:
                runtime_state.metrics.simulation_failures += 1
                logger.warning(logfmt("simulation_backpressure", scenario=scenario_name, index=index))
                continue
            await broadcast_message(
                "simulation_progress",
                {
                    "scenario": scenario_name,
                    "progress": f"{index}/{len(events)}",
                    "queue_depth": event_queue.metrics.depth,
                },
            )
        except Exception as exc:
            runtime_state.metrics.simulation_failures += 1
            logger.exception(logfmt("simulation_event_failed", scenario=scenario_name, index=index, error=exc))
        await asyncio.sleep(delay)

    runtime_state.simulation_running = False
    logger.info(logfmt("simulation_complete", scenario=scenario_name))
    await broadcast_message("simulation_end", {"scenario": scenario_name})


async def on_swarm_graph_update(snapshot: dict) -> None:
    await broadcast_message("graph_update", snapshot)


async def on_ant_activity(activity: dict) -> None:
    await broadcast_message("ant_activity", activity)


async def websocket_init_payload() -> Dict[str, Any]:
    from ant_agents import swarm_coordinator
    from storage import list_incidents
    from swarm_graph import pheromone_graph

    return {
        "type": "init",
        "data": {
            "graph": pheromone_graph.to_snapshot(),
            "swarm": swarm_coordinator.get_status(),
            "incidents": list_incidents(),
            "simulation_running": runtime_state.simulation_running,
        },
        "timestamp": time.time(),
    }


async def handle_ws_message(msg: dict, websocket: WebSocket) -> None:
    msg_type = msg.get("type", "")
    if msg_type == "auth":
        await websocket.send_text(json.dumps({"type": "auth_ok", "timestamp": time.time()}))
        return
    if msg_type == "request_graph":
        from swarm_graph import pheromone_graph

        await websocket.send_text(
            json.dumps(
                {
                    "type": "graph_update",
                    "data": pheromone_graph.to_snapshot(),
                    "timestamp": time.time(),
                },
                default=str,
            )
        )
        return

    if msg_type == "request_status":
        from ant_agents import swarm_coordinator

        await websocket.send_text(
            json.dumps(
                {
                    "type": "swarm_status",
                    "data": swarm_coordinator.get_status(),
                    "timestamp": time.time(),
                },
                default=str,
            )
        )


def serve_dashboard_response(dashboard_dir: str):
    dashboard_path = os.path.join(dashboard_dir, "index.html")
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path, media_type="text/html")
    return HTMLResponse(content="<h1>Dashboard not found. Create dashboard/index.html</h1>", status_code=404)

