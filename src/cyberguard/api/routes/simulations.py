"""In-memory Simulation Lab controls; background work belongs to lifespan."""

from fastapi import APIRouter, Query, Request

from cyberguard.simulation.engine_schemas import SimulationConfig

router = APIRouter(prefix="/api/v1/simulations", tags=["simulations"])


def controller(request):
    return request.app.state.simulations


@router.post("", status_code=201)
def create(payload: SimulationConfig, request: Request):
    return controller(request).create(payload).snapshot()


@router.get("")
def list_simulations(request: Request):
    return {"simulations": controller(request).list()}


@router.get("/{simulation_id}")
def inspect(simulation_id: str, request: Request):
    return controller(request).get(simulation_id).snapshot()


@router.post("/{simulation_id}/start")
def start(simulation_id: str, request: Request):
    return controller(request).start(simulation_id).snapshot()


@router.post("/{simulation_id}/pause")
def pause(simulation_id: str, request: Request):
    session = controller(request).get(simulation_id)
    session.control("pause")
    return session.snapshot()


@router.post("/{simulation_id}/resume")
def resume(simulation_id: str, request: Request):
    session = controller(request).get(simulation_id)
    session.control("resume")
    return session.snapshot()


@router.post("/{simulation_id}/stop")
def stop(simulation_id: str, request: Request):
    session = controller(request).get(simulation_id)
    session.control("stop")
    return session.snapshot()


@router.get("/{simulation_id}/metrics")
def metrics(simulation_id: str, request: Request):
    return controller(request).get(simulation_id).metrics()


@router.get("/{simulation_id}/events")
def events(
    simulation_id: str,
    request: Request,
    after: int = Query(-1, ge=-1),
    limit: int = Query(100, ge=1, le=1000),
):
    return controller(request).get(simulation_id).recent(after, limit)


@router.delete("/{simulation_id}")
def delete(simulation_id: str, request: Request):
    controller(request).delete(simulation_id)
    return {"id": simulation_id, "deleted": True}
