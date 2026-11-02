from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import Field, ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.common import DEMO_IDENTITIES, Contract, DomainError, Identity, Store, authenticate, clock
from app.service import Service


class Command(Contract):
    action: str = Field(pattern=r"^[a-z][a-z-]{0,63}$")
    data: dict[str, Any]
    key: str = Field(pattern=r"^[a-z0-9-]{8,96}$")


class BodyLimit:
    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 262144:
                await JSONResponse({"error": "Body exceeds 256 KiB"}, status_code=413)(
                    scope, receive, send
                )
                return
            if not message.get("more_body", False):
                break
        sent = False

        async def replay() -> Any:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def create_app(
    path: Path, identities: dict[str, Identity] | None = None, *, demo: bool = False
) -> FastAPI:
    if not demo and not identities:
        raise ValueError("Configured mode requires explicit identities")
    if demo and identities is not None:
        raise ValueError("Demo and configured identities cannot be combined")
    accounts = DEMO_IDENTITIES if demo else identities
    assert accounts is not None
    metadata = json.loads(Path("project.json").read_text())
    app = FastAPI(title=metadata["title"], docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"]
    )
    app.add_middleware(BodyLimit)
    service = Service(Store(path))
    app.state.service = service

    def identity(authorization: str = Header(default="")) -> Identity:
        return authenticate(authorization, accounts)

    @app.exception_handler(DomainError)
    async def domain_error(_request: Request, error: DomainError) -> JSONResponse:
        return JSONResponse({"error": str(error)}, status_code=error.status)

    async def invalid(_request: Request, _error: Exception) -> JSONResponse:
        return JSONResponse({"error": "Input violates the operation schema"}, status_code=422)

    app.add_exception_handler(ValidationError, invalid)
    app.add_exception_handler(RequestValidationError, invalid)

    @app.middleware("http")
    async def secure(request: Request, call_next: Any) -> Any:
        origin = request.headers.get("origin")
        if origin and origin != f"http://{request.headers.get('host')}":
            return JSONResponse({"error": "Origin rejected"}, status_code=403)
        if (
            request.method == "POST"
            and request.headers.get("content-type", "").split(";")[0] != "application/json"
        ):
            return JSONResponse({"error": "JSON content type required"}, status_code=415)
        response = await call_next(request)
        response.headers.update(
            {
                "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
            }
        )
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ready", "mode": "synthetic-demo" if demo else "configured"}

    @app.get("/api/scenario")
    def scenario() -> Any:
        if not demo:
            raise DomainError("Offline scenario is disabled in configured mode", 403)
        return {"project": metadata, **json.loads(Path("samples/scenario.json").read_text())}

    @app.post("/api/actions")
    def actions(command: Command, actor: Identity = Depends(identity)) -> Any:
        return service.execute(actor, command.action, command.data, command.key, clock())

    @app.get("/api/state")
    def state(actor: Identity = Depends(identity)) -> Any:
        return service.view(actor, clock())

    @app.get("/api/evidence")
    def evidence(actor: Identity = Depends(identity)) -> Any:
        return service.evidence(actor)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse("web/index.html")

    @app.get("/app.js")
    def script() -> FileResponse:
        return FileResponse("web/app.js", media_type="text/javascript")

    @app.get("/style.css")
    def style() -> FileResponse:
        return FileResponse("web/style.css", media_type="text/css")

    return app
