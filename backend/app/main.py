"""FastAPI application factory, lifespan management, CORS configuration, and CLI entrypoint."""
import sys
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.database import db
from backend.app.api.health import router as health_router
from backend.app.api.auth import router as auth_router
from backend.app.api.posture import router as posture_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Enforce production security check: refuse demo mode in production
    settings.validate_production_safety()
    # Initialize SQLite database schema
    db.init_db()
    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="Security Posture Scorer",
        description="AI security posture scorer auditing codebases and configs with deterministic 0-100 scoring and prioritized fixes.",
        version=settings.version,
        lifespan=lifespan
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.demo_mode else ["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(posture_router)

    return app


app = create_app()


def cli_main():
    """Command line interface preserving backwards-compatible CLI workflows."""
    import argparse
    import json
    from backend.app.services.scanner import scanner
    from backend.app.services.scorer import scorer

    db.init_db()
    parser = argparse.ArgumentParser(description="Security Posture Scorer CLI")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # score
    score_p = subparsers.add_parser("score", help="Score a codebase or config")
    score_p.add_argument("--path", default=".", help="Target path to scan")
    score_p.add_argument("--config", help="Specific config file to scan")
    score_p.add_argument("--output", help="Write report to output path")

    # headers
    hdr_p = subparsers.add_parser("headers", help="Audit HTTP security headers")
    hdr_p.add_argument("--file", help="Sample HTTP response headers file")

    args = parser.parse_args()

    if args.cmd == "score":
        target = args.config if args.config else args.path
        findings = []
        if os.path.isfile(target):
            content = open(target, errors="ignore").read()
            findings = scanner.scan_all(target_name=target, target_type="config", content=content)
        elif os.path.isdir(target):
            tree = {}
            for root, _, files in os.walk(target):
                if any(x in root for x in (".git", "node_modules", ".venv", "__pycache__")):
                    continue
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        tree[p] = open(p, errors="ignore").read()
                    except OSError:
                        pass
            findings = scanner.scan_all(target_name=target, target_type="codebase", file_tree=tree)

        score_val, grade, cat_scores, deductions, fixes, summary = scorer.compute_score(findings)
        print(f"\n============================================================")
        print(f"SECURITY POSTURE SCORE: {score_val}/100 (Grade {grade})")
        print(f"============================================================")
        print(f"Summary: {summary}\n")
        print("Deductions:")
        for d in deductions:
            print(f"  -{d.points:>2}  [{d.category}] {d.reason}")
        print("\nPrioritized Fixes:")
        for fx in fixes[:8]:
            print(f"  {fx.priority}. [{fx.effort.upper()}] {fx.action} (ROI: {fx.roi_score})")

    elif args.cmd == "headers":
        raw = open(args.file).read() if args.file else ""
        findings = scanner.scan_http_headers(raw)
        score_val, grade, _, deductions, fixes, _ = scorer.compute_score(findings)
        print(f"Header Posture Score: {score_val}/100 (Grade {grade})")
        print(json.dumps([f.model_dump() for f in findings], indent=2))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] not in ("run", "serve"):
        cli_main()
    else:
        import uvicorn
        uvicorn.run("backend.app.main:app", host=settings.host, port=settings.port, reload=False)
