"""Security-event API exposure tests."""

from app.main import create_app


def test_security_events_have_no_mutation_routes() -> None:
    application = create_app()
    mutation_methods = {"PATCH", "PUT", "DELETE"}

    mutation_routes = [
        (
            path,
            sorted(method.upper() for method in operations if method.upper() in mutation_methods),
        )
        for path, operations in application.openapi()["paths"].items()
        if "event" in path.casefold()
        and any(method.upper() in mutation_methods for method in operations)
    ]

    assert mutation_routes == []
