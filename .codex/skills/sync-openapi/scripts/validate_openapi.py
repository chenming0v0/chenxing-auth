from pathlib import Path
import sys

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required to validate openapi.yaml", file=sys.stderr)
    raise SystemExit(2)


ROOT = Path(__file__).resolve().parents[4]
SPEC_PATH = ROOT / "openapi.yaml"


def main() -> int:
    with SPEC_PATH.open(encoding="utf-8") as handle:
        spec = yaml.safe_load(handle)

    if not isinstance(spec, dict) or spec.get("openapi") not in {"3.0.3", "3.1.0"}:
        raise ValueError("openapi.yaml must declare OpenAPI 3.0.3 or 3.1.0")
    for key in ("info", "paths", "components"):
        if key not in spec:
            raise ValueError(f"missing top-level field: {key}")

    operation_ids = set()
    for path, path_item in spec["paths"].items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}:
                continue
            operation_id = operation.get("operationId")
            if not operation_id:
                raise ValueError(f"{method.upper()} {path} has no operationId")
            if operation_id in operation_ids:
                raise ValueError(f"duplicate operationId: {operation_id}")
            operation_ids.add(operation_id)
            declared = {
                parameter["name"]
                for parameter in operation.get("parameters", [])
                if parameter.get("in") == "path"
            }
            for segment in path.split("{")[1:]:
                parameter_name = segment.split("}", 1)[0]
                if parameter_name not in declared:
                    raise ValueError(f"{method.upper()} {path} lacks path parameter: {parameter_name}")

    print(f"OpenAPI OK: {len(spec['paths'])} paths, {len(operation_ids)} operations")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
