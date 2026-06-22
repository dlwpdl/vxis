from pathlib import Path
import tomllib


def test_wheel_includes_runtime_assets() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text())
    includes = set(pyproject["tool"]["hatch"]["build"]["include"])

    assert "src/vxis/**/*.py" in includes
    assert "src/vxis/**/*.json" in includes
    assert "src/vxis/**/*.html" in includes
    assert "src/vxis/**/*.css" in includes
    assert "src/vxis/**/*.md" in includes
