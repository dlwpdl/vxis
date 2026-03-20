"""Pure-SVG chart generation for VXIS security reports.

All functions return self-contained SVG strings with no external dependencies.
Charts are designed to be embedded inline inside HTML templates.
"""

from __future__ import annotations

import math

# Canonical severity colour palette
_SEVERITY_COLOURS: dict[str, str] = {
    "critical": "#7B2C34",
    "high": "#C0392B",
    "medium": "#E67E22",
    "low": "#2ECC71",
    "informational": "#3498DB",
}

# Display order for charts — most severe first
_SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "informational"]


def _arc_path(
    cx: float,
    cy: float,
    r: float,
    start_angle: float,
    end_angle: float,
) -> str:
    """Return an SVG arc path data string for a donut segment.

    Angles are in degrees, measured clockwise from the 12-o'clock position.
    Returns a closed path suitable for use as a donut slice.
    """
    # Convert degrees to radians, offset by -90° so 0° is at the top
    start_rad = math.radians(start_angle - 90)
    end_rad = math.radians(end_angle - 90)

    x1 = cx + r * math.cos(start_rad)
    y1 = cy + r * math.sin(start_rad)
    x2 = cx + r * math.cos(end_rad)
    y2 = cy + r * math.sin(end_rad)

    large_arc = 1 if (end_angle - start_angle) > 180 else 0

    return f"M {cx:.2f} {cy:.2f} L {x1:.2f} {y1:.2f} A {r:.2f} {r:.2f} 0 {large_arc} 1 {x2:.2f} {y2:.2f} Z"


def severity_donut_svg(counts: dict[str, int], size: int = 200) -> str:
    """Generate a donut chart SVG showing findings per severity.

    Parameters
    ----------
    counts:
        Mapping of severity name (lowercase) to integer count.
        Missing keys are treated as zero.
    size:
        Overall width and height of the SVG in pixels (chart is square).

    Returns
    -------
    str
        Self-contained SVG markup string.
    """
    total = sum(counts.get(s, 0) for s in _SEVERITY_ORDER)
    cx = cy = size / 2
    outer_r = size * 0.42
    inner_r = size * 0.26  # hole radius

    # Build slice paths
    slices: list[str] = []
    current_angle = 0.0

    if total == 0:
        # Empty state: grey circle
        slices.append(
            f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{outer_r:.2f}" fill="#CCCCCC" />'
        )
        slices.append(
            f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{inner_r:.2f}" fill="white" />'
        )
    else:
        for severity in _SEVERITY_ORDER:
            count = counts.get(severity, 0)
            if count == 0:
                continue
            angle_span = (count / total) * 360.0
            end_angle = current_angle + angle_span
            colour = _SEVERITY_COLOURS[severity]

            # Full circle edge case: use two 180° arcs
            if angle_span >= 359.99:
                slices.append(
                    f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{outer_r:.2f}" fill="{colour}" />'
                )
            else:
                path_d = _arc_path(cx, cy, outer_r, current_angle, end_angle)
                slices.append(f'<path d="{path_d}" fill="{colour}" />')

            current_angle = end_angle

        # Punch out the donut hole
        slices.append(
            f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{inner_r:.2f}" fill="white" />'
        )

    # Centre label: total count
    label_font = max(12, size // 8)
    sub_font = max(9, size // 14)
    centre_label = (
        f'<text x="{cx:.2f}" y="{cy:.2f}" text-anchor="middle" dominant-baseline="middle" '
        f'font-family="Arial, sans-serif" font-size="{label_font}" font-weight="bold" fill="#333">'
        f'{total}</text>'
        f'<text x="{cx:.2f}" y="{cy + label_font:.2f}" text-anchor="middle" '
        f'font-family="Arial, sans-serif" font-size="{sub_font}" fill="#666">findings</text>'
    )

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 {size} {size}">',
    ]
    svg_parts.extend(slices)
    svg_parts.append(centre_label)
    svg_parts.append("</svg>")

    return "\n".join(svg_parts)


def severity_bar_svg(
    counts: dict[str, int],
    width: int = 400,
    bar_height: int = 30,
) -> str:
    """Generate a horizontal bar chart SVG showing counts per severity.

    Each severity level gets its own labelled bar. The bar length is
    proportional to that severity's share of the maximum count.

    Parameters
    ----------
    counts:
        Mapping of severity name (lowercase) to integer count.
    width:
        Total SVG width in pixels.
    bar_height:
        Height of each individual bar in pixels.

    Returns
    -------
    str
        Self-contained SVG markup string.
    """
    label_width = 120  # pixels reserved for severity label on the left
    count_width = 40   # pixels reserved for count label on the right
    bar_area = width - label_width - count_width
    gap = 8            # vertical gap between bars
    padding_top = 10
    font_size = 13

    max_count = max((counts.get(s, 0) for s in _SEVERITY_ORDER), default=1)
    if max_count == 0:
        max_count = 1  # avoid division by zero

    rows: list[str] = []
    for i, severity in enumerate(_SEVERITY_ORDER):
        count = counts.get(severity, 0)
        y = padding_top + i * (bar_height + gap)
        colour = _SEVERITY_COLOURS[severity]
        bar_w = (count / max_count) * bar_area if count > 0 else 0

        # Background track
        rows.append(
            f'<rect x="{label_width}" y="{y}" width="{bar_area}" height="{bar_height}" '
            f'rx="4" fill="#F0F0F0" />'
        )
        # Filled bar
        if bar_w > 0:
            rows.append(
                f'<rect x="{label_width}" y="{y}" width="{bar_w:.2f}" height="{bar_height}" '
                f'rx="4" fill="{colour}" />'
            )
        # Severity label (left)
        label_y = y + bar_height / 2
        rows.append(
            f'<text x="{label_width - 8}" y="{label_y:.2f}" text-anchor="end" '
            f'dominant-baseline="middle" font-family="Arial, sans-serif" '
            f'font-size="{font_size}" fill="#333">{severity.capitalize()}</text>'
        )
        # Count label (right)
        count_x = label_width + bar_area + 8
        rows.append(
            f'<text x="{count_x}" y="{label_y:.2f}" text-anchor="start" '
            f'dominant-baseline="middle" font-family="Arial, sans-serif" '
            f'font-size="{font_size}" font-weight="bold" fill="#333">{count}</text>'
        )

    total_height = padding_top + len(_SEVERITY_ORDER) * (bar_height + gap)

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{total_height}" '
        f'viewBox="0 0 {width} {total_height}">',
    ]
    svg_parts.extend(rows)
    svg_parts.append("</svg>")

    return "\n".join(svg_parts)
