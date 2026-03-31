def build_line_chart(title: str, labels: list[str], datasets: list[dict]):
    return {"type": "line_chart", "title": title, "spec": {"labels": labels, "datasets": datasets}}


def build_bar_chart(title: str, labels: list[str], datasets: list[dict]):
    return {"type": "bar_chart", "title": title, "spec": {"labels": labels, "datasets": datasets}}


def build_pie_chart(title: str, labels: list[str], values: list[float]):
    return {"type": "pie_chart", "title": title, "spec": {"labels": labels, "values": values}}


def build_table(title: str, rows: list[dict]):
    return {"type": "table", "title": title, "spec": {"rows": rows}}


def build_stat_grid(title: str, stats: list[dict]):
    return {"type": "stat_grid", "title": title, "spec": {"stats": stats}}
