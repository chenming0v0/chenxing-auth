#!/usr/bin/env python3
"""Local preview server for the Chenxing design canvas export."""

from __future__ import annotations

import argparse
import html
import json
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit


ROOT_DIR = Path(__file__).resolve().parent
DESIGN_FILENAME = "design-auth-chengming.design"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 17880


def _display_value(value: Any) -> str:
    """Return a readable value for the index without exposing raw HTML."""
    if value is None:
        return "未提供"
    if isinstance(value, str):
        return value
    return str(value)


def _page_href(html_src: Any) -> Optional[str]:
    """Create a URL only for a relative HTML file inside the pages directory."""
    if not isinstance(html_src, str) or not html_src.startswith("pages/"):
        return None

    relative = PurePosixPath(html_src)
    if (
        relative.is_absolute()
        or relative.suffix.lower() != ".html"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        return None

    candidate = (ROOT_DIR / Path(relative.as_posix())).resolve()
    try:
        candidate.relative_to(ROOT_DIR)
    except ValueError:
        return None

    return "/" + quote(relative.as_posix(), safe="/")


def _load_pages() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Read page cards from the design file, keeping index failures non-fatal."""
    try:
        with (ROOT_DIR / DESIGN_FILENAME).open("r", encoding="utf-8") as design_file:
            document = json.load(design_file)
        data = document.get("data")
        if not isinstance(data, list):
            raise ValueError("data 不是数组")
        pages = [
            item
            for item in data
            if isinstance(item, dict) and item.get("type") == "page"
        ]
        return pages, None
    except (OSError, json.JSONDecodeError, AttributeError, TypeError, ValueError) as error:
        return [], f"无法读取原始设计蓝图：{error}"


def _render_index() -> bytes:
    pages, error = _load_pages()
    content: List[str] = [
        "<!doctype html>",
        '<html lang="zh-CN">',
        "<head>",
        '<meta charset="utf-8">',
        "<title>辰星认证中枢 · 设计预览</title>",
        "</head>",
        "<body>",
        "<h1>辰星认证中枢 · 设计预览</h1>",
        f'<p><a href="/{DESIGN_FILENAME}">原始设计蓝图</a></p>',
        "<h2>静态资源</h2>",
        '<ul><li><a href="/colors_and_type.css">CSS</a></li>'
        '<li><a href="/partials/">partials</a></li>'
        '<li><a href="/assets/">assets</a></li></ul>',
        "<h2>页面</h2>",
    ]

    if error is not None:
        content.append(f'<p role="alert">{html.escape(error)}</p>')
    elif not pages:
        content.append("<p>未找到 type=page 的页面。</p>")
    else:
        content.append("<ul>")
        for page in pages:
            title = html.escape(_display_value(page.get("title")))
            page_id = html.escape(_display_value(page.get("id")))
            html_src_value = _display_value(
                page.get("devMetadata", {}).get("htmlSrc")
                if isinstance(page.get("devMetadata"), dict)
                else None
            )
            html_src = html.escape(html_src_value)
            href = _page_href(
                page.get("devMetadata", {}).get("htmlSrc")
                if isinstance(page.get("devMetadata"), dict)
                else None
            )
            page_label = f"{title} · {page_id} · {html_src}"
            if href is None:
                content.append(f"<li>{page_label}（路径不可预览）</li>")
            else:
                content.append(f'<li><a href="{href}">{page_label}</a></li>')
        content.append("</ul>")

    content.extend(["</body>", "</html>"])
    return "\n".join(content).encode("utf-8")


def _is_within_root(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT_DIR)
    except ValueError:
        return False
    return True


class PreviewRequestHandler(SimpleHTTPRequestHandler):
    """Serve the index and static files from the fixed design directory."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(ROOT_DIR), **kwargs)

    def do_GET(self) -> None:
        if urlsplit(self.path).path == "/":
            payload = _render_index()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        super().do_GET()

    def send_head(self) -> Optional[BinaryIO]:
        translated_path = Path(super().translate_path(self.path))
        if not _is_within_root(translated_path):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        return super().send_head()

    def log_message(self, format: str, *args: Any) -> None:
        status = args[1] if len(args) > 1 else "-"
        print(f"{self.command} {urlsplit(self.path).path} -> {status}")


def _port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1 到 65535 之间")
    return port


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the Chenxing design preview.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="绑定地址（默认 127.0.0.1）")
    parser.add_argument(
        "--port",
        default=DEFAULT_PORT,
        type=_port,
        help="绑定端口（默认 17880）",
    )
    args = parser.parse_args()

    with ThreadingHTTPServer((args.host, args.port), PreviewRequestHandler) as server:
        print(
            f"Preview server running at http://{args.host}:{server.server_port}/",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Preview server stopped.", flush=True)


if __name__ == "__main__":
    main()
