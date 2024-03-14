from typing import List


class MarkdownStringGenerator:
    def __init__(self):
        self.markdown_string = ""

    def _header_generator(self, levels: int, header: str) -> str:
        return f"{'#' * levels} {header}\\n"

    def h1(self, header: str):
        self.markdown_string += self._header_generator(1, header)

    def h2(self, header: str):
        self.markdown_string += self._header_generator(2, header)

    def create_table(self, headers: List[str]):
        self.markdown_string += (
            " | ".join(["", *headers, ""]).strip()
            + "\\n"
            + " | ".join(["", *["---"] * len(headers), ""]).strip()
            + "\\n"
        )

    def add_table_row(self, content: List[str]):
        self.markdown_string += " | ".join(["", *content, ""]).strip() + "\\n"
