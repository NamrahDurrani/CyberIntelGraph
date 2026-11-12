import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from documents.chunking import (Block, chunk_blocks, embedding_text,  # noqa: E402
                                split_long_text, split_table)

LOREM = "The actor used a loader to stage payloads on the host. "


def para(n_sentences):
    return (LOREM * n_sentences).strip()


class ChunkerTests(unittest.TestCase):
    def test_heading_path_and_no_crossing(self):
        blocks = [Block("heading", "Title", 0),
                  Block("heading", "Overview", 1), Block("text", para(3)),
                  Block("heading", "Details", 1),
                  Block("heading", "Indicators", 2), Block("text", para(3))]
        chunks, _ = chunk_blocks(blocks)
        self.assertEqual([c.heading_path for c in chunks],
                         [["Title", "Overview"], ["Title", "Details", "Indicators"]])

    def test_sibling_heading_replaces_previous(self):
        blocks = [Block("heading", "A", 1), Block("text", para(3)),
                  Block("heading", "B", 1), Block("text", para(3))]
        chunks, _ = chunk_blocks(blocks)
        self.assertEqual([c.heading_path for c in chunks], [["A"], ["B"]])

    def test_max_words_respected_and_split_on_sentences(self):
        chunks, st = chunk_blocks([Block("text", para(60))], max_words=50)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(c.words <= 50 for c in chunks))
        self.assertEqual(st["split_long_blocks"], 1)
        self.assertTrue(all(c.text.endswith(".") for c in chunks))

    def test_small_blocks_are_merged_up_to_limit(self):
        blocks = [Block("text", para(2)) for _ in range(4)]    # 4 x 20 words
        chunks, _ = chunk_blocks(blocks, max_words=50)
        self.assertEqual(len(chunks), 2)

    def test_tiny_chunks_dropped_unless_they_carry_ids(self):
        blocks = [Block("text", "Share"), Block("heading", "H", 1),
                  Block("text", "See CVE-2024-3400."), Block("heading", "H2", 1),
                  Block("text", "Skip it")]
        chunks, st = chunk_blocks(blocks, min_words=8)
        self.assertEqual([c.text for c in chunks], ["See CVE-2024-3400."])
        self.assertEqual(st["dropped_tiny"], 2)

    def test_table_is_own_chunk_and_header_repeats_when_split(self):
        rows = "\n".join(f"| T{1000 + i} | technique number {i} used for access |" for i in range(40))
        table = "| ID | Use |\n|---|---|\n" + rows
        pieces = split_table(table, 60)
        self.assertGreater(len(pieces), 1)
        self.assertTrue(all(p.startswith("| ID | Use |\n|---|---|") for p in pieces))
        chunks, st = chunk_blocks([Block("text", para(3)), Block("table", table)], max_words=60)
        self.assertEqual(st["tables"], 1)
        self.assertEqual(chunks[0].kinds, ["text"])
        self.assertTrue(all(c.kinds == ["table"] for c in chunks[1:]))

    def test_pathological_sentence_is_split_by_words(self):
        pieces = split_long_text("word " * 500, 100)
        self.assertEqual([len(p.split()) for p in pieces], [100] * 5)

    def test_pages_tracked(self):
        chunks, _ = chunk_blocks([Block("text", para(3), page=2), Block("text", para(3), page=3)])
        self.assertEqual((chunks[0].page_start, chunks[0].page_end), (2, 3))
        chunks, _ = chunk_blocks([Block("text", para(3))])
        self.assertIsNone(chunks[0].page_start)

    def test_indexes_sequential_and_deterministic(self):
        blocks = [Block("heading", "A", 1), Block("text", para(40)), Block("heading", "B", 1),
                  Block("text", para(40))]
        a, _ = chunk_blocks(blocks, max_words=50)
        b, _ = chunk_blocks(blocks, max_words=50)
        self.assertEqual([c.index for c in a], list(range(1, len(a) + 1)))
        self.assertEqual(a, b)

    def test_embedding_text_has_heading_context(self):
        self.assertEqual(embedding_text(["A", "B"], "body"), "A > B\nbody")
        self.assertEqual(embedding_text([], "body"), "body")


if __name__ == "__main__":
    unittest.main()
