import os
import tempfile
import unittest
from pathlib import Path

from sbomaudit import goread, readers


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


GO_MOD = """module example.com/svc

go 1.24

require (
\tgithub.com/stretchr/testify v1.9.0
\tgithub.com/lib/pq v1.10.9
\tgolang.org/x/tools v0.20.0
\tgithub.com/google/go-cmp v0.6.0
\tgithub.com/unused/mod v1.0.0
\tgithub.com/mixed/mod v1.0.0
\tgithub.com/onlytool/gen v1.0.0
\tgithub.com/davecgh/go-spew v1.1.1 // indirect
)

tool github.com/onlytool/gen/cmd/gen
"""


class HeaderTests(unittest.TestCase):
    def test_single_block_alias_dot_blank_and_comments(self):
        src = ('// Package x does things.\n/* block\n import "fake/in/comment" */\npackage x // trailing\n\n'
               'import "fmt"\nimport alias "github.com/a/b"\n'
               'import (\n\t"os"\n\t. "github.com/dot/imp"\n\t_ "github.com/lib/pq" // driver\n'
               '\tnamed "github.com/n/m/sub"\n\t`github.com/raw/str`\n)\n'
               'import ("x/y"; "z/w")\n\nvar s = "import \\"not/this\\""\nimport "after/decl"\n')
        imports, tools = goread.parse_header(src)
        self.assertEqual(imports, ["fmt", "github.com/a/b", "os", "github.com/dot/imp", "github.com/lib/pq",
                                   "github.com/n/m/sub", "github.com/raw/str", "x/y", "z/w"])
        self.assertFalse(tools)

    def test_tools_build_tag(self):
        self.assertTrue(goread.parse_header('//go:build tools\n\npackage tools\nimport _ "a/b"\n')[1])
        self.assertTrue(goread.parse_header('// +build tools\n\npackage tools\n')[1])
        self.assertFalse(goread.parse_header('//go:build !tools\n\npackage x\n')[1])
        self.assertFalse(goread.parse_header('package x\n//go:build tools\n')[1])

    def test_malformed_input(self):
        for text in ["", "package", "import \"a\"", "package x\nimport (\n\"a\"\n", "package x\nimport \"unterminated",
                     "\x00\xff package", "package x\nimport ((((", "/* never closed"]:
            goread.parse_header(text)
        self.assertEqual(goread.parse_header('package x\nimport (\n"a"\n')[0], ["a"])

    def test_tool_directives(self):
        self.assertEqual(goread.parse_go_mod_tools("tool a/b\ntool (\n\tc/d // x\n\te/f\n)\n"), ["a/b", "c/d", "e/f"])


class DevOnlyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.src = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def dev(self):
        return goread.dev_only(self.src, [], readers.parse_go_mod)

    def test_rule(self):
        write(self.src, {
            "go.mod": GO_MOD,
            "main.go": 'package main\nimport (\n\t_ "github.com/lib/pq"\n\t"github.com/mixed/mod/x"\n)\n',
            "main_test.go": 'package main\nimport (\n\t"github.com/stretchr/testify/assert"\n'
                            '\t"github.com/google/go-cmp/cmp"\n\t"github.com/mixed/mod"\n)\n',
            "tools.go": '//go:build tools\n\npackage main\nimport _ "golang.org/x/tools/cmd/stringer"\n',
            "internal/x/x_test.go": 'package x\nimport "github.com/stretchr/testify/require"\n',
            "vendor/github.com/lib/pq/conn.go": 'package pq\nimport "github.com/unused/mod"\n',
            "testdata/fixture.go": 'package fixture\nimport "github.com/unused/mod"\n',
            "_scratch/a.go": 'package a\nimport "github.com/unused/mod"\n'})
        self.assertEqual(self.dev(), {"github.com/stretchr/testify", "github.com/google/go-cmp",
                                      "golang.org/x/tools", "github.com/onlytool/gen"})

    def test_production_import_in_another_go_mod_wins_and_nested_modules_are_separate(self):
        write(self.src, {
            "go.mod": "module example.com/a\n\nrequire github.com/x/y v1.0.0\n",
            "a_test.go": 'package a\nimport "github.com/x/y"\n',
            "sub/go.mod": "module example.com/a/sub\n\nrequire github.com/x/y v1.0.0\n",
            "sub/sub.go": 'package sub\nimport "github.com/x/y"\n'})
        self.assertEqual(self.dev(), set())
        usage = goread.usage(self.src, [], readers.parse_go_mod)
        self.assertEqual(usage["go.mod"]["github.com/x/y"], {"test"})
        self.assertEqual(usage["sub/go.mod"]["github.com/x/y"], {"prod"})

    def test_no_import_found_stays_unknown(self):
        write(self.src, {"go.mod": "module example.com/a\n\nrequire github.com/x/y v1.0.0\n",
                         "other/go.mod": "module example.com/o\n\nrequire github.com/x/y v1.0.0\n",
                         "other/o_test.go": 'package o\nimport "github.com/x/y"\n'})
        self.assertEqual(self.dev(), set())

    def test_longest_module_prefix(self):
        write(self.src, {"go.mod": "module m\n\nrequire (\n\tcloud.google.com/go v0.1.0\n"
                                   "\tcloud.google.com/go/storage v1.0.0\n)\n",
                         "m.go": 'package m\nimport "cloud.google.com/go/storage"\n',
                         "m_test.go": 'package m\nimport "cloud.google.com/go/civil"\n'})
        self.assertEqual(self.dev(), {"cloud.google.com/go"})

    def test_hostile_symlink_size_and_cap(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        write(Path(outside.name), {"evil.go": 'package e\nimport "github.com/x/y"\n'})
        write(self.src, {"go.mod": "module m\n\nrequire github.com/x/y v1.0.0\n",
                         "m_test.go": 'package m\nimport "github.com/x/y"\n'})
        os.symlink(Path(outside.name) / "evil.go", self.src / "evil.go")
        os.symlink(Path(outside.name), self.src / "linkdir")
        self.assertEqual(self.dev(), {"github.com/x/y"})        # the symlinked production import is not read
        write(self.src, {"big.go": "package m\n//" + "x" * goread.MAX_FILE_BYTES})
        self.assertEqual(self.dev(), set())                     # a file not read: no claim for the module
        (self.src / "big.go").unlink()
        old = goread.MAX_GO_FILES
        goread.MAX_GO_FILES = 0
        try:
            self.assertEqual(self.dev(), set())
        finally:
            goread.MAX_GO_FILES = old

    def test_wired_into_dev_only_deps(self):
        write(self.src, {"go.mod": "module m\n\nrequire (\n\tgithub.com/x/y v1.0.0\n\tgithub.com/p/q v1.0.0\n)\n",
                         "m_test.go": 'package m\nimport "github.com/x/y"\n',
                         "m.go": 'package m\nimport "github.com/p/q"\n'})
        dev = readers.dev_only_deps(self.src, [])
        self.assertIn(("Go", "github.com/x/y"), dev)
        self.assertNotIn(("Go", "github.com/p/q"), dev)


if __name__ == "__main__":
    unittest.main()
