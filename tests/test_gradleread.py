import os
import tempfile
import unittest
from pathlib import Path

from sbomaudit import gradleread, readers


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


CATALOG = """
[versions]
okhttp = "4.12.0"
compose-bom = "2024.02.00"
room = { strictly = "2.6.1" }

[libraries]
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
okhttp-logging = { group = "com.squareup.okhttp3", name = "logging-interceptor", version.ref = "okhttp" }
androidx-compose-bom = { group = "androidx.compose", name = "compose-bom", version.ref = "compose-bom" }
compose-ui = { module = "androidx.compose.ui:ui" }
room-runtime = { module = "androidx.room:room-runtime", version.ref = "room" }
room-compiler = { module = "androidx.room:room-compiler", version.ref = "room" }
junit = "junit:junit:4.13.2"
broken-ref = { module = "org.x:broken", version.ref = "nope" }

[bundles]
network = ["okhttp", "okhttp-logging"]

[plugins]
android-app = { id = "com.android.application", version = "8.2.0" }
"""

APP_KTS = """
plugins { alias(libs.plugins.android.app) }

val composeBom = platform(libs.androidx.compose.bom)
val coroutines = "1.7.3"

dependencies {
    implementation(libs.okhttp)
    implementation(libs.bundles.network)
    implementation(composeBom)
    implementation(libs.compose.ui)
    implementation(libs.room.runtime)
    ksp(libs.room.compiler)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:$coroutines")
    implementation(project(":core"))
    testImplementation(libs.junit)
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    debugImplementation("com.squareup.leakcanary:leakcanary-android:2.13")
    // implementation("com.example:commented-out:1.0")
    implementation(kotlin("reflect"))
    implementation(libs.broken.ref)
    implementation(libs.does.not.exist)
    implementation(Deps.mystery)
}
"""

GROOVY = """
plugins { id 'java' }
ext.jacksonVersion = '2.16.1'
ext {
    slf4jVersion = "2.0.9"
}
def guavaVersion = '33.0.0-jre'

dependencies {
    implementation "com.fasterxml.jackson.core:jackson-databind:${jacksonVersion}"
    implementation group: 'org.slf4j', name: 'slf4j-api', version: slf4jVersion
    api "com.google.guava:guava:$guavaVersion"
    compileOnly 'org.projectlombok:lombok:1.18.30'
    annotationProcessor 'org.projectlombok:lombok:1.18.30'
    runtimeOnly 'org.postgresql:postgresql:42.+'
    implementation 'org.apache.commons:commons-text:[1.10,2.0)'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation platform('org.springframework.boot:spring-boot-dependencies:3.2.1')
    implementation "org.unknown:thing:${undefinedVersion}"
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.1', 'org.mockito:mockito-core:5.8.0'
    developmentOnly 'org.springframework.boot:spring-boot-devtools'
    implementation 'org.mixed:lib:1.0'
    testImplementation 'org.mixed:lib:1.0'
}
"""


class GradleTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.src = Path(self._tmp.name).resolve()

    def tearDown(self):
        self._tmp.cleanup()

    def decls(self):
        a = gradleread.analyse(self.src, [])
        return {(d.ga or d.unknown): d for d in a.declarations()}, a


class ConfigurationTests(unittest.TestCase):
    def test_dev_and_production_configurations(self):
        dev = ["testImplementation", "androidTestImplementation", "debugImplementation", "kapt", "ksp",
               "annotationProcessor", "kaptTest", "kspAndroidTest", "testFixturesApi", "integrationTestImplementation",
               "testCompileClasspath", "debugRuntimeClasspath", "debugUnitTestRuntimeClasspath",
               "developmentOnly", "detektPlugins", "lintChecks", "checkstyle", "testAnnotationProcessor"]
        prod = ["implementation", "api", "runtimeOnly", "compileOnly", "compileClasspath", "runtimeClasspath",
                "releaseRuntimeClasspath", "coreLibraryDesugaring", "freeImplementation", "contestImplementation",
                "latestImplementation"]
        for name in dev:
            self.assertTrue(gradleread.config_is_dev(name), name)
        for name in prod:
            self.assertFalse(gradleread.config_is_dev(name), name)


class CatalogTests(unittest.TestCase):
    def test_catalog_forms(self):
        cat = gradleread.parse_catalog(CATALOG)
        self.assertEqual(cat["okhttp"], [("com.squareup.okhttp3", "okhttp", "4.12.0", "")])
        self.assertEqual(cat["okhttp.logging"][0][:3], ("com.squareup.okhttp3", "logging-interceptor", "4.12.0"))
        self.assertEqual(cat["junit"][0][:3], ("junit", "junit", "4.13.2"))
        self.assertEqual(cat["room.runtime"][0][2], "2.6.1")
        self.assertEqual(cat["compose.ui"][0][2], "")
        self.assertIn("BOM", cat["compose.ui"][0][3])
        self.assertEqual(cat["broken.ref"][0][2], "")
        self.assertEqual(len(cat["bundles.network"]), 2)
        self.assertFalse(any(k.startswith("plugins") for k in cat))

    def test_malformed_catalog_is_empty(self):
        self.assertEqual(gradleread.parse_catalog("[libraries\nx = "), {})


class BuildFileTests(GradleTestCase):
    def test_kotlin_dsl_with_catalog(self):
        write(self.src, {"settings.gradle.kts": 'include(":app", ":core")\n', "gradle/libs.versions.toml": CATALOG,
                         "app/build.gradle.kts": APP_KTS, "core/build.gradle.kts": "dependencies { }\n"})
        d, a = self.decls()
        self.assertEqual(d["com.squareup.okhttp3:okhttp"].version, "4.12.0")
        self.assertIn("com.squareup.okhttp3:logging-interceptor", d)
        bom = d["androidx.compose:compose-bom"]
        self.assertTrue(bom.platform)
        self.assertEqual(bom.version, "2024.02.00")
        self.assertEqual(d["androidx.compose.ui:ui"].version, "")
        self.assertTrue(d["androidx.room:room-compiler"].dev)
        self.assertFalse(d["androidx.room:room-runtime"].dev)
        self.assertEqual(d["org.jetbrains.kotlinx:kotlinx-coroutines-android"].version, "1.7.3")
        self.assertTrue(d["junit:junit"].dev)
        self.assertTrue(d["androidx.test.espresso:espresso-core"].dev)
        self.assertTrue(d["com.squareup.leakcanary:leakcanary-android"].dev)
        self.assertNotIn("com.example:commented-out", d)
        self.assertEqual(d["org.jetbrains.kotlin:kotlin-reflect"].version, "")
        self.assertEqual(d["org.x:broken"].version, "")
        self.assertIn("libs.does.not.exist", d)
        self.assertIn("Deps.mystery", d)
        self.assertFalse(any(":core" in k for k in d))
        self.assertEqual({m.rel for m in a.modules}, {"app/build.gradle.kts", "core/build.gradle.kts"})

    def test_groovy_notations_and_constants(self):
        write(self.src, {"build.gradle": GROOVY, "gradle.properties": "unused=1\n"})
        d, _ = self.decls()
        self.assertEqual(d["com.fasterxml.jackson.core:jackson-databind"].version, "2.16.1")
        self.assertEqual(d["org.slf4j:slf4j-api"].version, "2.0.9")
        self.assertEqual(d["com.google.guava:guava"].version, "33.0.0-jre")
        self.assertEqual(d["org.postgresql:postgresql"].version, "")
        self.assertIn("dynamic", d["org.postgresql:postgresql"].reason)
        self.assertEqual(d["org.apache.commons:commons-text"].version, "")
        self.assertEqual(d["org.springframework.boot:spring-boot-starter-web"].version, "")
        self.assertTrue(d["org.springframework.boot:spring-boot-dependencies"].platform)
        self.assertEqual(d["org.unknown:thing"].version, "")
        self.assertIn("variable", d["org.unknown:thing"].reason)
        self.assertTrue(d["org.mockito:mockito-core"].dev)
        self.assertTrue(d["org.junit.jupiter:junit-jupiter"].dev)
        self.assertTrue(d["org.springframework.boot:spring-boot-devtools"].dev)

    def test_gradle_properties_and_ambiguous_constants(self):
        write(self.src, {"gradle.properties": "kotlinVersion=1.9.22\n",
                         "a/build.gradle": "def v = '1.0'\ndependencies { implementation \"g:a:$v\"\n"
                                           "implementation \"org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion\" }\n",
                         "b/build.gradle": "def v = '2.0'\ndependencies { implementation \"g:b:$v\" }\n"})
        d, _ = self.decls()
        self.assertEqual(d["org.jetbrains.kotlin:kotlin-stdlib"].version, "1.9.22")
        self.assertEqual(d["g:a"].version, "")            # `v` is 1.0 in one file, 2.0 in another: never a guess
        self.assertEqual(d["g:b"].version, "")

    def test_constraints_supply_versions_and_are_not_declarations(self):
        write(self.src, {"build.gradle": "dependencies {\n implementation 'g:a'\n constraints {\n"
                                         "  implementation 'g:a:1.2.3'\n  implementation 'g:only-constraint:9'\n }\n}\n"})
        d, _ = self.decls()
        self.assertEqual(d["g:a"].version, "1.2.3")
        self.assertNotIn("g:only-constraint", d)

    def test_buildscript_and_plugins_are_not_dependencies(self):
        write(self.src, {"build.gradle": "buildscript { dependencies { classpath 'com.android.tools.build:gradle:8.2.0' } }\n"
                                         "plugins { id 'org.springframework.boot' version '3.2.1' }\n"
                                         "dependencies { implementation 'g:a:1' }\n"})
        d, _ = self.decls()
        self.assertEqual(set(d), {"g:a"})

    def test_kmp_test_source_sets_are_dev(self):
        write(self.src, {"build.gradle.kts": "kotlin { sourceSets {\n commonMain.dependencies { implementation(\"g:main:1\") }\n"
                                             " commonTest.dependencies { implementation(\"g:test:1\") }\n"
                                             " val jvmTest by getting { dependencies { implementation(\"g:jvmtest:1\") } }\n"
                                             "} }\n"})
        d, _ = self.decls()
        self.assertFalse(d["g:main"].dev)
        self.assertTrue(d["g:test"].dev)
        self.assertTrue(d["g:jvmtest"].dev)

    def test_buildsrc_constants(self):
        write(self.src, {"buildSrc/src/main/kotlin/Versions.kt": 'object Versions { const val retrofit = "2.9.0" }\n',
                         "build.gradle.kts": 'dependencies { implementation("com.squareup.retrofit2:retrofit:${Versions.retrofit}") }\n'})
        d, _ = self.decls()
        self.assertEqual(d["com.squareup.retrofit2:retrofit"].version, "2.9.0")


class LockfileTests(GradleTestCase):
    def test_lockfile_scopes_and_unknown_direct(self):
        write(self.src, {"build.gradle": "dependencies { implementation 'g:a:1'\n testImplementation 'g:t:1' }\n",
                         "gradle.lockfile": "g:a:1.0=compileClasspath,runtimeClasspath\n"
                                            "g:trans:2.0=runtimeClasspath\n"
                                            "g:t:1.0=testCompileClasspath,testRuntimeClasspath\n"
                                            "g:ttrans:1.0=testRuntimeClasspath\nempty=annotationProcessor\n"})
        a = gradleread.analyse(self.src, [])
        s = gradleread.scopes(a)
        self.assertEqual(s["g:ttrans"], {True})
        self.assertEqual(s["g:trans"], {False})
        self.assertEqual(s["g:t"], {True})
        self.assertEqual(gradleread.unknown_direct_locations(a), set())
        # declared and locked: the lock file (read by Syft) has the version, nothing is added
        self.assertEqual(gradleread.components(a, set()), [])

    def test_unparseable_declaration_makes_lockfile_direct_unknown(self):
        write(self.src, {"build.gradle": "dependencies { implementation Deps.x }\n",
                         "gradle.lockfile": "g:a:1.0=runtimeClasspath\n"})
        a = gradleread.analyse(self.src, [])
        self.assertEqual(gradleread.unknown_direct_locations(a), {"gradle.lockfile"})

    def test_transitive_lock_scope_ignored_when_a_module_is_unlocked(self):
        write(self.src, {"a/build.gradle": "dependencies { implementation 'g:x:1' }\n",
                         "a/gradle.lockfile": "g:x:1=runtimeClasspath\ng:tt:1=testRuntimeClasspath\n",
                         "b/build.gradle": "dependencies { implementation 'g:y:1' }\n"})
        s = gradleread.scopes(gradleread.analyse(self.src, []))
        self.assertNotIn("g:tt", s)

    def test_legacy_lock_state_emits_packages(self):
        write(self.src, {"build.gradle": "dependencies { testImplementation 'g:t:1' }\n",
                         "gradle/dependency-locks/testRuntimeClasspath.lockfile": "g:t:1.5\ng:tt:2.0\n"})
        a = gradleread.analyse(self.src, [])
        comps = {c.name: c for c in gradleread.components(a, {"g:t", "g:tt"})}
        self.assertEqual(comps["t"].version, "1.5")
        self.assertTrue(comps["t"].direct)
        self.assertFalse(comps["tt"].direct)
        self.assertEqual(comps["tt"].scope, "optional")
        self.assertEqual(gradleread.scopes(a)["g:tt"], {True})

    def test_unlocked_module_emits_declared_and_unresolved(self):
        write(self.src, {"build.gradle": "dependencies { implementation 'g:a:1.0'\n implementation 'g:dyn:1.+'\n"
                                         " implementation helper()\n testImplementation 'g:t:2' }\n"})
        a = gradleread.analyse(self.src, [])
        comps = {c.name: c for c in gradleread.components(a, {"g:t"})}
        self.assertEqual((comps["a"].version, comps["a"].purl, comps["a"].scope), ("1.0", "pkg:maven/g/a@1.0", "required"))
        self.assertEqual((comps["dyn"].version, comps["dyn"].purl), ("", "pkg:maven/g/dyn"))
        self.assertTrue(comps["dyn"].props["unresolved"])
        self.assertEqual(comps["dyn"].props["requirement"], "g:dyn:1.+")
        self.assertEqual(comps["t"].scope, "optional")
        self.assertIn("helper()", comps)
        self.assertEqual(comps["helper()"].purl, "")
        self.assertTrue(comps["helper()"].props["unresolved"])


class HostileInputTests(GradleTestCase):
    def test_symlinked_build_file_outside_tree_is_ignored(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        write(Path(outside.name), {"build.gradle": "dependencies { implementation 'evil:outside:1' }\n"})
        (self.src / "mod").mkdir()
        os.symlink(Path(outside.name) / "build.gradle", self.src / "mod" / "build.gradle")
        os.symlink(Path(outside.name), self.src / "linked")
        d, _ = self.decls()
        self.assertEqual(d, {})

    def test_settings_include_cannot_escape(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        write(Path(outside.name), {"x/build.gradle": "dependencies { implementation 'evil:outside:1' }\n"})
        rel = os.path.relpath(Path(outside.name) / "x", self.src)
        write(self.src, {"settings.gradle": f"include ':x'\nproject(':x').projectDir = file('{rel}')\n"
                                            "include '..:..:..:etc'\n",
                         "build.gradle": "dependencies { implementation 'g:a:1' }\n"})
        d, _ = self.decls()
        self.assertEqual(set(d), {"g:a"})

    def test_huge_file_is_skipped(self):
        write(self.src, {"build.gradle": "dependencies { implementation 'g:a:1' }\n" + "//" + "x" * gradleread.MAX_FILE_BYTES})
        d, _ = self.decls()
        self.assertEqual(d, {})

    def test_pathological_input_does_not_hang_or_raise(self):
        write(self.src, {"build.gradle": "dependencies {" + "(" * 5000 + "{" * 3000 + "'unterminated\n" + '"""' + "}" * 10,
                         "gradle/libs.versions.toml": "[[[",
                         "gradle.properties": "\x00\xff=\n",
                         "gradle.lockfile": ":::\n=\na:b\n"})
        gradleread.analyse(self.src, [])

    def test_ignore_prefixes(self):
        write(self.src, {"samples/build.gradle": "dependencies { implementation 'g:a:1' }\n"})
        self.assertEqual(list(gradleread.analyse(self.src, ["samples"]).declarations()), [])


class ReaderHookTests(GradleTestCase):
    def test_direct_and_dev_only_across_maven_and_gradle(self):
        write(self.src, {"build.gradle": GROOVY,
                         "pom.xml": "<project><dependencies><dependency><groupId>org.mockito</groupId>"
                                    "<artifactId>mockito-core</artifactId><scope>compile</scope></dependency>"
                                    "</dependencies></project>"})
        direct = readers.direct_deps(self.src, [])
        self.assertEqual(direct[("Maven", "org.slf4j:slf4j-api")], ["build.gradle"])
        dev = readers.dev_only_deps(self.src, [])
        self.assertIn(("Maven", "org.junit.jupiter:junit-jupiter"), dev)
        self.assertNotIn(("Maven", "org.mockito:mockito-core"), dev)     # compile in the pom
        self.assertNotIn(("Maven", "org.mixed:lib"), dev)               # implementation and test
        self.assertNotIn(("Maven", "org.projectlombok:lombok"), dev)    # compileOnly and annotationProcessor

    def test_read_tree_adds_unlocked_gradle_packages(self):
        write(self.src, {"build.gradle": "dependencies { implementation 'g:a:1.0'\n testImplementation 'g:t' }\n"})
        comps = {c.name: c for c in readers.read_tree(self.src, []) if c.ecosystem == "Maven"}
        self.assertEqual(comps["a"].version, "1.0")
        self.assertEqual(comps["t"].scope, "optional")
        self.assertTrue(comps["t"].props["unresolved"])


if __name__ == "__main__":
    unittest.main()
