"""Edge runtime vs. the open-default model contract (gaps G1 to G4).

G1: InferenceEngine.classify fed receiver-scaled windows to a model trained
    on unit-power windows.
G2: the edge family lookups returned UNKNOWN for most open-default classes,
    which trips the default "Novel Signal Detected" rule.
G3: a missing metadata file silently swapped in an older model's class list.
G4: the benchmark and stdin frame size were hard-coded to 4096 samples.

The models here are tiny real ONNX graphs run by the real onnxruntime:
logits = ReduceMean(iq * iq over samples) @ W, so the output depends on the
input's scale and on the I/Q power split.
"""

from __future__ import annotations

import importlib
import io
import json
import logging
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import numpy as np
import pytest

onnx = pytest.importorskip("onnx")
pytest.importorskip("onnxruntime")
from onnx import TensorProto, helper  # noqa: E402

import sigrift.edge.detection_reporter as reporter_mod  # noqa: E402
import sigrift.edge.edge_inference as ei  # noqa: E402

OPEN_DEFAULT = [
    "noise",
    "tone",
    "am",
    "fm",
    "ask",
    "psk",
    "qam",
    "fsk",
    "gfsk",
    "msk",
    "ofdm",
    "lora-css",
    "dsss",
    "adsb",
    "fpv-analog",
    "pocsag",
]

AGREED_FAMILY = {
    "noise": "NOISE",
    "tone": "ANALOG",
    "am": "ANALOG",
    "fm": "ANALOG",
    "ask": "ASK",
    "psk": "PSK",
    "qam": "QAM",
    "fsk": "FSK",
    "gfsk": "FSK",
    "msk": "FSK",
    "ofdm": "OFDM",
    "lora-css": "SPREAD_SPECTRUM",
    "dsss": "SPREAD_SPECTRUM",
    "adsb": "PULSED",
    "fpv-analog": "ANALOG",
    "pocsag": "FSK",
}

_LEGACY_COMMON = {
    "ASK": ["ook", "4ask", "8ask", "16ask"],
    "PAM": ["4pam", "8pam", "16pam"],
    "PSK": ["bpsk", "qpsk", "8psk", "16psk", "32psk"],
    "QAM": ["16qam", "32qam", "64qam", "128qam", "256qam"],
    "APSK": ["16apsk", "32apsk", "64apsk", "128apsk"],
    "OFDM": ["ofdm-64", "ofdm-128", "ofdm-256", "ofdm-512", "ofdm-1024", "ofdm-2048"],
}
# Dumped from main before this change.
LEGACY_EDGE = {
    **_LEGACY_COMMON,
    "FSK": ["2fsk", "4fsk", "2gfsk", "4gfsk", "2msk", "4msk", "2gmsk", "4gmsk"],
    "ANALOG": ["am-dsb", "am-ssb", "fm", "tone"],
    "SPREAD_SPECTRUM": ["lora-css"],
    "NOISE": ["noise"],
}
LEGACY_REPORTER = {
    **_LEGACY_COMMON,
    "FSK": ["2fsk", "4fsk", "2gfsk", "4gfsk"],
    "MSK": ["2msk", "4msk", "2gmsk", "4gmsk"],
    # lora-css was ANALOG here; it is deliberately SPREAD_SPECTRUM now (the
    # agreed table, the bridge and edge_inference all say so).
    "ANALOG": ["am-dsb", "am-ssb", "fm", "tone"],
}


def make_model(path: Path, *, samples=8192, classes=16) -> Path:
    """Write a real ONNX classifier; samples=None makes the length symbolic."""
    n_cls = classes
    rng = np.random.default_rng(7)
    weights = rng.normal(size=(2, n_cls)).astype(np.float32) * 3
    nodes = [
        helper.make_node("Mul", ["iq", "iq"], ["sq"]),
        helper.make_node("ReduceMean", ["sq"], ["pw"], axes=[2], keepdims=0),
        helper.make_node("MatMul", ["pw", "w"], ["logits"]),
    ]
    graph = helper.make_graph(
        nodes,
        "power_split",
        [
            helper.make_tensor_value_info(
                "iq", TensorProto.FLOAT, ["batch", 2, samples or "n"]
            )
        ],
        [
            helper.make_tensor_value_info(
                "logits", TensorProto.FLOAT, ["batch", classes]
            )
        ],
        [helper.make_tensor("w", TensorProto.FLOAT, [2, n_cls], weights.ravel())],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model, full_check=True)
    onnx.save(model, str(path))
    return path


def write_meta(model: Path, names) -> Path:
    meta = model.parent / f"{model.stem}_metadata.json"
    meta.write_text(json.dumps({"classes": list(names)}))
    return meta


@pytest.fixture
def symbolic_classes(monkeypatch):
    """Report the class dimension as symbolic, as some exports do.

    onnxruntime infers it from this graph's weights, so a real symbolic
    class dimension cannot be built this small; the backend still runs the
    real session.
    """

    class Backend(ei.ONNXBackend):
        def __init__(self, model_path):
            super().__init__(model_path)
            self.output_shape = ["batch", "classes"]

    monkeypatch.setattr(ei, "ONNXBackend", Backend)


@pytest.fixture
def open_default(tmp_path) -> Path:
    model = make_model(tmp_path / "open-default.onnx")
    write_meta(model, OPEN_DEFAULT)
    return model


def window(n=8192, seed=1) -> np.ndarray:
    rng = np.random.default_rng(seed)
    # Unequal I/Q power so the class depends on the power split.
    return np.stack([rng.normal(size=n) * 1.7, rng.normal(size=n) * 0.4]).astype(
        np.float32
    )


# ---------------------------------------------------------------------------
# A1 (G1): unit-power normalisation in classify
# ---------------------------------------------------------------------------


class TestUnitPower:
    def test_class_and_confidence_do_not_depend_on_scale(self, open_default):
        engine = ei.InferenceEngine(str(open_default))
        iq = window()
        base = engine.classify(iq)
        for scale in (0.01, 4.0):
            got = engine.classify(iq * np.float32(scale))
            assert (got["class"], got["confidence"]) == (
                base["class"],
                base["confidence"],
            )

    def test_model_sees_unit_power(self, open_default, monkeypatch):
        engine = ei.InferenceEngine(str(open_default))
        seen = []
        real = engine.backend.infer
        monkeypatch.setattr(
            engine.backend, "infer", lambda x: (seen.append(x.copy()), real(x))[1]
        )
        engine.classify(window() * np.float32(0.003))
        power = np.mean(np.sum(seen[0][0].astype(np.float64) ** 2, axis=0))
        assert power == pytest.approx(1.0, rel=1e-5)

    def test_each_window_in_a_batch_is_normalised_on_its_own(self):
        batch = np.stack([window(64, 1) * 0.01, window(64, 2) * 9]).astype(np.float32)
        out = ei._unit_power(batch)
        powers = np.mean(np.sum(out.astype(np.float64) ** 2, axis=1), axis=-1)
        np.testing.assert_allclose(powers, [1.0, 1.0], rtol=1e-5)

    def test_callers_array_is_unchanged(self, open_default):
        engine = ei.InferenceEngine(str(open_default))
        iq = window() * np.float32(0.05)
        before = iq.copy()
        engine.classify(iq)
        np.testing.assert_array_equal(iq, before)
        batched = iq[np.newaxis]
        engine.classify(batched)
        np.testing.assert_array_equal(batched[0], before)

    @pytest.mark.parametrize("fill", [0.0, np.inf, np.nan])
    def test_zero_or_non_finite_power_is_left_alone(self, open_default, fill):
        engine = ei.InferenceEngine(str(open_default))
        iq = np.full((2, 8192), fill, dtype=np.float32)
        with np.errstate(all="ignore"):
            out = ei._unit_power(iq[np.newaxis])
            result = engine.classify(iq)  # does not raise
        np.testing.assert_array_equal(out[0], iq)
        assert result["class"] in OPEN_DEFAULT


# ---------------------------------------------------------------------------
# A2 (G2): family lookups
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "lookup",
    [ei._class_to_family, reporter_mod._class_to_family],
    ids=["edge", "reporter"],
)
def test_open_default_classes_map_to_the_agreed_family(lookup):
    assert {name: lookup(name) for name in OPEN_DEFAULT} == AGREED_FAMILY


@pytest.mark.parametrize(
    ("lookup", "legacy"),
    [
        (ei._class_to_family, LEGACY_EDGE),
        (reporter_mod._class_to_family, LEGACY_REPORTER),
    ],
    ids=["edge", "reporter"],
)
def test_legacy_mappings_are_unchanged(lookup, legacy):
    expected = {name: fam for fam, names in legacy.items() for name in names}
    assert {name: lookup(name) for name in expected} == expected
    assert lookup("not-a-class") == "UNKNOWN"


def test_classify_reports_the_agreed_family(open_default):
    result = ei.InferenceEngine(str(open_default)).classify(window())
    assert result["family"] == AGREED_FAMILY[result["class"]]


# ---------------------------------------------------------------------------
# A3 (G3): class names must match the model's output size
# ---------------------------------------------------------------------------


class TestClassCount:
    def test_metadata_count_mismatch_fails_naming_both_files(self, tmp_path):
        model = make_model(tmp_path / "open-default.onnx")
        meta = write_meta(model, OPEN_DEFAULT[:15])
        with pytest.raises(ei.ModelContractError) as exc:
            ei.InferenceEngine(str(model))
        msg = str(exc.value)
        assert str(model) in msg and str(meta) in msg
        assert "16" in msg and "15" in msg

    def test_missing_metadata_with_wrong_default_length_names_expected_file(
        self, tmp_path
    ):
        model = make_model(tmp_path / "open-default.onnx")
        with pytest.raises(ei.ModelContractError) as exc:
            ei.InferenceEngine(str(model))
        msg = str(exc.value)
        assert str(tmp_path / "open-default_metadata.json") in msg
        assert "16" in msg and str(len(ei.DEFAULT_CLASSES)) in msg

    def test_missing_metadata_with_matching_length_warns_and_works(
        self, tmp_path, caplog
    ):
        model = make_model(tmp_path / "legacy.onnx", classes=len(ei.DEFAULT_CLASSES))
        with caplog.at_level(logging.INFO, logger="edge_inference"):
            engine = ei.InferenceEngine(str(model))
        warned = [
            r
            for r in caplog.records
            if r.levelno == logging.WARNING and "legacy_metadata.json" in r.getMessage()
        ]
        assert warned
        assert engine.classify(window())["class"] in ei.DEFAULT_CLASSES

    def test_matching_metadata_loads(self, open_default):
        engine = ei.InferenceEngine(str(open_default))
        assert engine.class_names == OPEN_DEFAULT

    def test_another_models_sidecar_is_never_used(self, tmp_path):
        # A same-length list for a different model would pass the count
        # check and mislabel everything, so it must not be picked up.
        model = make_model(tmp_path / "my-local.onnx")
        write_meta(tmp_path / "previous-release.onnx", [f"x{i}" for i in range(16)])
        with pytest.raises(ei.ModelContractError) as exc:
            ei.InferenceEngine(str(model))
        assert str(tmp_path / "my-local_metadata.json") in str(exc.value)

    def test_an_alias_uses_its_targets_sidecar(self, tmp_path):
        # quickstart links open-default.onnx to the release file; the
        # release file's own sidecar names the classes even without a
        # metadata alias, and a stranger's sidecar next to it is ignored.
        model = make_model(tmp_path / "release-model.onnx")
        meta = write_meta(model, OPEN_DEFAULT)
        write_meta(tmp_path / "another.onnx", [f"x{i}" for i in range(16)])
        alias = tmp_path / "open-default.onnx"
        alias.symlink_to(model.name)
        engine = ei.InferenceEngine(str(alias))
        assert engine.class_names == OPEN_DEFAULT
        assert engine.metadata_path.resolve() == meta.resolve()

    def test_the_alias_named_sidecar_wins_over_the_targets(self, tmp_path):
        model = make_model(tmp_path / "release-model.onnx")
        write_meta(model, [f"x{i}" for i in range(16)])
        alias = tmp_path / "open-default.onnx"
        alias.symlink_to(model.name)
        write_meta(alias, OPEN_DEFAULT)
        assert ei.InferenceEngine(str(alias)).class_names == OPEN_DEFAULT

    def test_load_metadata_returns_just_the_names(self, open_default):
        assert ei.load_metadata(str(open_default)) == OPEN_DEFAULT

    @pytest.mark.parametrize("shape", [None, [], ["batch", "n"], [1, 0]])
    def test_a_missing_or_symbolic_dimension_is_not_fixed(self, shape):
        assert ei._fixed_dim(shape, -1) is None

    def test_symbolic_class_dim_is_checked_on_first_inference(
        self, tmp_path, symbolic_classes
    ):
        model = make_model(tmp_path / "m.onnx")
        write_meta(model, OPEN_DEFAULT[:12])
        engine = ei.InferenceEngine(str(model))  # cannot tell yet
        with pytest.raises(ei.ModelContractError, match="12 class names"):
            engine.classify(window())

    def test_symbolic_class_dim_that_matches_keeps_working(
        self, tmp_path, symbolic_classes
    ):
        model = make_model(tmp_path / "m.onnx")
        write_meta(model, OPEN_DEFAULT)
        engine = ei.InferenceEngine(str(model))
        assert engine.classify(window())["class"] in OPEN_DEFAULT
        assert engine.classify(window(seed=3))["class"] in OPEN_DEFAULT


# ---------------------------------------------------------------------------
# A4 (G4): frame size follows the model
# ---------------------------------------------------------------------------


class TestFrameSize:
    def test_fixed_input_length_wins(self, open_default, monkeypatch):
        monkeypatch.setenv("MLRF_INPUT_SAMPLES", "1024")
        assert ei.InferenceEngine(str(open_default)).input_samples == 8192

    def test_dynamic_input_length_uses_env_then_4096(self, tmp_path, monkeypatch):
        model = make_model(tmp_path / "m.onnx", samples=None)
        write_meta(model, OPEN_DEFAULT)
        monkeypatch.setenv("MLRF_INPUT_SAMPLES", "1024")
        assert ei.InferenceEngine(str(model)).input_samples == 1024
        monkeypatch.delenv("MLRF_INPUT_SAMPLES")
        assert ei.InferenceEngine(str(model)).input_samples == 4096

    @pytest.mark.parametrize("bad", ["0", "-5", "lots"])
    def test_bad_env_fails_loudly(self, tmp_path, monkeypatch, bad):
        model = make_model(tmp_path / "m.onnx", samples=None)
        write_meta(model, OPEN_DEFAULT)
        monkeypatch.setenv("MLRF_INPUT_SAMPLES", bad)
        with pytest.raises(ei.ModelContractError, match="MLRF_INPUT_SAMPLES"):
            ei.InferenceEngine(str(model))

    def test_benchmark_runs_against_an_8192_sample_model(self, open_default):
        result = ei.run_benchmark(ei.InferenceEngine(str(open_default)), num_iters=3)
        assert result["iterations"] == 3

    def test_benchmark_runs_against_a_dynamic_length_model(self, tmp_path, monkeypatch):
        model = make_model(tmp_path / "m.onnx", samples=None)
        write_meta(model, OPEN_DEFAULT)
        monkeypatch.delenv("MLRF_INPUT_SAMPLES", raising=False)
        result = ei.run_benchmark(ei.InferenceEngine(str(model)), num_iters=3)
        assert result["iterations"] == 3

    def test_benchmark_cli_against_an_8192_sample_model(
        self, open_default, monkeypatch, capsys
    ):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "edge_inference.py",
                "--model",
                str(open_default),
                "--benchmark",
                "--benchmark-iters",
                "2",
            ],
        )
        ei.main()
        assert json.loads(capsys.readouterr().out)["iterations"] == 2

    def test_cli_exits_cleanly_on_a_contract_error(self, tmp_path, monkeypatch, caplog):
        model = make_model(tmp_path / "open-default.onnx")  # no metadata
        monkeypatch.setattr(
            sys, "argv", ["edge_inference.py", "--model", str(model), "--benchmark"]
        )
        with caplog.at_level(logging.ERROR, logger="edge_inference"):
            with pytest.raises(SystemExit) as exc:
                ei.main()
        assert exc.value.code == 1
        assert "open-default_metadata.json" in caplog.text

    def test_stdin_reads_frames_of_the_models_length(self, open_default, monkeypatch):
        frames = np.stack([window(), window(seed=2)])  # [2 frames, 2, 8192]
        raw = np.ascontiguousarray(frames.transpose(0, 2, 1)).tobytes()
        seen = []
        real = ei.InferenceEngine.classify

        def spy(self, iq):
            seen.append(iq.copy())
            return real(self, iq)

        monkeypatch.setattr(ei.InferenceEngine, "classify", spy)
        monkeypatch.setattr(
            sys, "argv", ["edge_inference.py", "--model", str(open_default)]
        )
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
        ei.main()
        assert len(seen) == 2
        np.testing.assert_array_equal(seen[0], frames[0])
        np.testing.assert_array_equal(seen[1], frames[1])


# ---------------------------------------------------------------------------
# rf_scan: raw power, frame length, and how a contract error surfaces
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rf(tmp_path_factory) -> ModuleType:
    if "sigrift.edge.rf_scan" in sys.modules:
        return sys.modules["sigrift.edge.rf_scan"]
    tmp = tmp_path_factory.mktemp("rf_scan")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("MLRF_LOG_DIR", str(tmp / "logs"))
        mp.setenv("MLRF_AGENT_DIR", str(tmp / "agent"))
        return importlib.import_module("sigrift.edge.rf_scan")


class _SDR:
    connected = True
    name = "synthetic"
    sample_rate = 2.4e6

    def __init__(self, iq=None, *_args):
        self.iq = iq
        self.asked = []

    def connect(self):
        return True

    def set_frequency(self, _freq):
        return True

    def capture(self, count):
        self.asked.append(count)
        if self.iq is not None:
            return self.iq
        rng = np.random.default_rng(5)
        return (rng.normal(size=count) + 1j * rng.normal(size=count)).astype(
            np.complex64
        ) * np.float32(0.02)

    def disconnect(self):
        pass


class _Reporter:
    def __init__(self, **_kwargs):
        self.calls = []
        self.stopped = False

    def start(self):
        pass

    def report(self, **kwargs):
        self.calls.append(kwargs)
        return False

    def stop(self):
        self.stopped = True


class TestRfScan:
    def test_reported_power_reflects_the_raw_capture(self, rf, open_default):
        engine = ei.InferenceEngine(str(open_default))
        rng = np.random.default_rng(9)
        iq = (rng.normal(size=8192) + 1j * rng.normal(size=8192)).astype(
            np.complex64
        ) * np.float32(0.01)
        before = iq.copy()
        rep = _Reporter()
        rf.scan_frequency(_SDR(iq), 915_000_000, engine, rep)
        call = rep.calls[0]
        assert call["power_dbm"] == rf.estimate_power(before)
        assert call["power_dbm"] == pytest.approx(10 * np.log10(2e-4), abs=0.2)
        assert call["snr_db"] == rf.estimate_snr(before)
        np.testing.assert_array_equal(call["iq_data"], before)

    def test_capture_length_follows_the_model(self, rf, open_default, monkeypatch):
        monkeypatch.setattr(rf, "INPUT_SAMPLES", 4096)
        sdr = _SDR()
        rf.scan_frequency(
            sdr, 915_000_000, ei.InferenceEngine(str(open_default)), _Reporter()
        )
        assert sdr.asked == [8192]

    def _prepare_main(self, rf, monkeypatch, model):
        monkeypatch.setenv("MLRF_BRIDGE_URL", "https://bridge.invalid")
        monkeypatch.setenv("MLRF_BRIDGE_KEY", "k")
        monkeypatch.setenv("MLRF_NODE_ID", "n1")
        monkeypatch.setenv("MLRF_MODEL_PATH", str(model))
        monkeypatch.setenv("MLRF_ANOMALY", "0")
        monkeypatch.setattr(rf, "start_status_server", lambda: None)
        monkeypatch.setattr(rf, "_check_tls_config", lambda: True)
        monkeypatch.setattr(rf.signal, "signal", lambda *_a: None)
        monkeypatch.setattr(rf, "FREQUENCIES", {915: "synthetic"})
        monkeypatch.setitem(rf.state, "running", True)

    def test_main_refuses_to_start_without_matching_metadata(
        self, rf, tmp_path, monkeypatch, caplog
    ):
        model = make_model(tmp_path / "open-default.onnx")  # metadata missing
        self._prepare_main(rf, monkeypatch, model)

        def unexpected(*_a, **_k):
            pytest.fail("radio opened despite an unusable model")

        monkeypatch.setattr(rf, "RTLTCPClient", unexpected)
        with caplog.at_level(logging.ERROR, logger="rf_scan"):
            assert rf.main() == 1
        assert "open-default_metadata.json" in caplog.text

    def test_late_contract_error_stops_the_scanner_with_error_status(
        self, rf, tmp_path, monkeypatch, caplog, symbolic_classes
    ):
        model = make_model(tmp_path / "open-default.onnx")
        write_meta(model, OPEN_DEFAULT[:10])
        self._prepare_main(rf, monkeypatch, model)
        monkeypatch.setattr(rf, "RTLTCPClient", lambda *_a: _SDR())
        reporters = []

        def make_reporter(**kwargs):
            reporters.append(_Reporter(**kwargs))
            return reporters[-1]

        monkeypatch.setattr(reporter_mod, "DetectionReporter", make_reporter)
        finals = []

        class Status:
            def __init__(self, *_a):
                pass

            def start(self):
                pass

            def stop(self, final):
                finals.append(final)

        monkeypatch.setattr(rf, "ScannerStatusReporter", Status)
        with caplog.at_level(logging.ERROR, logger="rf_scan"):
            assert rf.main() == 1
        assert "10 class names" in caplog.text
        assert finals == ["error"]
        assert reporters[0].stopped and reporters[0].calls == []
