"""Protocol decode pipeline: demod -> decode -> crypto -> storage.

Orchestrates the full signal processing chain from raw IQ samples
through demodulation, protocol decoding, optional decryption, and
persistence to the decoded message store.

Each demodulator is driven through its real interface:

* DMR / P25 (4FSK, 4800 baud): the capture is resampled to
  :data:`_FSK_DEMOD_RATE` (10 samples per symbol), channel-filtered to a
  12.5 kHz channel, trimmed so the demodulator's symbol clock starts on
  a symbol centre, and demodulated with
  ``FSKDemodulator(sample_rate).demodulate(iq, preset=...)``.  Symbols
  map to dibits as ETSI TS 102 361-1 / TIA-102.BAAA define them
  (+3 -> 01, +1 -> 00, -1 -> 10, -3 -> 11), and the bit stream is decoded
  frame by frame (a capture holds many bursts; ``decode_packet`` decodes
  one).
* LoRa / Meshtastic: the occupied bandwidth is measured on the wideband
  capture, the capture is resampled to that bandwidth (the CSS
  demodulator assumes one sample per chip) and demodulated with
  ``LoRaCSSDemodulator(sample_rate).demodulate(iq, bw=...)``.  The
  symbols after the preamble are packed as ``sf``-bit values for
  ``LoRaPhyDecoder.decode_packet(raw, sf=...)``.  A PHY frame is only
  kept when its header check and payload CRC pass (the demodulator has
  no fine frame synchronisation, so unverified output would be noise
  stored as messages); a Meshtastic packet is decoded from a verified
  PHY payload only.

The work is bounded whatever the capture claims (its sample rate comes
from the uploader): at most :func:`sigrift.bridge.iq_store.analysis_max_samples`
samples are processed, before and after resampling; a rate outside
:data:`~sigrift.bridge.iq_store.MIN_IQ_SAMPLE_RATE_HZ` ..
:data:`~sigrift.bridge.iq_store.MAX_IQ_SAMPLE_RATE_HZ`, too low to hold
the protocol's channel, or needing a resampling factor beyond
:data:`_MAX_UPSAMPLE` / :data:`_MAX_RESAMPLE_TERM` is not decoded.

A capture is only worth a job when it can hold a whole frame
(:func:`decode_skip_reason`): one DMR burst (27.5 ms), a P25 frame sync
and NID (13.3 ms), or a LoRa preamble, sync word, SFD and header at SF7
and the widest bandwidth the capture holds (21 symbols, 5.4 ms at
500 kHz) — counting only the part the job analyses.  An edge's
classifier window (4096 samples at 2.048 MHz, 2 ms) is shorter than all
of them, so no job is queued for it (the reason is logged, and returned
by the IQ upload route) instead of a job "decoding" it into nothing.

Each detection is decoded at most once, whichever path queues it first —
the IQ upload route or post-ingest (contract K8b): see
:func:`queue_protocol_decode_once`.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from fractions import Fraction
from typing import Any, Callable

import numpy as np

from sigrift.bridge import iq_store as _iq_store

logger = logging.getLogger(__name__)

# Signal class to demodulator mapping.  Detections are stored with the
# canonical class_map names (LoRa is ``lora-css``); the raw / legacy names
# edges may send are accepted too.
_MESHTASTIC_CLASSES = {"meshtastic", "lora-meshtastic"}
_LORA_CLASSES = {
    "lora",
    "lora-css",
    "lora_css",
    "lorawan",
    "lora-lorawan",
    "lora-meshcore",
} | _MESHTASTIC_CLASSES
_DMR_CLASSES = {"dmr"}
_P25_CLASSES = {"p25", "p25_c4fm"}
_DECT_CLASSES = {"dect"}

#: Signal classes with both a demodulator and a protocol decoder (DECT has
#: a demodulator but no decoder, so decoding it could never yield a
#: message).  ``protocol_decode`` jobs are queued only for these.
DECODABLE_SIGNAL_CLASSES = frozenset(_LORA_CLASSES | _DMR_CLASSES | _P25_CLASSES)

_DEFAULT_SAMPLE_RATE = 2_048_000.0
#: Decoded-message records a protocol_decode job result carries inline.
_JOB_RESULT_MESSAGES = 50

# -- FSK (DMR / P25) front end -------------------------------------------------

#: DMR and P25 C4FM are demodulated at this rate: 10 samples per symbol.
_FSK_DEMOD_RATE = 48_000.0
#: One-sided cut-off of the channel filter (12.5 kHz channel; 4FSK at
#: +-1944 Hz / 4800 baud occupies about +-4.4 kHz).
_FSK_CHANNEL_CUTOFF_HZ = 6_000.0
_FSK_CHANNEL_TAPS = 129
#: Fewer symbols than this cannot hold a frame (a DMR burst is 132).
_FSK_MIN_SYMBOLS = 64
#: Below this many samples per symbol (9.6 kHz at 4800 baud) the 4FSK
#: channel (about +-4.4 kHz) does not fit in the capture.
_FSK_MIN_SAMPLES_PER_SYMBOL = 2.0
#: Dibits per 4FSK symbol: ETSI TS 102 361-1 (DMR) and TIA-102.BAAA (P25
#: C4FM) use the same mapping.
_FSK_DIBITS = {3: (0, 1), 1: (0, 0), -1: (1, 0), -3: (1, 1)}
#: Largest numerator / denominator of a rational resampling factor (the
#: anti-alias FIR has about 20 x max(up, down) taps), and so the largest
#: decimation: a capture over 4096 x the demodulation rate is not decoded.
_MAX_RESAMPLE_TERM = 4096
#: Largest interpolation (a DMR / P25 capture below 48 kHz).
_MAX_UPSAMPLE = 8

# -- LoRa front end ------------------------------------------------------------

_LORA_BANDWIDTHS = (125_000.0, 250_000.0, 500_000.0)
#: LoRa frame layout after the preamble: 2 sync-word symbols, then 2.25
#: down-chirps (the SFD) before the header.
_LORA_SYNC_SYMBOLS = 2
_LORA_SFD_BLOCKS = 3
_LORA_MIN_PREAMBLE = 8
#: Symbols of the explicit header.
_LORA_HEADER_SYMBOLS = 8
#: Shortest LoRa frame the pipeline can find: preamble, sync word, SFD
#: blocks and the header.
_LORA_MIN_FRAME_SYMBOLS = (
    _LORA_MIN_PREAMBLE + _LORA_SYNC_SYMBOLS + _LORA_SFD_BLOCKS + _LORA_HEADER_SYMBOLS
)
#: Smallest spreading factor (the shortest symbol: 2**SF chips).
_LORA_MIN_SF = 7

# -- Framing -------------------------------------------------------------------

#: Both DMR and P25 frame syncs are 48 bits.
_SYNC_BITS = 48
#: Frames decoded from one capture at most (bounds CPU time and storage).
_MAX_FRAMES = 256


@dataclass(frozen=True)
class _Framing:
    """Where a protocol's frames sit around their sync in the bit stream.

    ``window`` bits are handed to ``decode_packet`` at a time (a multiple
    of 8, so they pack into whole bytes); a frame needs ``lead`` bits
    before its sync and ``tail`` bits from the sync's first bit on.
    """

    window: int
    lead: int
    tail: int


_FRAMINGS = {
    # 264-bit burst: 108 bits (info + slot type), 48-bit sync, 108 bits.
    "dmr": _Framing(window=1056, lead=108, tail=156),
    # Frame sync, then the 64-bit NID (status dibits interleaved); an LDU
    # (the longest voice frame) is 1728 bits.
    "p25": _Framing(window=1728, lead=0, tail=128),
}


def is_decodable(signal_class: Any) -> bool:
    """True if a detection of *signal_class* can be protocol-decoded."""
    return (
        isinstance(signal_class, str)
        and signal_class.lower().strip() in DECODABLE_SIGNAL_CLASSES
    )


def min_decode_seconds(signal_class: Any, sample_rate: Any) -> float | None:
    """Shortest capture (seconds) in which *signal_class* can hold a frame.

    ``None`` when the class is not decodable, or no capture at
    *sample_rate* can be decoded (a rate too low for the protocol's
    channel).
    """
    if not is_decodable(signal_class):
        return None
    sc = signal_class.lower().strip()
    rate = _sample_rate(sample_rate)
    if sc in _DMR_CLASSES | _P25_CLASSES:
        from sigrift.lib.dsp.demod import DMR_PRESET, P25_PRESET

        dmr = sc in _DMR_CLASSES
        preset = DMR_PRESET if dmr else P25_PRESET
        if rate < _FSK_MIN_SAMPLES_PER_SYMBOL * preset.symbol_rate:
            return None
        framing = _FRAMINGS["dmr" if dmr else "p25"]
        # A whole frame around its sync, two bits per 4FSK symbol.
        symbols = max(_FSK_MIN_SYMBOLS, (framing.lead + framing.tail) / 2)
        return symbols / preset.symbol_rate
    usable = [bw for bw in _LORA_BANDWIDTHS if bw <= rate <= bw * _MAX_RESAMPLE_TERM]
    if not usable:
        return None
    return _LORA_MIN_FRAME_SYMBOLS * 2**_LORA_MIN_SF / max(usable)


def decode_skip_reason(
    signal_class: Any, n_samples: Any, sample_rate: Any
) -> str | None:
    """Why a capture of *n_samples* at *sample_rate* cannot be decoded, or None.

    Only the first :func:`sigrift.bridge.iq_store.analysis_max_samples`
    samples are decoded, so that is the length that counts.  ``None``
    (go ahead) when *signal_class* is not decodable at all — callers check
    :func:`is_decodable` — or *n_samples* is unknown (``None`` or 0).
    """
    if not is_decodable(signal_class):
        return None
    rate = _sample_rate(sample_rate)
    if not _iq_store.MIN_IQ_SAMPLE_RATE_HZ <= rate <= _iq_store.MAX_IQ_SAMPLE_RATE_HZ:
        return f"sample rate {rate:.0f} Hz is out of range"
    minimum = min_decode_seconds(signal_class, rate)
    if minimum is None:
        return f"sample rate {rate:.0f} Hz is too low for {signal_class}"
    try:
        count = int(n_samples)
    except (TypeError, ValueError):
        return None
    if count <= 0:
        return None
    analysed = min(count, _iq_store.analysis_max_samples())
    seconds = analysed / rate
    if seconds < minimum:
        return (
            f"capture too short for {signal_class}: {seconds * 1e3:.1f} ms "
            f"decoded ({analysed} samples at {rate:.0f} Hz), a frame needs "
            f"{minimum * 1e3:.1f} ms"
        )
    return None


def _sample_rate(value: Any) -> float:
    try:
        rate = float(value)
    except (TypeError, ValueError):
        return _DEFAULT_SAMPLE_RATE
    return rate if math.isfinite(rate) and rate > 0 else _DEFAULT_SAMPLE_RATE


def queue_protocol_decode(
    job_queue: Any,
    *,
    detection_id: str,
    signal_class: Any,
    freq_hz: Any = 0.0,
    node_id: Any = "",
    sample_rate: Any = None,
    tenant_id: str = "default",
    n_samples: Any = None,
) -> str | None:
    """Queue a ``protocol_decode`` job for a detection whose IQ is stored.

    Called once the capture is on disk, so the job always finds its IQ.
    Returns the job id, or ``None`` when the class is not decodable, the
    capture (*n_samples*, when known) cannot hold a frame
    (:func:`decode_skip_reason`; logged at debug level), there is no
    queue / handler, or the queue is full — never raises (decoding is best
    effort and must not fail the upload).  Not idempotent by itself:
    request paths use :func:`queue_protocol_decode_once`.
    """
    if job_queue is None or not detection_id or not is_decodable(signal_class):
        return None
    reason = decode_skip_reason(signal_class, n_samples, sample_rate)
    if reason is not None:
        logger.debug("Protocol decode for %s not queued: %s", detection_id, reason)
        return None
    try:
        freq = float(freq_hz or 0.0)
    except (TypeError, ValueError):
        freq = 0.0
    try:
        return job_queue.submit_nowait(
            "protocol_decode",
            {
                "detection_id": detection_id,
                "signal_class": signal_class,
                "freq_hz": freq if math.isfinite(freq) else 0.0,
                "node_id": node_id if isinstance(node_id, str) else "",
                "sample_rate": _sample_rate(sample_rate),
                "tenant_id": tenant_id,
            },
        )
    except ValueError as exc:  # no protocol_decode handler registered
        logger.debug("Protocol decode job for %s not queued: %s", detection_id, exc)
        return None
    except Exception as exc:  # queue full, queue unusable
        logger.warning(
            "Protocol decode job for %s not queued: %s",
            detection_id,
            exc or type(exc).__name__,
        )
        return None


@dataclass(frozen=True)
class DecodeQueueing:
    """What :func:`queue_protocol_decode_once` did."""

    job_id: str | None = None
    #: Why no job was queued; ``None`` when one was, or when the class is
    #: not decodable at all.
    skipped: str | None = None


async def queue_protocol_decode_once(
    job_queue: Any,
    claims: Any,
    *,
    detection_id: str,
    signal_class: Any,
    freq_hz: Any = 0.0,
    node_id: Any = "",
    sample_rate: Any = None,
    n_samples: Any = None,
    source: str = "",
) -> DecodeQueueing:
    """Queue the ``protocol_decode`` of a detection unless it is queued already.

    Contract K8b: the IQ upload route and post-ingest (the bridge's batch
    and summary ingest, the gateway's ingest hook) both try, because
    either may be the one that sees the detection and its IQ together.
    The first claims the detection in ``detections.db``
    (:meth:`~sigrift.bridge.storage.ingest_claims.IngestClaimStore.claim_decode`,
    shared by every worker process) and queues the job; every later try
    is a no-op.  A claim whose job could not be queued (queue full, no
    handler) is released, so a later try can still queue it.  With
    *claims* ``None`` the job is queued without the check.  Never raises.
    """
    if job_queue is None or not detection_id or not is_decodable(signal_class):
        return DecodeQueueing()
    reason = decode_skip_reason(signal_class, n_samples, sample_rate)
    if reason is not None:
        logger.debug("Protocol decode for %s not queued: %s", detection_id, reason)
        return DecodeQueueing(skipped=reason)
    if claims is not None:
        try:
            claimed = await asyncio.to_thread(
                claims.claim_decode, detection_id, now=time.time(), source=source
            )
        except Exception as exc:
            logger.warning(
                "Protocol decode for %s not queued: claim failed: %s",
                detection_id,
                exc,
            )
            return DecodeQueueing(skipped="decode claim failed")
        if not claimed:
            return DecodeQueueing(skipped="already queued")
    job_id = queue_protocol_decode(
        job_queue,
        detection_id=detection_id,
        signal_class=signal_class,
        freq_hz=freq_hz,
        node_id=node_id,
        sample_rate=sample_rate,
        n_samples=n_samples,
    )
    if job_id is None:
        if claims is not None:
            try:
                await asyncio.to_thread(claims.release_decode, detection_id)
            except Exception:
                logger.warning(
                    "Could not release the decode claim of %s",
                    detection_id,
                    exc_info=True,
                )
        return DecodeQueueing(skipped="not queued")
    return DecodeQueueing(job_id=job_id)


def protocol_decode_job_handler(
    pipeline: ProtocolDecodePipeline, iq_store: Any
) -> Callable[[str, dict], dict]:
    """Build the ``protocol_decode`` analysis-job handler.

    Loads the detection's IQ from *iq_store* and runs *pipeline* on it;
    the result reports how many messages were decoded / stored and
    carries the first records.  At most
    :func:`sigrift.bridge.iq_store.analysis_max_samples` samples (the
    start of the capture) are decoded, so a highly compressible upload
    cannot make every decode job inflate and filter 256 MiB.
    Synchronous (the job queue runs it in a worker thread).
    """

    def _protocol_decode_handler(job_id: str, params: dict) -> dict:
        detection_id = params.get("detection_id", "")
        signal_class = params.get("signal_class", "")
        freq_hz = params.get("freq_hz", 0.0)
        node_id = params.get("node_id", "")
        tenant_id = params.get("tenant_id", "default")
        sample_rate = _sample_rate(params.get("sample_rate", _DEFAULT_SAMPLE_RATE))
        iq_data = None
        if iq_store is not None and detection_id:
            iq_data = iq_store.load_iq(
                detection_id, max_samples=_iq_store.analysis_max_samples()
            )
        if iq_data is None or len(iq_data) < 256:
            return {"status": "skipped", "reason": "no IQ data"}
        reason = decode_skip_reason(signal_class, len(iq_data), sample_rate)
        if reason is not None:
            # Not "decoded" with no messages: the capture cannot hold a frame.
            return {"status": "skipped", "reason": reason}
        try:
            results = pipeline.decode_iq(
                iq_data,
                signal_class,
                freq_hz,
                sample_rate,
                node_id,
                tenant_id,
                detection_id=detection_id or None,
            )
        except Exception as exc:
            logger.warning("Protocol decode failed for %s: %s", detection_id, exc)
            return {"status": "error", "error": str(exc)}
        return {
            "status": "decoded",
            "messages": len(results),
            "stored": sum(1 for r in results if r.get("id") is not None),
            "decoded_messages": results[:_JOB_RESULT_MESSAGES],
        }

    return _protocol_decode_handler


# Demod output protocol to decoder mapping
_PROTOCOL_DECODER_MAP = {
    "meshtastic": "meshtastic",
    "dmr": "dmr",
    "p25": "p25",
    "lora": "lora_phy",
}


class ProtocolDecodePipeline:
    """End-to-end pipeline from IQ samples to stored decoded messages.

    Parameters
    ----------
    decoded_store : DecodedMessageStore or None
        Storage backend for decoded messages
        (:class:`sigrift.bridge.storage.decoded_messages.DecodedMessageStore`).
        With ``None`` messages are decoded and returned but not persisted.
    crypto_key_store : KeyStore
        In-memory key store for auto-decryption attempts.
    """

    def __init__(self, decoded_store: Any, crypto_key_store: Any) -> None:
        self._decoded_store = decoded_store
        self._crypto_key_store = crypto_key_store

    def decode_iq(
        self,
        iq_data: np.ndarray,
        signal_class: str,
        freq_hz: float,
        sample_rate: float,
        node_id: str = "",
        tenant_id: str = "default",
        detection_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Run the full decode pipeline on IQ data.

        Parameters
        ----------
        iq_data : np.ndarray
            Complex IQ samples.
        signal_class : str
            Classified signal type (e.g. "meshtastic", "dmr", "p25").
        freq_hz : float
            Center frequency in Hz.
        sample_rate : float
            Sample rate of *iq_data* in Hz.
        node_id : str
            Originating node ID.
        tenant_id : str
            Tenant identifier.
        detection_id : str or None
            Associated detection ID.

        Returns
        -------
        list[dict]
            One record per decoded message, whether or not it could be
            persisted: ``id`` is the stored row id, or ``None`` when there
            is no store or the insert failed.
        """
        sc = signal_class.lower().strip()
        protocol = self._map_signal_to_protocol(sc)

        # Steps 1-2: demodulate and decode
        try:
            messages = self._decode_messages(iq_data, sc, protocol, sample_rate)
        except Exception as exc:
            # Decoding is best effort: one line per failure, the traceback
            # only at debug level.
            logger.warning(
                "Protocol decode failed for signal_class=%s (detection %s): %s: %s",
                signal_class,
                detection_id,
                type(exc).__name__,
                exc,
            )
            logger.debug("Protocol decode traceback", exc_info=True)
            return []

        if not messages:
            return []

        # Step 3: Attempt auto-decryption on encrypted messages
        messages = self._try_auto_decrypt(messages, protocol)

        # Step 4: Persist to store
        stored = self._store_messages(
            messages,
            detection_id,
            freq_hz,
            node_id,
            tenant_id,
        )
        return stored

    # -- Demodulation + decoding ------------------------------------------------

    def _decode_messages(
        self,
        iq_data: np.ndarray,
        signal_class: str,
        protocol: str,
        sample_rate: Any,
    ) -> list[Any]:
        """Demodulate *iq_data* and return the decoded messages."""
        decoder = self._select_decoder(protocol)
        if decoder is None:
            logger.debug("No decoder for protocol=%s", protocol)
            return []
        rate = _sample_rate(sample_rate)
        if (
            not _iq_store.MIN_IQ_SAMPLE_RATE_HZ
            <= rate
            <= _iq_store.MAX_IQ_SAMPLE_RATE_HZ
        ):
            logger.debug("Sample rate %r Hz out of range: not decoded", rate)
            return []
        # Bounded work whatever the caller hands in: the capture's start.
        limit = _iq_store.analysis_max_samples()
        iq = np.ascontiguousarray(
            np.asarray(iq_data).ravel()[:limit], dtype=np.complex64
        )

        if protocol in _FRAMINGS:
            demod = self._select_demodulator(signal_class, rate)
            if demod is None:
                logger.debug("No demodulator for signal_class=%s", signal_class)
                return []
            bits = self._fsk_bits(demod, iq, rate, protocol, limit)
            packets = [
                (decoder, packet)
                for packet in self._decode_frames(decoder, bits, _FRAMINGS[protocol])
            ]
        elif protocol in ("lora_phy", "meshtastic"):
            packets = self._decode_lora(
                iq, signal_class, rate, protocol, decoder, limit
            )
        else:
            return []

        messages: list[Any] = []
        for packet_decoder, packet in packets:
            messages.extend(packet_decoder.extract_messages(packet))
        return messages

    def _fsk_bits(
        self, demod: Any, iq: np.ndarray, rate: float, protocol: str, limit: int
    ) -> np.ndarray:
        """4FSK-demodulate *iq* (``rate`` Hz) into a dibit-mapped bit array.

        At most *limit* samples are demodulated (after resampling).
        """
        from sigrift.lib.dsp.demod import DMR_PRESET, P25_PRESET

        preset = DMR_PRESET if protocol == "dmr" else P25_PRESET
        nothing = np.zeros(0, dtype=np.uint8)
        if rate < _FSK_MIN_SAMPLES_PER_SYMBOL * preset.symbol_rate:
            logger.debug("Sample rate %.0f Hz too low for %s", rate, protocol)
            return nothing
        resampled = _resample(iq, rate, _FSK_DEMOD_RATE, limit)
        if resampled is None:
            logger.debug("Sample rate %.0f Hz not resampled for %s", rate, protocol)
            return nothing
        samples, demod_rate = resampled
        sps = demod_rate / preset.symbol_rate
        if len(samples) < _FSK_MIN_SYMBOLS * sps:
            return nothing
        samples = _channel_filter(samples, demod_rate, _FSK_CHANNEL_CUTOFF_HZ)
        # The demodulator's timing loop adapts slowly and starts its
        # symbol clock at sample ``sps``: start the capture so that this
        # falls on a symbol centre (maximum eye opening).
        samples = samples[_symbol_timing_offset(samples, sps) :]
        demod.sample_rate = demod_rate
        result = demod.demodulate(samples, preset=preset)
        return _dibits(result.symbols)

    def _decode_frames(
        self, decoder: Any, bits: np.ndarray, framing: _Framing
    ) -> list[Any]:
        """Decode every frame of a bit stream, one ``decode_packet`` per frame.

        ``decode_packet`` decodes one frame sync of the bits it is given,
        and reports where it was (``metadata["sync_offset"]``).  The stream
        is fed to it in windows of ``framing.window`` bits; after each
        frame the next window starts right after that frame's sync, and
        windows without a frame overlap by a frame less one bit (a decoder
        may report only syncs whose whole frame it was given).  A decoder
        need not report the *first* sync of a window (DMR prefers
        an error-free sync to an earlier one with tolerated bit errors), so
        the bits before a reported sync are decoded again on their own
        while they can hold the sync of an earlier frame.  A frame the
        window cut off (too close to the window start or end) is decoded
        again from a window that starts ``framing.lead`` bits before its
        sync, unless that would reach back into the previous frame's sync.
        """
        from sigrift.lib.protocol.base import DecodeError, FrameSyncError

        n = len(bits)
        window = framing.window
        frame_bits = framing.lead + framing.tail
        packets: list[Any] = []
        pos = 0
        prev_end = 0
        calls = 0
        # A safety net, not a budget: one call per window without a frame;
        # per frame the window's call, a look for an earlier sync, and a
        # retry with its own look (a few calls more when earlier syncs are
        # found).
        max_calls = 2 * (n // max(1, window - _SYNC_BITS) + 1) + 6 * _MAX_FRAMES

        def decode_at(start: int, length: int) -> Any:
            nonlocal calls
            calls += 1
            return decoder.decode_packet(_pack_bits(bits[start : start + length]))

        def earliest(start: int, min_len: int) -> tuple[Any, int]:
            """Decode the window at *start*; returns (packet, bits it held).

            While the bits before the reported frame (``framing.lead`` bits
            before its sync) are at least *min_len* bits, they are decoded
            on their own (a whole number of bytes, so no padding): a sync
            found there is earlier than the one reported.
            """
            packet = decode_at(start, window)
            span = min(window, n - start)
            while calls < max_calls:
                offset = _sync_offset(packet)
                if offset is None:
                    break
                shorter = (offset - framing.lead) // 8 * 8
                if shorter < min_len:
                    break
                try:
                    earlier = decode_at(start, shorter)
                except DecodeError:
                    break
                found = _sync_offset(earlier)
                if found is None or not 0 <= found < offset:
                    break
                packet, span = earlier, min(shorter, n - start)
            return packet, span

        while pos + _SYNC_BITS <= n and len(packets) < _MAX_FRAMES:
            if calls >= max_calls:
                break
            chunk_len = min(window, n - pos)
            # An earlier sync is worth finding if its frame can be decoded:
            # in the window, or by a retry that does not reach back into
            # the previous frame's sync.
            first_useful = max(0, framing.lead - (pos - prev_end))
            try:
                packet, span = earliest(pos, first_useful + _SYNC_BITS)
            except FrameSyncError:
                packet, span = None, chunk_len
            except DecodeError:
                # A sync near the end of the window, frame cut off: move
                # on so the next window holds the frame.
                if pos + chunk_len >= n:
                    break
                pos += max(1, chunk_len - framing.tail - _SYNC_BITS)
                continue
            offset = _sync_offset(packet)
            if offset is None or offset < 0:
                # No (decodable) sync in this window.  Overlap the next one
                # by a frame less one bit, so every frame lies whole in some
                # window: a decoder that reports only syncs whose frame it
                # was given whole would otherwise never see a frame that
                # straddles the window end.
                if pos + chunk_len >= n:
                    break
                pos += max(1, chunk_len - frame_bits + 1)
                continue
            sync = pos + offset
            in_window = offset >= framing.lead and offset + framing.tail <= span
            start = sync - framing.lead
            if (
                not in_window
                and start >= prev_end
                and start >= 0
                and sync + framing.tail <= n
                and calls < max_calls
            ):
                try:
                    # The frame at ``lead`` must fit whole in the window.
                    retry, _span = earliest(start, frame_bits)
                except DecodeError:
                    retry = None
                if _sync_offset(retry) == framing.lead:
                    packet = retry
            packets.append(packet)
            prev_end = sync + _SYNC_BITS
            pos = prev_end
        return packets

    def _decode_lora(
        self,
        iq: np.ndarray,
        signal_class: str,
        rate: float,
        protocol: str,
        decoder: Any,
        limit: int,
    ) -> list[tuple[Any, Any]]:
        """LoRa CSS demodulation and PHY decoding (see the module docstring).

        Returns ``(decoder, packet)`` pairs: the PHY packet for plain LoRa,
        the Meshtastic packet decoded from a verified PHY payload for
        Meshtastic classes.
        """
        wideband = self._select_demodulator(signal_class, rate)
        if wideband is None:
            logger.debug("No demodulator for signal_class=%s", signal_class)
            return []
        # Bandwidths the capture holds and can be decimated to.
        usable = [
            bw for bw in _LORA_BANDWIDTHS if bw <= rate <= bw * _MAX_RESAMPLE_TERM
        ]
        if not usable:
            logger.debug("Sample rate %.0f Hz not usable for LoRa", rate)
            return []
        if len(usable) == 1 or len(iq) < 64:
            bw = usable[0]
        else:
            bw = min(
                usable, key=lambda b: abs(b - float(wideband.detect_bandwidth(iq)))
            )
        resampled = _resample(iq, rate, bw, limit)
        if resampled is None:
            return []
        samples, chip_rate = resampled
        demod = type(wideband)(sample_rate=chip_rate)
        result = demod.demodulate(samples, bw=chip_rate)
        if not getattr(result, "preamble_detected", False):
            return []
        symbols = _lora_frame_symbols(np.asarray(result.symbols))
        if symbols.size == 0:
            return []
        phy = decoder if protocol == "lora_phy" else self._select_decoder("lora_phy")
        if phy is None:
            return []
        packet = phy.decode_packet(_pack_symbols(symbols, int(result.sf)), sf=result.sf)
        if not _lora_frame_verified(packet):
            logger.debug(
                "LoRa frame not verified (sf=%s): %s", result.sf, packet.errors
            )
            return []
        if protocol == "lora_phy":
            return [(phy, packet)]
        return [(decoder, decoder.decode_packet(packet.payload))]

    def _select_demodulator(
        self, signal_class: str, sample_rate: float | None = None
    ) -> Any | None:
        """Return the demodulator for a signal class (``None`` if none).

        LoRa classes get a :class:`LoRaCSSDemodulator` at *sample_rate*;
        DMR / P25 a :class:`FSKDemodulator` at :data:`_FSK_DEMOD_RATE`
        (the pipeline resamples to it).  Their ``demodulate`` methods take
        the IQ plus ``sf`` / ``bw`` (LoRa) or ``preset`` (FSK) — never a
        sample rate, which is a constructor argument.
        """
        rate = _sample_rate(sample_rate)
        if signal_class in _LORA_CLASSES:
            try:
                from sigrift.lib.dsp.demod import LoRaCSSDemodulator

                return LoRaCSSDemodulator(sample_rate=rate)
            except ImportError:
                logger.warning("LoRaCSSDemodulator not available")
                return None

        if signal_class in _DMR_CLASSES | _P25_CLASSES:
            try:
                from sigrift.lib.dsp.demod import FSKDemodulator

                return FSKDemodulator(sample_rate=_FSK_DEMOD_RATE)
            except ImportError:
                logger.warning("FSKDemodulator not available")
                return None

        # DECT has a demodulator preset but no protocol decoder.
        return None

    def _select_decoder(self, protocol: str) -> Any | None:
        """Select the appropriate protocol decoder."""
        if protocol == "meshtastic":
            try:
                from sigrift.lib.protocol.meshtastic import MeshtasticDecoder

                return MeshtasticDecoder()
            except ImportError:
                logger.warning("MeshtasticDecoder not available")
                return None

        if protocol == "dmr":
            try:
                from sigrift.lib.protocol.dmr import DMRDecoder

                return DMRDecoder()
            except ImportError:
                logger.warning("DMRDecoder not available")
                return None

        if protocol == "p25":
            try:
                from sigrift.lib.protocol.p25 import P25Decoder

                return P25Decoder()
            except ImportError:
                logger.warning("P25Decoder not available")
                return None

        if protocol == "lora_phy":
            try:
                from sigrift.lib.protocol.lora_phy import LoRaPhyDecoder

                return LoRaPhyDecoder()
            except ImportError:
                logger.warning("LoRaPhyDecoder not available")
                return None

        return None

    def _map_signal_to_protocol(self, signal_class: str) -> str:
        """Map a signal class to a protocol name for decoder lookup."""
        if signal_class in _MESHTASTIC_CLASSES:
            return "meshtastic"
        if signal_class in _LORA_CLASSES:
            return "lora_phy"
        if signal_class in _DMR_CLASSES:
            return "dmr"
        if signal_class in _P25_CLASSES:
            return "p25"
        return signal_class

    def _try_auto_decrypt(
        self,
        messages: list[Any],
        protocol: str,
    ) -> list[Any]:
        """Try to auto-decrypt encrypted messages using stored keys."""
        if self._crypto_key_store is None:
            return messages

        # Map protocol to decryption protocol names
        decrypt_protocol_map = {
            "meshtastic": "meshtastic",
            "dmr": "dmr_basic",
            "p25": "p25_phase1",
        }
        decrypt_proto = decrypt_protocol_map.get(protocol)
        if decrypt_proto is None:
            return messages

        keys = self._crypto_key_store.lookup_by_protocol(protocol)
        if not keys:
            return messages

        key_tuples = [(bytes(k.key_material), k.key_id) for k in keys]

        for msg in messages:
            if not getattr(msg, "decrypted", False) and msg.payload:
                try:
                    from sigrift.lib.crypto.aes_decrypt import try_decrypt

                    params: dict[str, Any] = {}
                    # Meshtastic needs packet_id and source_node from metadata
                    if protocol == "meshtastic" and hasattr(msg, "metadata"):
                        md = msg.metadata
                        if "packet_id" in md:
                            params["packet_id"] = md["packet_id"]
                        if "source_node" in md:
                            params["source_node"] = md["source_node"]

                    result = try_decrypt(
                        ciphertext=msg.payload,
                        protocol=decrypt_proto,
                        keys=key_tuples,
                        **params,
                    )
                    if result is not None and result.error is None:
                        msg.decrypted = True
                        msg.decrypted_payload = result.plaintext
                        msg.key_id = result.key_id
                        logger.debug(
                            "Auto-decrypted %s message with key %s (confidence=%.2f)",
                            protocol,
                            result.key_id,
                            result.confidence,
                        )
                except Exception:
                    logger.exception(
                        "Auto-decrypt failed for %s message",
                        protocol,
                    )

        return messages

    def _store_messages(
        self,
        messages: list[Any],
        detection_id: str | None,
        freq_hz: float,
        node_id: str,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Build a record per decoded message and persist it when a store is set.

        Returns
        -------
        list[dict]
            Every decoded message's record (``id`` None when not stored).
        """
        if self._decoded_store is None:
            logger.debug("No decoded store configured — messages are not persisted")

        now = datetime.now(timezone.utc).isoformat()
        records: list[dict[str, Any]] = []
        stored = 0

        for msg in messages:
            try:
                payload_hex = msg.payload.hex() if msg.payload else ""
                record = {
                    "detection_id": detection_id,
                    "protocol": msg.protocol,
                    "source_id": getattr(msg, "source_id", None),
                    "dest_id": getattr(msg, "dest_id", None),
                    "message_type": getattr(msg, "message_type", None),
                    "payload_hex": payload_hex,
                    "payload_length": len(msg.payload) if msg.payload else 0,
                    "encrypted": not getattr(msg, "decrypted", False)
                    and bool(payload_hex),
                    "decrypted_payload": (
                        msg.decrypted_payload.hex()
                        if getattr(msg, "decrypted_payload", None)
                        else None
                    ),
                    "key_id": getattr(msg, "key_id", None),
                    "gps_lat": getattr(msg, "gps_lat", None),
                    "gps_lon": getattr(msg, "gps_lon", None),
                    "confidence": getattr(msg, "confidence", None),
                    "freq_hz": freq_hz,
                    "node_id": node_id,
                    "text": getattr(msg, "text", None),
                    "metadata": getattr(msg, "metadata", None) or None,
                    "tenant_id": tenant_id,
                    "timestamp": now,
                    "id": None,
                }
            except Exception:
                logger.exception(
                    "Failed to build record for decoded %s message",
                    getattr(msg, "protocol", "?"),
                )
                continue
            records.append(record)

        store_many = getattr(self._decoded_store, "store_messages", None)
        if records and callable(store_many):
            # One transaction for the whole decode.
            try:
                ids = store_many(records)
            except Exception:
                logger.exception("Failed to store %d decoded messages", len(records))
                ids = []
            for record, msg_id in zip(records, ids):
                record["id"] = msg_id
            stored = sum(1 for record in records if record["id"] is not None)
        elif self._decoded_store is not None:
            for record in records:
                try:
                    record["id"] = self._decoded_store.store_message(record)
                    stored += 1
                except Exception:
                    logger.exception(
                        "Failed to store decoded %s message",
                        record["protocol"],
                    )

        logger.debug(
            "Stored %d/%d decoded messages for detection %s",
            stored,
            len(messages),
            detection_id,
        )
        return records


# ---------------------------------------------------------------------------
# Signal-conditioning and framing helpers
# ---------------------------------------------------------------------------


def _resample(
    iq: np.ndarray, rate: float, target: float, max_out: int
) -> tuple[np.ndarray, float] | None:
    """Resample *iq* from *rate* to (about) *target* Hz with an anti-alias FIR.

    Returns the samples and their exact rate (``rate * up / down`` for
    the rational factor used), or ``None`` when that needs more than
    :data:`_MAX_UPSAMPLE` x interpolation or :data:`_MAX_RESAMPLE_TERM` x
    decimation.  Both terms of the factor stay within about
    :data:`_MAX_RESAMPLE_TERM` (the FIR has ~20 x max(up, down) taps), and
    at most *max_out* samples are produced (from the start of *iq*): the
    cost is bounded whatever rate the capture claims.
    """
    if not (rate > 0 and target > 0 and max_out > 0):
        return None
    ratio = target / rate
    if abs(ratio - 1.0) <= 1e-9:
        return iq[:max_out], rate
    if not 1.0 / _MAX_RESAMPLE_TERM <= ratio <= _MAX_UPSAMPLE:
        return None
    # Bounding the denominator by TERM / ratio bounds the numerator (about
    # ratio x denominator) by TERM too.  For ratio >= 1 / TERM the best
    # approximation is never 0.
    factor = Fraction(ratio).limit_denominator(
        max(1, int(_MAX_RESAMPLE_TERM / max(1.0, ratio)))
    )
    up, down = factor.numerator, factor.denominator
    if up <= 0 or max(up, down) > 2 * _MAX_RESAMPLE_TERM:
        return None
    n_in = min(len(iq), max_out * down // up)
    if n_in <= 0:
        return None
    from scipy.signal import resample_poly

    out = resample_poly(iq[:n_in], up, down)[:max_out]
    return np.ascontiguousarray(out, dtype=np.complex64), rate * up / down


def _channel_filter(iq: np.ndarray, rate: float, cutoff_hz: float) -> np.ndarray:
    """Low-pass *iq* to +-*cutoff_hz* (linear phase, same length)."""
    if cutoff_hz >= rate / 2:
        return iq
    from scipy.signal import firwin, oaconvolve

    taps = firwin(_FSK_CHANNEL_TAPS, cutoff_hz, fs=rate)
    return oaconvolve(iq, taps, mode="same").astype(np.complex64)


def _symbol_timing_offset(iq: np.ndarray, sps: float) -> int:
    """Samples to drop so a symbol clock starting at sample *sps* hits centres.

    Picks the sampling phase with the largest mean squared instantaneous
    frequency (the widest eye) over the capture.
    """
    period = int(round(sps))
    if period < 2 or len(iq) < 4 * period:
        return 0
    freq = np.angle(iq[1:] * np.conj(iq[:-1]))
    n_symbols = int((len(freq) - period) / sps)
    if n_symbols < 4:
        return 0
    instants = np.arange(n_symbols) * sps
    energy = [
        float(np.mean(freq[(instants + phase).astype(np.int64)] ** 2))
        for phase in range(period)
    ]
    return int(np.argmax(energy))


def _dibits(symbols: Any) -> np.ndarray:
    """Map 4FSK symbols (+3 / +1 / -1 / -3) to bits, two per symbol."""
    sym = np.asarray(symbols, dtype=np.int64).ravel()
    if sym.size == 0:
        return np.zeros(0, dtype=np.uint8)
    high = sym < 0  # -1 -> 10, -3 -> 11
    low = np.abs(sym) >= 2  # +3 -> 01, -3 -> 11
    return np.column_stack((high, low)).astype(np.uint8).ravel()


def _pack_bits(bits: np.ndarray) -> bytes:
    """Pack a 0/1 array MSB-first into bytes (zero-padded to a byte)."""
    return np.packbits(np.asarray(bits, dtype=np.uint8)).tobytes()


def _pack_symbols(symbols: np.ndarray, sf: int) -> bytes:
    """Pack LoRa symbols as *sf*-bit values, MSB-first (``LoRaPhyDecoder`` input)."""
    sym = np.asarray(symbols, dtype=np.int64).ravel() & ((1 << sf) - 1)
    shifts = np.arange(sf - 1, -1, -1)
    bits = ((sym[:, None] >> shifts) & 1).astype(np.uint8).ravel()
    return _pack_bits(bits)


def _sync_offset(packet: Any) -> int | None:
    """Bit offset of the frame sync a decoded packet reports, if any."""
    metadata = getattr(packet, "metadata", None)
    if not isinstance(metadata, dict):
        return None
    offset = metadata.get("sync_offset")
    if isinstance(offset, bool) or not isinstance(offset, int):
        return None
    return offset


def _lora_frame_symbols(symbols: np.ndarray) -> np.ndarray:
    """Symbols from the LoRa header on: skip preamble, sync word and SFD.

    The preamble is the first run of at least eight identical symbols;
    two sync-word symbols and the 2.25-symbol SFD follow it.
    """
    run = 1
    for i in range(1, len(symbols)):
        if symbols[i] == symbols[i - 1]:
            run += 1
            continue
        if run >= _LORA_MIN_PREAMBLE:
            return symbols[i + _LORA_SYNC_SYMBOLS + _LORA_SFD_BLOCKS :]
        run = 1
    return symbols[:0]


def _lora_frame_verified(packet: Any) -> bool:
    """True when a LoRa PHY frame passed its header check and payload CRC."""
    metadata = getattr(packet, "metadata", None) or {}
    header = metadata.get("header")
    return (
        bool(getattr(packet, "payload", b""))
        and isinstance(header, dict)
        and header.get("header_ok") is True
        and metadata.get("crc_ok") is True
    )
