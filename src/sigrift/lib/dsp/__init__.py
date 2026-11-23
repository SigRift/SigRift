"""DSP primitives for RF signal processing.

Provides standalone, tested implementations of:
- DC offset removal (IIR high-pass and mean subtraction)
- IQ imbalance estimation and correction (Gram-Schmidt)
- Windowed FFT / PSD / spectrogram
- SNR estimation (M2M4 moments, percentile, eigenvalue)
- OFDM signal generation (with proper DC/Nyquist nulling — pilot bug fixed)
- Channel impairment models (multipath, CFO, phase noise with modulo 2pi, SRO)
- HOS cumulant features (with C21 clamping for low-SNR stability)
- RRC pulse shaping (consolidated from duplicated implementations)
"""

from sigrift.lib.dsp.cumulant_features import cumulant_features
from sigrift.lib.dsp.spectral_features import (
    NUM_DSP_FEATURES,
    compute_dsp_features,
    cp_autocorrelation,
    extended_features,
    nth_power_spectral_peaks,
)
from sigrift.lib.dsp.channel_models import (
    ChannelConfig,
    RTL_SDR_REALISTIC,
    apply_adc_quantization,
    apply_agc_transient,
    apply_cfo,
    apply_channel,
    apply_dc_offset,
    apply_frequency_drift,
    apply_multipath,
    apply_phase_noise,
    apply_sro,
)
from sigrift.lib.dsp.dc_removal import (
    dc_removal_alpha_from_cutoff,
    remove_dc_iir,
    remove_dc_mean,
)
from sigrift.lib.dsp.iq_correction import (
    apply_iq_imbalance,
    correct_iq_imbalance,
    estimate_iq_imbalance,
)
from sigrift.lib.dsp.ofdm import (
    WIFI_64_PILOTS,
    WIFI_256_PILOTS,
    generate_ofdm_signal,
    generate_ofdm_symbol,
)
from sigrift.lib.dsp.snr_estimation import (
    estimate_snr_eigenvalue,
    estimate_snr_m2m4,
    estimate_snr_percentile,
)
from sigrift.lib.dsp.windowing import (
    get_window,
    windowed_fft,
    windowed_psd,
    windowed_spectrogram,
)
from sigrift.lib.dsp.pulse_shaping import rrc_filter, apply_rrc_pulse_shaping
from sigrift.lib.dsp.modulation_params import (
    estimate_symbol_rate,
    estimate_occupied_bandwidth,
    estimate_cfo,
    extract_modulation_params,
)

# Fingerprint encoder/trainer moved to sigrift_sentinel.fingerprint (enterprise plugin).
from sigrift.lib.dsp.preamble_detector import (
    PreambleDetector,
    PreambleMatch,
    SyncPattern,
    _bits_to_symbols,
    _generate_barker,
    _normalized_xcorr,
)
from sigrift.lib.dsp.packet_detector import (
    PacketBoundary,
    PacketDetector,
    TimingAnalysis,
)
from sigrift.lib.dsp.family_classifier import (
    SIGNAL_FAMILIES,
    FamilyTrainer,
    LightweightClassifier,
    get_family,
    get_family_index,
    get_family_names,
    load_family_classifier,
)
from sigrift.lib.dsp.adsb_decoder import (
    ADSBMessage,
    decode_adsb,
    decode_cpr,
    demodulate_ppm,
    extract_messages,
)
from sigrift.lib.dsp.uat_decoder import (
    UATMessage,
    decode_uat_message,
    demodulate_uat,
)
from sigrift.lib.dsp.lora_demodulator import (
    MeshNetworkIntelligence,
    classify_protocol,
    dechirp,
    decode_meshtastic_header,
    decode_meshtastic_protobuf,
    decode_payload,
    demodulate_and_decode,
    extract_header,
    try_decrypt_meshtastic,
)

__all__ = [
    "remove_dc_iir",
    "remove_dc_mean",
    "dc_removal_alpha_from_cutoff",
    "estimate_iq_imbalance",
    "correct_iq_imbalance",
    "apply_iq_imbalance",
    "get_window",
    "windowed_fft",
    "windowed_psd",
    "windowed_spectrogram",
    "estimate_snr_m2m4",
    "estimate_snr_percentile",
    "estimate_snr_eigenvalue",
    "generate_ofdm_symbol",
    "generate_ofdm_signal",
    "WIFI_64_PILOTS",
    "WIFI_256_PILOTS",
    "compute_dsp_features",
    "nth_power_spectral_peaks",
    "cp_autocorrelation",
    "extended_features",
    "NUM_DSP_FEATURES",
    "cumulant_features",
    "ChannelConfig",
    "RTL_SDR_REALISTIC",
    "apply_adc_quantization",
    "apply_agc_transient",
    "apply_cfo",
    "apply_channel",
    "apply_dc_offset",
    "apply_frequency_drift",
    "apply_multipath",
    "apply_phase_noise",
    "apply_sro",
    "rrc_filter",
    "apply_rrc_pulse_shaping",
    "estimate_symbol_rate",
    "estimate_occupied_bandwidth",
    "estimate_cfo",
    "extract_modulation_params",
    "PreambleDetector",
    "PreambleMatch",
    "SyncPattern",
    "_bits_to_symbols",
    "_generate_barker",
    "_normalized_xcorr",
    "PacketBoundary",
    "PacketDetector",
    "TimingAnalysis",
    "SIGNAL_FAMILIES",
    "FamilyTrainer",
    "LightweightClassifier",
    "get_family",
    "get_family_index",
    "get_family_names",
    "load_family_classifier",
    "ADSBMessage",
    "decode_adsb",
    "decode_cpr",
    "demodulate_ppm",
    "extract_messages",
    "UATMessage",
    "decode_uat_message",
    "demodulate_uat",
    "MeshNetworkIntelligence",
    "classify_protocol",
    "dechirp",
    "decode_meshtastic_header",
    "decode_meshtastic_protobuf",
    "decode_payload",
    "demodulate_and_decode",
    "extract_header",
    "try_decrypt_meshtastic",
]
