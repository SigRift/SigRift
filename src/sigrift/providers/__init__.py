"""SigRift provider interfaces — abstract base classes for pluggable features.

Optional add-on packages (e.g. TDOA geolocation, SIEM alerting, audit reports)
implement these interfaces and register via entry points. Core discovers them
at runtime without compile-time knowledge of their existence.
"""
