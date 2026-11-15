"""Incremental weighted complete-vector generation with private NumPy RNG."""

import numpy as np

from cyberguard.features.nf_cse import MAX_COUNTER
from cyberguard.simulation import GENERATOR_VERSION, PROFILE_VERSION
from cyberguard.simulation.schemas import GeneratorConfig
from cyberguard.simulation.validation import record_from_vector


class TrafficGenerator:
    def __init__(self, profiles, config: GeneratorConfig):
        self.profiles, self.config = profiles, config
        self.rng = np.random.default_rng(config.seed)
        self.perturb_rng = np.random.default_rng(
            np.random.SeedSequence(config.seed, spawn_key=(1,))
        )
        self.sequence = 0
        self.remaining = [config.benign_count, config.count - config.benign_count]
        self.samplers = {}
        # Memory proportional to compact profiles, never to requested output size.
        for label in (0, 1):
            if not self.remaining[label]:
                continue
            selected = []
            for start in range(0, len(profiles.labels), 50000):
                stop = min(start + 50000, len(profiles.labels))
                vectors = profiles.vectors[start:stop]
                mask = profiles.labels[start:stop] == label
                if config.protocols:
                    mask &= np.isin(vectors[:, 0], config.protocols)
                if config.destination_ports:
                    # Nontransport raw-zero placeholder is not a service port.
                    mask &= np.isin(vectors[:, 0], [6, 17]) & np.isin(
                        vectors[:, 2], config.destination_ports
                    )
                selected.append(np.flatnonzero(mask) + start)
            indices = np.concatenate(selected)
            if not len(indices):
                raise ValueError(
                    f"No {'benign' if label == 0 else 'attack'} support after restrictions"
                )
            cumulative = np.cumsum(profiles.weights[indices], dtype=np.uint64)
            if cumulative[-1] == 0 or cumulative[-1] > np.iinfo(np.int64).max:
                raise ValueError("Empty/overflowing profile weights")
            self.samplers[label] = indices, cumulative

    def __iter__(self):
        return self

    def __next__(self):
        left = sum(self.remaining)
        if not left:
            raise StopIteration
        label = 0 if self.rng.integers(left) < self.remaining[0] else 1
        indices, cumulative = self.samplers[label]
        pick = np.searchsorted(
            cumulative, np.uint64(self.rng.integers(int(cumulative[-1]))), side="right"
        )
        vector = self.profiles.vectors[indices[pick]].copy()
        if self.config.mode == "synthetic":
            # A conditional anchor fixes profile, protocol, service and source port.
            # One shared factor preserves directional coupling/ratios approximately.
            # Structural zeros stay zero; positive counts stay positive. No MTU,
            # bytes/packet bound or packet-size model is assumed.
            maximum = int(vector[3:].max())
            upper = (
                min(1 + self.config.perturbation, MAX_COUNTER / maximum)
                if maximum
                else 1 + self.config.perturbation
            )
            factor = self.perturb_rng.uniform(1 - self.config.perturbation, upper)
            for i in range(3, 7):
                if vector[i]:
                    vector[i] = min(MAX_COUNTER, max(1, round(int(vector[i]) * factor)))
        result = {
            "record": record_from_vector(vector),
            "simulation": {
                "mode": self.config.mode,
                "source_profile": "benign" if label == 0 else "attack",
                "sequence": self.sequence,
                "generator_version": GENERATOR_VERSION,
                "profile_version": PROFILE_VERSION,
            },
        }
        self.remaining[label] -= 1
        self.sequence += 1
        return result
