"""Training-fitted encoders for the restricted network baseline."""

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier

from cyberguard.features.network import (
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    RestrictedNetworkFeatures,
)


def make_network_pipeline(seed: int = 20261115) -> Pipeline:
    """Small fixed baseline. No hyperparameter search or test-set selection."""
    encoding = ColumnTransformer(
        [
            (
                "categories",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                list(CATEGORICAL_FEATURES),
            ),
            ("ports", "passthrough", list(NUMERIC_FEATURES)),
        ],
        remainder="drop",
        verbose_feature_names_out=True,
    )
    return Pipeline(
        [
            ("normalize", RestrictedNetworkFeatures()),
            ("encode", encoding),
            (
                "classifier",
                DecisionTreeClassifier(
                    max_depth=6,
                    max_leaf_nodes=32,
                    min_samples_leaf=5,
                    random_state=seed,
                ),
            ),
        ]
    )
