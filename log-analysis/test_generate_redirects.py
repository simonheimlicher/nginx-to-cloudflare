import pytest
import pandas as pd

from constants import (
    HTTP_STATUS_NOT_FOUND,
    HTTP_STATUS_REDIRECT,
    REDIRECT_STATUS,
    REDIRECT_URI,
    REQUEST_METHOD,
    REQUEST_TIMESTAMP,
    REQUEST_URI,
    REQUEST_URI_CANONICAL,
    RESPONSE_STATUS,
    REQUEST_REFERER,
    REQUEST_USER_AGENT,
    ACCESS_COUNT,
)
from generate_redirects import (
    apply_default_redirects,
    apply_canonicalization,
    apply_transformation,
)


# Define the fixture
@pytest.fixture
def df_base():
    # Create and return a DataFrame with the necessary structure
    return pd.DataFrame(
        {
            REQUEST_URI: [""],
            REQUEST_TIMESTAMP: [""],
            REQUEST_METHOD: [""],
            RESPONSE_STATUS: [""],
            REQUEST_REFERER: [""],
            REQUEST_USER_AGENT: [""],
            ACCESS_COUNT: [0],
            REQUEST_URI_CANONICAL: [""],
            REDIRECT_URI: [""],
            REDIRECT_STATUS: HTTP_STATUS_REDIRECT,
        }
    )


canonicalization_tests = [
    (
        "/articles/2011/02/18/time-machine-volume-uuid",
        "/articles/time-machine-volume-uuid/",
    ),
    (
        "/articles/2011/02/18/time-machine-volume-uuid/",
        "/articles/time-machine-volume-uuid/",
    ),
]


@pytest.mark.parametrize("request_uri,expected_redirect_uri", canonicalization_tests)
def test_canonicalization(request_uri, expected_redirect_uri, df_base):
    # Update the DataFrame with test-specific data
    df_base[REQUEST_URI] = [request_uri]

    # Apply the canonicalization function
    df_canonicalized = apply_canonicalization(df_base)

    # Assert the expected output
    assert df_canonicalized[REQUEST_URI_CANONICAL].iloc[0] == expected_redirect_uri


# Validation data
transformation_tests = [
    (r"/publications/forwarding-paradigms", "/research/forwarding-paradigms/"),
    (r"/publications/characterizing-networks", "/research/characterizing-networks/"),
    (r"/publications/dissertation", "/research/dissertation/"),
    (
        r"/publications/heimlicher_e2e-vs-hbh-transport_sigmetrics07.pdf",
        "/research/publications/heimlicher_e2e-vs-hbh-transport_sigmetrics07.pdf",
    ),
    (
        r"/publications/heimlicher_globs_mobihoc10.pdf",
        "/research/publications/heimlicher_globs_mobihoc10.pdf",
    ),
]


@pytest.mark.parametrize(
    "request_uri_canonical,expected_redirect_uri", transformation_tests
)
def test_transformation(request_uri_canonical, expected_redirect_uri, df_base):
    # Transformation rules are only applied after the canonical version
    # of column REQUEST_URI has been added by `apply_canonicalization`
    # to column REQUEST_URI_CANONICAL
    df_base[REQUEST_URI_CANONICAL] = [request_uri_canonical]

    # Apply the transformation function
    df_transformed = apply_transformation(df_base)

    # Assert the expected output
    assert df_transformed[REDIRECT_URI].iloc[0] == expected_redirect_uri


default_tests = [
    (r"/tags/ipad/", r"/technology/"),
    (r"/tags/matlab/", r"/technology/"),
    (r"/tags/time-machine/", r"/technology/"),
]


@pytest.mark.parametrize("request_uri_canonical,expected_redirect_uri", default_tests)
def test_default(request_uri_canonical, expected_redirect_uri, df_base):
    # Default rules must only apply to rows where `REDIRECT_STATUS == HTTP_STATUS_NOT_FOUND`
    df_base[REQUEST_URI_CANONICAL] = [request_uri_canonical]
    df_base[REDIRECT_STATUS] = HTTP_STATUS_NOT_FOUND
    print(df_base)

    # Apply the default function
    df_defaulted = apply_default_redirects(df_base)

    # Assert the expected output
    assert df_defaulted[REDIRECT_URI].iloc[0] == expected_redirect_uri
