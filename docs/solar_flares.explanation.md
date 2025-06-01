# Understanding Solar Flare Data as an Entropy Source (Proof of Concept)

## Introduction

This document explains how solar flare data, specifically from NOAA's Geostationary Operational Environmental Satellites (GOES) X-ray sensor API, is used as a source of chaotic data for entropy anchoring in this project's Proof of Concept (PoC). The goal is to leverage the inherent unpredictability of these natural phenomena to contribute to the randomness used in cryptographic key generation.

## Data Source: NOAA GOES X-Ray Flares API

*   **API Endpoint:** `https://services.swpc.noaa.gov/json/goes/primary/xray-flares-latest.json`
*   **Data Provided:** This API returns a JSON list of recent solar flare events detected by the primary GOES satellite's X-ray sensor. Each event includes various parameters.
*   **Nature of Solar Flares:** Solar flares are intense bursts of radiation coming from the release of magnetic energy associated with sunspots. They are inherently chaotic and unpredictable in their exact timing, intensity, and detailed characteristics.

## Data Fetching (`data_fetcher.py`)

*   The `data_fetcher.py` script periodically queries the NOAA API.
*   It retrieves the latest flare data (typically a list of recent events).
*   A UTC timestamp of when the data was retrieved is added to the dataset.
*   The entire dataset (list of flares + retrieval timestamp) is stored locally as a JSON file (e.g., `solar_flares_data.json`). This local cache is used by the entropy extraction process.
*   **Scheduling:** For continuous operation, this script is intended to be run on a schedule (e.g., daily via cron or Task Scheduler) to keep the local data cache reasonably up-to-date.

## Entropy Extraction (`entropy_extractor.py`)

The raw JSON data itself is not directly usable as cryptographic entropy. It needs processing to extract randomness.

1.  **Data Selection:** From each flare event in the dataset, specific fields that are likely to exhibit more variability and less predictability are chosen. For this PoC, we focus on:
    *   `peak_time`: The exact timestamp of the flare's peak intensity.
    *   `peak_cflux`: The C-class X-ray flux value at the peak (a measure of intensity). The actual flux values are floating-point numbers.
    *   `class_type`: The classification of the flare (e.g., "C1.8", "M2.0", "X1.5").
    *   Other fields like `begin_time`, `end_time`, `integrated_flux` could also be considered.

2.  **Data Preprocessing & Concatenation:**
    *   The selected string and numeric fields from all recent flare events are converted to strings (if not already) and concatenated into one large string.
    *   This combined string is then encoded into bytes (UTF-8).

3.  **Cryptographic Hashing:**
    *   The resulting byte string is fed into a cryptographic hash function, specifically **SHA3-256**.
    *   SHA3-256 produces a 32-byte (256-bit) digest.
    *   **Why Hashing?**
        *   **Fixed-Size Output:** Hash functions produce a fixed-size output, regardless of the input size, which is suitable for cryptographic keys or seeds.
        *   **Avalanche Effect:** A small change in the input data (e.g., a slightly different peak time or flux value) results in a drastically different hash output, amplifying the unpredictability.
        *   **Uniform Distribution (Approximation):** Good cryptographic hash functions distribute input bits fairly evenly across the output bits, making the output appear random.
        *   **One-Way Property:** It's computationally infeasible to reverse the hash and get back the original solar flare data.

4.  **Quality, Freshness, and Volatility Checks:**
    *   **Freshness:** The `entropy_extractor` checks the `retrieved_at_utc` timestamp from the data file. If the data is older than a defined threshold (e.g., 24 hours), it's considered stale and may not be used directly for entropy.
    *   **Volatility (Rudimentary PoC Check):** A simple check `contains_high_class_flares` is implemented. In this PoC, it looks for the presence of more energetic M-class or X-class flares. The idea is that more significant solar events might represent more "chaotic" or "unpredictable" periods. *This is a highly simplified heuristic for the PoC and would need significant refinement based on heliophysics and statistical analysis for a production system.*
    *   **Basic Entropy Quality Check:** After hashing, a very basic `entropy_quality_check` is performed on the 32-byte digest (e.g., ensuring it's not all zeros, has a minimum number of unique byte values). *This is not a substitute for proper statistical randomness testing (like NIST SP 800-90B).*

## Output

*   If the data passes the freshness and volatility checks, and the resulting hash digest passes the basic quality check, this 32-byte digest is considered the "chaotic entropy" for this PoC.
*   This entropy is then used by the `EntropyManager` (in `secure_prng.py`).

## Limitations and PoC Nature

*   **True Randomness vs. Pseudorandomness:** While solar flares are chaotic, the process of selecting specific data fields and hashing them does not guarantee true, statistically unbiased random numbers in the same way a hardware QRNG might. The hashing step aims to extract and concentrate the unpredictability.
*   **Data Availability and Reliability:** Relies on the NOAA API being available and providing data.
*   **Volatility Heuristic:** The check for M/X class flares is a very basic proxy for "chaotic enough" data and is not scientifically rigorous for entropy quality.
*   **Not a Standalone TRNG/QRNG:** This mechanism is designed to *contribute* entropy to a KDF or seed a PRNG, not to be a full-fledged True Random Number Generator by itself for all cryptographic purposes.

For a production system, much more rigorous analysis of the solar flare data's actual entropy content and more sophisticated extraction and conditioning techniques (as outlined in standards like NIST SP 800-90B) would be essential.