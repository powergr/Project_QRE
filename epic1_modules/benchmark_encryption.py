# benchmark_encryption.py
import os
import time
import uuid
from statistics import mean, stdev
import platform  # For OS and Python info
import psutil    # For CPU and Memory info

# For getting package versions reliably on Python 3.8+
from importlib.metadata import version as get_package_version, PackageNotFoundError

# Import your existing Vault-integrated encryption modules
# Ensure these files are in the same directory or your PYTHONPATH is set
try:
    from parallel_encryption_vault import parallel_encrypt_vault, parallel_decrypt_vault, KEM_ALGORITHM_PARALLEL
    from layered_encryption_vault import layered_encrypt_vault, layered_decrypt_vault, KEM_ALGORITHM_LAYERED
    # key_vault_manager is used by the encryption functions, so not directly called here for benchmarking crypto
    from key_vault_manager import VAULT_ADDR_ENV, VAULT_TOKEN_ENV # For env var check
except ImportError as e:
    print(f"ImportError: {e}. Make sure all required .py files (parallel_encryption_vault.py, "
          "layered_encryption_vault.py, key_vault_manager.py) are in the current directory "
          "or Python path.")
    exit(1)

# --- Configuration ---
DATA_SIZE_MB = 1
DATA_SIZE_BYTES = DATA_SIZE_MB * 1024 * 1024
NUM_ITERATIONS = 100  # Number of times to run each operation for averaging
TARGET_MS_PER_OP = 100

# --- Helper Functions ---
def generate_test_data(size_bytes: int) -> bytes:
    """Generates a block of random data."""
    print(f"Generating {size_bytes / (1024*1024):.2f} MB of random test data...")
    return os.urandom(size_bytes)

def check_vault_env_vars():
    """Checks if Vault environment variables are set."""
    if not (os.environ.get(VAULT_ADDR_ENV) and os.environ.get(VAULT_TOKEN_ENV)):
        print(f"ERROR: VAULT_ADDR and VAULT_TOKEN environment variables must be set.")
        print("Please start Vault dev server and export these variables.")
        exit(1)
    print("Vault environment variables seem to be set.")

def get_system_info() -> dict:
    """Gathers system and library version information."""
    info = {}
    try:
        import oqs  # oqs needs to be imported to call its specific version function
        info['oqs_python_version_api'] = oqs.oqs_python_version()  # Version from its own API
    except ImportError:
        info['oqs_python_version_api'] = "oqs package not found or failed to import"
    except AttributeError:
        info['oqs_python_version_api'] = "oqs.oqs_python_version() attribute not found"

    info['python_version'] = platform.python_version()
    info['platform_details'] = platform.platform() # More detailed OS info
    info['architecture'] = platform.machine() + ", " + platform.architecture()[0]

    # CPU info
    info['cpu_model'] = platform.processor() # Often a good summary
    info['cpu_logical_cores'] = psutil.cpu_count(logical=True)
    info['cpu_physical_cores'] = psutil.cpu_count(logical=False)
    try:
        cpu_freq = psutil.cpu_freq()
        info['cpu_current_freq_mhz'] = f"{cpu_freq.current:.0f}" if cpu_freq and hasattr(cpu_freq, 'current') and cpu_freq.current else "N/A"
        info['cpu_max_freq_mhz'] = f"{cpu_freq.max:.0f}" if cpu_freq and hasattr(cpu_freq, 'max') and cpu_freq.max else "N/A"
    except Exception:
        info['cpu_freq_note'] = "Could not read CPU frequency (permissions or unsupported)"

    # Memory info
    mem = psutil.virtual_memory()
    info['total_ram_gb'] = f"{mem.total / (1024**3):.2f} GB"

    # Library versions using importlib.metadata.version
    packages_to_version = {
        'cryptography': 'cryptography_version',
        'hvac': 'hvac_version',
        'oqs': 'oqs_pip_installed_version',  # Version as per pip installation
        'psutil': 'psutil_version',
    }

    for pkg_name, info_key in packages_to_version.items():
        try:
            info[info_key] = get_package_version(pkg_name)
        except PackageNotFoundError:
            info[info_key] = f"{pkg_name} package not found"
        except Exception as e: 
            info[info_key] = f"Error getting {pkg_name} version: {e}"

    info['openssl_version_note'] = "For linked OpenSSL, check 'openssl version' in your environment."
    return info

def benchmark_operation(op_name: str, func, *args) -> tuple[float, float]:
    """
    Benchmarks a given function over NUM_ITERATIONS.
    Returns average time in milliseconds and standard deviation.
    """
    times = []
    print(f"\nBenchmarking: {op_name} ({NUM_ITERATIONS} iterations)...")
    # Optional: Warm-up run if operations are extremely short and you want to stabilize CPU state, JIT, etc.
    # if NUM_ITERATIONS > 10:
    #     try:
    #         func(*args) # One warm-up call
    #     except Exception:
    #         pass # Ignore errors in warm-up, focus on benchmarked calls

    for i in range(NUM_ITERATIONS):
        start_time = time.perf_counter()
        try:
            func(*args)
        except Exception as e:
            print(f"ERROR during {op_name} iteration {i+1}: {e}")
            # Decide if you want to skip this timing or record a failure marker
            # For now, let it raise if it's a persistent issue after setup.
            # If an error occurs here after setup, it might indicate an issue with the crypto function itself.
            # For this benchmark, we assume setup calls prepare valid inputs.
            raise # Re-raise the exception to stop the benchmark if a crypto op fails mid-way
        end_time = time.perf_counter()
        times.append((end_time - start_time) * 1000)  # Convert to milliseconds
        if (i + 1) % (NUM_ITERATIONS // 10 or 1) == 0: # Print progress every 10%
            print(f"  Completed iteration {i+1}/{NUM_ITERATIONS}")
            
    if not times: # Should not happen if NUM_ITERATIONS > 0 and no errors
        return 0.0, 0.0

    avg_time = mean(times)
    std_dev_time = stdev(times) if len(times) > 1 else 0.0
    print(f"Finished benchmarking {op_name}.")
    return avg_time, std_dev_time

def print_report_line(op_name: str, avg_time_ms: float, std_dev_ms: float, target_ms: float):
    """Prints a formatted line for the benchmark report."""
    status = "PASSED" if avg_time_ms < target_ms else "FAILED"
    print(f"| {op_name:<50} | {avg_time_ms:>15.3f} ms | {std_dev_ms:>15.3f} ms | {status:<8} |")


# --- Main Benchmarking Logic ---
if __name__ == "__main__":
    report_width = 90 # Adjusted width
    print("="*report_width)
    print("Starting Encryption Performance Benchmark (Ticket 6)")
    print("="*report_width)

    check_vault_env_vars()

    # 1. Gather System Info
    system_info = get_system_info()
    print("\n--- System Information ---")
    for key, value in system_info.items():
        # Simple title case for keys, replace underscores
        formatted_key = key.replace('_', ' ').title()
        print(f"{formatted_key:<35}: {value}")
    print("--- End System Information ---\n")

    # 2. Generate Test Data
    test_plaintext = generate_test_data(DATA_SIZE_BYTES)
    print(f"Test data generated ({len(test_plaintext)} bytes).")

    # 3. Pre-generate keys and store them in Vault for consistent decryption tests
    #    The encrypt functions already store keys in Vault.
    #    We do an initial encryption run to get valid ciphertexts for decryption benchmarks.
    parallel_ciphertext = None
    layered_ciphertext = None

    print("\nPreparing for Parallel Encryption Benchmark (initial encryption for setup)...")
    try:
        parallel_ciphertext = parallel_encrypt_vault(test_plaintext)
        print(f"Parallel encryption setup complete. Ciphertext length: {len(parallel_ciphertext)}")
    except Exception as e:
        print(f"ERROR during parallel encryption setup: {e}")
        print("Please ensure parallel_encryption_vault.py is working and Vault is accessible.")
        exit(1)

    print("\nPreparing for Layered Encryption Benchmark (initial encryption for setup)...")
    try:
        layered_ciphertext = layered_encrypt_vault(test_plaintext)
        print(f"Layered encryption setup complete. Ciphertext length: {len(layered_ciphertext)}")
    except Exception as e:
        print(f"ERROR during layered encryption setup: {e}")
        print("Please ensure layered_encryption_vault.py is working and Vault is accessible.")
        exit(1)

    # --- Run Benchmarks ---
    results = []

    # Parallel Encryption
    op_name_pe = "Parallel Encrypt (Vault, Concurrent AES, 1MB)"
    avg_parallel_enc, std_parallel_enc = benchmark_operation(
        op_name_pe, parallel_encrypt_vault, test_plaintext
    )
    results.append((op_name_pe, avg_parallel_enc, std_parallel_enc))

    op_name_pd = "Parallel Decrypt (Vault, C1 path, 1MB)"
    avg_parallel_dec, std_parallel_dec = benchmark_operation(
        op_name_pd, parallel_decrypt_vault, parallel_ciphertext
    )
    results.append((op_name_pd, avg_parallel_dec, std_parallel_dec))
    
    # Layered Encryption
    op_name_le = "Layered Encrypt (Vault, 1MB)"
    avg_layered_enc, std_layered_enc = benchmark_operation(
        op_name_le, layered_encrypt_vault, test_plaintext
    )
    results.append((op_name_le, avg_layered_enc, std_layered_enc))

    op_name_ld = "Layered Decrypt (Vault, 1MB)"
    avg_layered_dec, std_layered_dec = benchmark_operation(
        op_name_ld, layered_decrypt_vault, layered_ciphertext
    )
    results.append((op_name_ld, avg_layered_dec, std_layered_dec))

    # --- Print Report ---
    print("\n" + "="*report_width)
    print("Benchmark Report (Target < 100ms per operation)")
    print("="*report_width)
    print(f"Data Size: {DATA_SIZE_MB} MB")
    print(f"Iterations per operation: {NUM_ITERATIONS}")
    print(f"Target Performance: < {TARGET_MS_PER_OP} ms")
    print("-"*report_width)
    # Adjusted column name to fit new max op_name length
    header = f"| {'Operation':<50} | {'Avg Time (ms)':>15} | {'Std Dev (ms)':>15} | {'Status':<8} |"
    print(header)
    # Dynamic separator based on header length, accounting for column separators
    separator_line = f"|{'-'*(50+2)}|{'-'*(15+2)}|{'-'*(15+2)}|{'-'*(8+2)}|" 
    print(separator_line.replace(' ', '-')) # Ensure it's all dashes
    
    all_passed = True
    for op_name, avg_time, std_dev in results:
        print_report_line(op_name, avg_time, std_dev, TARGET_MS_PER_OP)
        if avg_time >= TARGET_MS_PER_OP:
            all_passed = False
    print(separator_line.replace(' ', '-'))
    print("-"*report_width)


    if all_passed:
        print("\nAll operations met the performance target!")
    else:
        print("\nOne or more operations FAILED to meet the performance target.")
        print("Consider profiling the slower operations (e.g., using cProfile).")
        print("Example: python -m cProfile -o profile.out your_script_to_profile.py")
        print("Then visualize with: snakeviz profile.out")
    
    print("\nBenchmark finished.")
    print("Reminder: liboqs C library version (often shown in UserWarnings) is also relevant for performance.")