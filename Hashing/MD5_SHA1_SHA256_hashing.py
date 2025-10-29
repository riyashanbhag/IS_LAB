"""
LAB 5 — Exercise 3
----------------------------
Objective:
To analyze the performance of MD5, SHA-1, and SHA-256 hashing techniques
in terms of computation time and collision resistance.

Steps Implemented:
1. Generate random dataset of strings (size: 50–100 strings)
2. Compute hash values using MD5, SHA-1, and SHA-256
3. Measure computation time for each hashing algorithm
4. Check for collisions (same hash value for different inputs)
5. Compare and display results
"""

import hashlib
import random
import string
import time

# -----------------------------------
# Step 1: Generate Random Dataset
# -----------------------------------
def generate_random_strings(n, length=10):
    """Generate a list of random strings of given length."""
    dataset = []
    for _ in range(n):
        text = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(text)
    return dataset


# -----------------------------------
# Step 2: Hashing and Performance Measurement
# -----------------------------------
def compute_hashes(dataset, algorithm):
    """Compute hashes using the given algorithm and measure performance."""
    start_time = time.time()
    hashes = []
    for data in dataset:
        if algorithm == 'MD5':
            hash_val = hashlib.md5(data.encode()).hexdigest()
        elif algorithm == 'SHA1':
            hash_val = hashlib.sha1(data.encode()).hexdigest()
        elif algorithm == 'SHA256':
            hash_val = hashlib.sha256(data.encode()).hexdigest()
        hashes.append(hash_val)
    end_time = time.time()
    return hashes, (end_time - start_time)


# -----------------------------------
# Step 3: Collision Detection
# -----------------------------------
def detect_collisions(hashes):
    """Return number of collisions in the given hash list."""
    unique_hashes = set(hashes)
    collisions = len(hashes) - len(unique_hashes)
    return collisions


# -----------------------------------
# Step 4: Main Experiment
# -----------------------------------
if __name__ == "__main__":
    print("\n--- Hash Function Performance and Collision Analysis ---")

    # Generate random dataset (between 50–100 strings)
    n = random.randint(50, 100)
    dataset = generate_random_strings(n)
    print(f"\nGenerated Dataset Size: {n} strings")

    # Analyze for each hashing algorithm
    results = []

    for algo in ['MD5', 'SHA1', 'SHA256']:
        hashes, duration = compute_hashes(dataset, algo)
        collisions = detect_collisions(hashes)
        results.append((algo, duration, collisions))

    # Display Results
    print("\nAlgorithm\tTime Taken (seconds)\tCollisions Found")
    print("----------------------------------------------------------")
    for algo, duration, collisions in results:
        print(f"{algo}\t\t{duration:.6f}\t\t\t{collisions}")

    print("\n✅ Experiment Completed Successfully!")

    # Observation Summary
    print("\n--- Observations ---")
    print("1. MD5 is generally the fastest but least secure (prone to collisions).")
    print("2. SHA-1 is slower but more secure than MD5.")
    print("3. SHA-256 takes the longest time but provides highest collision resistance.")
