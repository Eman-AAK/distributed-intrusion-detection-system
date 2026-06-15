# MPI Network Intrusion Detection System

A parallel cybersecurity log analysis system built using MPI (Message Passing Interface) to detect and correlate network attacks within the UNSW-NB15 intrusion detection dataset.

---

## Overview

This project demonstrates the application of parallel and distributed computing techniques to large-scale cybersecurity data analysis. The system distributes network traffic records across multiple MPI processes, enabling faster detection of malicious activity and improved scalability compared to a traditional serial implementation.

The project consists of:

- Parallel attack detection
- Distributed attack correlation
- Serial baseline implementation for performance comparison

---

## Features

### MPI Intrusion Detector

Implemented in:

```text
src/mpi_intrusion_detector.c
```

Capabilities:

- Parallel processing of network logs
- Detection of malicious traffic patterns
- Identification of:
  - DoS attacks
  - Backdoor attacks
  - Reconnaissance attacks
- Workload distribution among MPI processes
- Checksum validation for result consistency
- Execution time measurement

---

### MPI Attack Correlator

Implemented in:

```text
src/mpi_attack_correlator.c
```

Capabilities:

- Cross-process attack correlation
- Suspicious source IP analysis
- Destination port pattern analysis
- Aggregation of attack indicators from distributed nodes
- Security event correlation reporting
- Detailed execution logging

---

### Baseline Detector

Implemented in:

```text
src/baseline_intrusion_detector.c
```

Capabilities:

- Single-process execution
- Baseline performance measurements
- Comparison against MPI implementations

---

## Dataset

The project uses the UNSW-NB15 Network Intrusion Detection Dataset.

Files analyzed include:

```text
UNSW-NB15_1.csv
UNSW-NB15_2.csv
UNSW-NB15_3.csv
UNSW-NB15_4.csv
```

Dataset source:

:contentReference[oaicite:0]{index=0}

---

## Technologies Used

- C Programming
- MPI (OpenMPI / MPICH)
- Parallel Computing
- Distributed Systems
- Cybersecurity Analytics
- Network Traffic Analysis

---

## Project Structure

```text
mpi-network-intrusion-detection/
│
├── src/
│   ├── mpi_intrusion_detector.c
│   ├── mpi_attack_correlator.c
│   └── baseline_intrusion_detector.c
│
├── logs/
│   ├── q1_1_process.txt
│   ├── q1_2_processes.txt
│   ├── q1_4_processes.txt
│   ├── q1_8_processes.txt
│   ├── q2_1_process.txt
│   ├── q2_2_processes.txt
│   ├── q2_4_processes.txt
│   └── q2_8_processes.txt
│
├── report/
│   └── Project_Report.pdf
│
├── README.md
└── .gitignore
```

---

## Compilation

### Compile MPI Intrusion Detector

```bash
mpicc src/mpi_intrusion_detector.c -o intrusion_detector
```

### Compile MPI Attack Correlator

```bash
mpicc src/mpi_attack_correlator.c -o attack_correlator
```

### Compile Baseline Detector

```bash
gcc src/baseline_intrusion_detector.c -o baseline_detector
```

---

## Execution

### Run Intrusion Detector

Using 4 MPI processes:

```bash
mpirun -np 4 ./intrusion_detector
```

### Run Attack Correlator

Using 4 MPI processes:

```bash
mpirun -np 4 ./attack_correlator
```

### Run Baseline Detector

```bash
./baseline_detector
```

---

## Performance Evaluation

The project evaluates:

- Parallel execution speedup
- Scalability across multiple processes
- Detection accuracy
- Load distribution efficiency
- Checksum validation
- Security event correlation effectiveness

Testing was conducted using:

```text
1 Process
2 Processes
4 Processes
8 Processes
```

---

## Learning Outcomes

- MPI process management
- Distributed workload partitioning
- Parallel file processing
- Inter-process communication
- Cybersecurity log analytics
- Performance benchmarking
- Distributed attack correlation

---

## Authors

**Eman Akbar**  
FAST National University of Computer and Emerging Sciences


---

## Course Information

**Course:** Parallel and Distributed Computing

This project was developed as part of coursework focused on applying distributed computing concepts to real-world cybersecurity problems.
