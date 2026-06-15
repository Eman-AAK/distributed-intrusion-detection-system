# MPI Network Intrusion Detection System

## Overview

This project implements a parallel network intrusion detection system using MPI (Message Passing Interface) and the UNSW-NB15 cybersecurity dataset.

The system distributes network log analysis across multiple processes to improve performance and scalability when detecting suspicious activities such as:

- Denial of Service (DoS) attacks
- Backdoor attacks
- Reconnaissance attacks

The project compares serial and parallel execution approaches and demonstrates the benefits of distributed processing for large-scale cybersecurity datasets.

---

## Features

### Question 1
- Parallel processing using MPI
- Batch-based file distribution
- Detection of:
  - DoS attacks
  - Backdoor attacks
  - Reconnaissance attacks
- Global checksum verification
- Execution logging
- Performance measurement

### Question 2
- Cross-process attack correlation
- Distributed source IP analysis
- Distributed destination port analysis
- Multi-process suspicious activity tracking
- Detailed correlation logging

### Serial Version
- Single-process implementation
- Used for performance comparison against MPI implementation

---

## Dataset

The project uses the UNSW-NB15 Network Intrusion Detection Dataset.

Files analyzed:

- UNSW-NB15_1.csv
- UNSW-NB15_2.csv
- UNSW-NB15_3.csv
- UNSW-NB15_4.csv

---

## Technologies Used

- C Programming
- MPI (OpenMPI / MPICH)
- Parallel Computing
- Distributed Systems
- Cybersecurity Analytics

---

## Project Structure

```
i221588_i221713_A/
│
├── i221588_i221713_Q1.c
├── i221588_i221713_Q2.c
├── i221588_i221713_serial.c
│
├── Output Log Files/
│   ├── OutputLog_Q1_1Process.txt
│   ├── OutputLog_Q1_2Processes.txt
│   ├── OutputLog_Q1_4Processes.txt
│   ├── OutputLog_Q1_8Processes.txt
│   ├── OutputLog_Q2_1Process.txt
│   ├── OutputLog_Q2_2Processes.txt
│   ├── OutputLog_Q2_4Processes.txt
│   └── OutputLog_Q2_8Processes.txt
│
└── Project_Report.pdf
```

---

## Compilation

### MPI Programs

Compile Q1:

```bash
mpicc i221588_i221713_Q1.c -o q1
```

Compile Q2:

```bash
mpicc i221588_i221713_Q2.c -o q2
```

### Serial Program

```bash
gcc i221588_i221713_serial.c -o serial
```

---

## Execution

### MPI Execution

Run with 4 processes:

```bash
mpirun -np 4 ./q1
```

```bash
mpirun -np 4 ./q2
```

### Serial Execution

```bash
./serial
```

---

## Performance Evaluation

The project evaluates:

- Execution time
- Scalability
- Attack detection accuracy
- Checksum validation
- Process distribution efficiency

using 1, 2, 4, and 8 processes.

---

## Authors

- Eman Akbar (22I-1588)
- Partner: 22I-1713

FAST National University of Computer and Emerging Sciences

Course: Parallel and Distributed Computing
