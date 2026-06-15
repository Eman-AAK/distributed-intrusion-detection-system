#include <mpi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LINE    2048
#define BATCH_SIZE  20000
#define MAX_IPS     2000
#define MAX_PORTS   2000
#define IP_LEN      50
#define PORT_LEN    16

/* UNSW-NB15 columns used: col 0 = srcip, col 3 = dsport, col 47 = attack label
 * IPs and ports are flagged as distributed if seen across 2+ processes */

static char batch[BATCH_SIZE][MAX_LINE];
static char local_logs[BATCH_SIZE][MAX_LINE];

/* Returns 1 for DoS, Backdoor, or Reconnaissance; 0 otherwise */
int detect_attack(char *attack) {
    return (strstr(attack, "DoS")            != NULL ||
            strstr(attack, "Backdoor")       != NULL ||
            strstr(attack, "Reconnaissance") != NULL);
}

/* Generic CSV column extractor (0-indexed) — strips trailing whitespace/newline */
void get_field(char *line, int target_col, char *out, int out_len) {
    int col = 0;
    char *token = strtok(line, ",");
    while (token != NULL) {
        if (col == target_col) {
            strncpy(out, token, out_len - 1);
            out[out_len - 1] = '\0';
            int len = (int)strlen(out);
            while (len > 0 && (out[len-1] == '\n' || out[len-1] == '\r' ||
                               out[len-1] == ' ')) {
                out[--len] = '\0';
            }
            return;
        }
        token = strtok(NULL, ",");
        col++;
    }
    out[0] = '\0';
}

/* Byte-sum checksum — unsigned char cast prevents sign-extension on bytes > 127 */
long long checksum(char *line) {
    long long sum = 0;
    int len = (int)strlen(line);
    for (int i = 0; i < len; i++)
        sum += (unsigned char)line[i];
    return sum;
}

/* Returns 1 if key exists in arr[0..count-1]; stride = element width in bytes */
int exists_n(char *arr, int count, int stride, char *key) {
    for (int i = 0; i < count; i++)
        if (strcmp(arr + i * stride, key) == 0) return 1;
    return 0;
}

int main(int argc, char *argv[]) {

    int rank, size;
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    double start = MPI_Wtime();

    /* Logfile opened once before any loop — only rank 0 writes */
    FILE *logfile = NULL;
    if (rank == 0) {
        logfile = fopen("q2_execution_log.txt", "w");
        if (!logfile)
            fprintf(stderr, "Warning: could not open q2_execution_log.txt\n");
        else {
            fprintf(logfile, "===== Q2: Cross-Process Correlation Log =====\n");
            fprintf(logfile, "Processes: %d\n\n", size);
        }
    }

    char *files[] = {
        "UNSW-NB15_1.csv",
        "UNSW-NB15_2.csv",
        "UNSW-NB15_3.csv",
        "UNSW-NB15_4.csv"
    };
    int num_files = 4;

    int global_total          = 0;
    long long global_checksum = 0;

    char local_ips[MAX_IPS][IP_LEN];     /* unique suspicious source IPs per process */
    int  local_ip_count = 0;

    char local_ports[MAX_PORTS][PORT_LEN]; /* unique suspicious dest ports per process */
    int  local_port_count = 0;

    for (int f = 0; f < num_files; f++) {

        /* Only rank 0 opens and reads files */
        FILE *fp = NULL;
        if (rank == 0) {
            fp = fopen(files[f], "r");
            if (!fp) {
                fprintf(stderr, "Error: cannot open %s\n", files[f]);
                MPI_Abort(MPI_COMM_WORLD, 1);
            }
            if (logfile)
                fprintf(logfile, "\n=== Reading file: %s ===\n", files[f]);
            char header[MAX_LINE];
            fgets(header, sizeof(header), fp);   /* skip CSV header */
        }

        int batch_num = 0;

        while (1) {

            int batch_count = 0;

            if (rank == 0) {
                char line[MAX_LINE];
                while (batch_count < BATCH_SIZE && fgets(line, sizeof(line), fp)) {
                    strncpy(batch[batch_count], line, MAX_LINE - 1);
                    batch[batch_count][MAX_LINE - 1] = '\0';
                    batch_count++;
                }
                batch_num++;
                if (logfile)
                    fprintf(logfile, "batch %d loaded (%d logs)\n",
                            batch_num, batch_count);
            }

            MPI_Bcast(&batch_count, 1, MPI_INT, 0, MPI_COMM_WORLD);
            if (batch_count == 0) break;

            int chunk = (batch_count + size - 1) / size;   /* ceiling division */

            /* memset padding rows — prevents stale data causing checksum errors */
            if (rank == 0) {
                for (int i = batch_count; i < chunk * size; i++)
                    memset(batch[i], 0, MAX_LINE);
            }

            MPI_Scatter(batch,      chunk * MAX_LINE, MPI_CHAR,
                        local_logs, chunk * MAX_LINE, MPI_CHAR,
                        0, MPI_COMM_WORLD);

            int local_count     = 0;
            long long local_sum = 0;

            for (int i = 0; i < chunk; i++) {

                if (local_logs[i][0] == '\0') continue;   /* skip padding rows */

                local_sum += checksum(local_logs[i]);   /* checksum before strtok */

                /* One copy per field — strtok is destructive */
                char t_attack[MAX_LINE], t_srcip[MAX_LINE], t_port[MAX_LINE];
                strncpy(t_attack, local_logs[i], MAX_LINE-1); t_attack[MAX_LINE-1] = '\0';
                strncpy(t_srcip,  local_logs[i], MAX_LINE-1); t_srcip[MAX_LINE-1]  = '\0';
                strncpy(t_port,   local_logs[i], MAX_LINE-1); t_port[MAX_LINE-1]   = '\0';

                char attack[IP_LEN]   = "";
                char srcip[IP_LEN]    = "";
                char dsport[PORT_LEN] = "";

                get_field(t_attack, 47, attack,  IP_LEN);    /* col 47 — attack label */
                get_field(t_srcip,   0, srcip,   IP_LEN);    /* col  0 — source IP    */
                get_field(t_port,    3, dsport,  PORT_LEN);  /* col  3 — dest port    */

                if (srcip[0] == '\0') continue;

                if (detect_attack(attack)) {

                    local_count++;

                    /* Track unique source IPs per process */
                    if (local_ip_count < MAX_IPS &&
                        !exists_n((char*)local_ips, local_ip_count, IP_LEN, srcip)) {
                        strncpy(local_ips[local_ip_count], srcip, IP_LEN - 1);
                        local_ips[local_ip_count][IP_LEN - 1] = '\0';
                        local_ip_count++;
                    }

                    /* Track unique dest ports per process */
                    if (dsport[0] != '\0' &&
                        local_port_count < MAX_PORTS &&
                        !exists_n((char*)local_ports, local_port_count, PORT_LEN, dsport)) {
                        strncpy(local_ports[local_port_count], dsport, PORT_LEN - 1);
                        local_ports[local_port_count][PORT_LEN - 1] = '\0';
                        local_port_count++;
                    }
                }
            }

            int total_count = 0;
            long long total_sum = 0;
            MPI_Reduce(&local_count, &total_count, 1, MPI_INT,       MPI_SUM, 0, MPI_COMM_WORLD);
            MPI_Reduce(&local_sum,   &total_sum,   1, MPI_LONG_LONG, MPI_SUM, 0, MPI_COMM_WORLD);

            if (rank == 0) {
                global_total    += total_count;
                global_checksum += total_sum;
                if (logfile)
                    fprintf(logfile,
                            "batch %d completed — malicious hits: %d  "
                            "checksum contribution: %lld\n",
                            batch_num, total_count, total_sum);
            }

        } /* end batch loop */

        if (rank == 0 && fp) fclose(fp);

    } /* end file loop */


    /* Gather IP and port counts from all processes */
    int *ip_counts   = NULL;
    int *port_counts = NULL;
    if (rank == 0) {
        ip_counts   = malloc(size * sizeof(int));
        port_counts = malloc(size * sizeof(int));
    }

    MPI_Gather(&local_ip_count,   1, MPI_INT, ip_counts,   1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Gather(&local_port_count, 1, MPI_INT, port_counts, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (rank == 0 && logfile) {
        fprintf(logfile, "\n===== GATHER RESULTS =====\n");
        for (int p = 0; p < size; p++)
            fprintf(logfile, "Process %d — source IPs: %d  dest ports: %d\n",
                    p, ip_counts[p], port_counts[p]);
    }

    /* MPI_Gatherv for IPs — variable receive counts since each process
     * has a different local_ip_count; recvcounts[] and displs[] handle this */
    int  *ip_recv  = NULL, *ip_disp  = NULL;
    char *all_ips  = NULL;
    int   total_ips = 0;

    if (rank == 0) {
        ip_recv = malloc(size * sizeof(int));
        ip_disp = malloc(size * sizeof(int));
        ip_disp[0] = 0;
        for (int i = 0; i < size; i++) ip_recv[i] = ip_counts[i] * IP_LEN;
        for (int i = 1; i < size; i++) ip_disp[i] = ip_disp[i-1] + ip_recv[i-1];
        for (int i = 0; i < size; i++) total_ips += ip_counts[i];
        all_ips = malloc(total_ips * IP_LEN * sizeof(char));
    }

    MPI_Gatherv(local_ips,  local_ip_count * IP_LEN, MPI_CHAR,
                all_ips,    ip_recv, ip_disp,         MPI_CHAR,
                0, MPI_COMM_WORLD);

    /* MPI_Gatherv for destination ports */
    int  *port_recv  = NULL, *port_disp  = NULL;
    char *all_ports  = NULL;
    int   total_ports = 0;

    if (rank == 0) {
        port_recv = malloc(size * sizeof(int));
        port_disp = malloc(size * sizeof(int));
        port_disp[0] = 0;
        for (int i = 0; i < size; i++) port_recv[i] = port_counts[i] * PORT_LEN;
        for (int i = 1; i < size; i++) port_disp[i] = port_disp[i-1] + port_recv[i-1];
        for (int i = 0; i < size; i++) total_ports += port_counts[i];
        all_ports = malloc(total_ports * PORT_LEN * sizeof(char));
    }

    MPI_Gatherv(local_ports,  local_port_count * PORT_LEN, MPI_CHAR,
                all_ports,    port_recv, port_disp,         MPI_CHAR,
                0, MPI_COMM_WORLD);

    /* Log raw gathered data per process */
    if (rank == 0 && logfile) {

        fprintf(logfile, "\n===== RAW SOURCE IPs PER PROCESS =====\n");
        int slot = 0;
        for (int p = 0; p < size; p++) {
            fprintf(logfile, "Process %d:\n", p);
            if (ip_counts[p] == 0) fprintf(logfile, "  (none)\n");
            for (int k = 0; k < ip_counts[p]; k++)
                fprintf(logfile, "  %s\n", all_ips + slot++ * IP_LEN);
        }

        fprintf(logfile, "\n===== RAW DEST PORTS PER PROCESS =====\n");
        slot = 0;
        for (int p = 0; p < size; p++) {
            fprintf(logfile, "Process %d:\n", p);
            if (port_counts[p] == 0) fprintf(logfile, "  (none)\n");
            for (int k = 0; k < port_counts[p]; k++)
                fprintf(logfile, "  port %s\n", all_ports + slot++ * PORT_LEN);
        }
    }

    /* Cross-check IPs — flag only if seen across 2+ distinct processes */
    int distributed_ip_count = 0;
    char final_ips[MAX_IPS][IP_LEN];
    int  final_ip_count = 0;

    if (rank == 0) {
        if (logfile)
            fprintf(logfile, "\n===== CROSS-PROCESS IP CORRELATION =====\n");

        /* ip_owner[slot] = process that contributed that IP slot */
        int *ip_owner = malloc(total_ips * sizeof(int));
        int slot = 0;
        for (int p = 0; p < size; p++)
            for (int k = 0; k < ip_counts[p]; k++)
                ip_owner[slot++] = p;

        for (int i = 0; i < total_ips; i++) {
            char *ip = all_ips + i * IP_LEN;
            if (ip[0] == '\0') continue;
            if (exists_n((char*)final_ips, final_ip_count, IP_LEN, ip)) continue;

            int proc_seen[size];
            memset(proc_seen, 0, size * sizeof(int));
            for (int j = 0; j < total_ips; j++)
                if (strcmp(ip, all_ips + j * IP_LEN) == 0)
                    proc_seen[ip_owner[j]] = 1;

            int distinct = 0;
            for (int p = 0; p < size; p++) distinct += proc_seen[p];

            if (logfile) {
                if (distinct > 1)
                    fprintf(logfile, "IP: %-20s → seen in %d processes → DISTRIBUTED ATTACK\n",
                            ip, distinct);
                else
                    fprintf(logfile, "IP: %-20s → seen in %d process  → single source\n",
                            ip, distinct);
            }

            if (distinct > 1 && final_ip_count < MAX_IPS) {
                strncpy(final_ips[final_ip_count], ip, IP_LEN - 1);
                final_ips[final_ip_count][IP_LEN - 1] = '\0';
                final_ip_count++;
                distributed_ip_count++;
            }
        }

        free(ip_owner);
        free(ip_recv); free(ip_disp); free(ip_counts); free(all_ips);
    }

    /* Cross-check ports — flag only if targeted across 2+ distinct processes */
    int distributed_port_count = 0;
    char final_ports[MAX_PORTS][PORT_LEN];
    int  final_port_count = 0;

    if (rank == 0) {
        if (logfile)
            fprintf(logfile, "\n===== CROSS-PROCESS PORT CORRELATION =====\n");

        int *port_owner = malloc(total_ports * sizeof(int));
        int slot = 0;
        for (int p = 0; p < size; p++)
            for (int k = 0; k < port_counts[p]; k++)
                port_owner[slot++] = p;

        for (int i = 0; i < total_ports; i++) {
            char *port = all_ports + i * PORT_LEN;
            if (port[0] == '\0') continue;
            if (exists_n((char*)final_ports, final_port_count, PORT_LEN, port)) continue;

            int proc_seen[size];
            memset(proc_seen, 0, size * sizeof(int));
            for (int j = 0; j < total_ports; j++)
                if (strcmp(port, all_ports + j * PORT_LEN) == 0)
                    proc_seen[port_owner[j]] = 1;

            int distinct = 0;
            for (int p = 0; p < size; p++) distinct += proc_seen[p];

            if (logfile) {
                if (distinct > 1)
                    fprintf(logfile, "Port: %-8s → targeted by %d processes → DISTRIBUTED SCAN\n",
                            port, distinct);
                else
                    fprintf(logfile, "Port: %-8s → targeted by %d process  → single source\n",
                            port, distinct);
            }

            if (distinct > 1 && final_port_count < MAX_PORTS) {
                strncpy(final_ports[final_port_count], port, PORT_LEN - 1);
                final_ports[final_port_count][PORT_LEN - 1] = '\0';
                final_port_count++;
                distributed_port_count++;
            }
        }

        free(port_owner);
        free(port_recv); free(port_disp); free(port_counts); free(all_ports);
    }

    /* Bcast counts first so all ranks raise a valid flag for Allreduce */
    MPI_Bcast(&distributed_ip_count,   1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&distributed_port_count, 1, MPI_INT, 0, MPI_COMM_WORLD);

    int local_flag  = (distributed_ip_count > 0 || distributed_port_count > 0) ? 1 : 0;
    int global_flag = 0;
    MPI_Allreduce(&local_flag, &global_flag, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);

    /* Broadcast final deduplicated IP and port lists to all processes */
    MPI_Bcast(&final_ip_count,   1,                       MPI_INT,  0, MPI_COMM_WORLD);
    MPI_Bcast(final_ips,         final_ip_count * IP_LEN, MPI_CHAR, 0, MPI_COMM_WORLD);

    MPI_Bcast(&final_port_count, 1,                           MPI_INT,  0, MPI_COMM_WORLD);
    MPI_Bcast(final_ports,       final_port_count * PORT_LEN, MPI_CHAR, 0, MPI_COMM_WORLD);

    double end = MPI_Wtime();

    if (rank == 0 && logfile) {

        fprintf(logfile, "\n===== CHECKSUM VALIDATION =====\n");
        fprintf(logfile, "Global Checksum : %lld\n", global_checksum);
        fprintf(logfile, "Compare against serial.c output — a match confirms\n");
        fprintf(logfile, "no log segments were skipped or misprocessed.\n");

        fprintf(logfile, "\n===== FINAL SUMMARY =====\n");
        fprintf(logfile, "Total Malicious Activities    : %d\n",   global_total);
        fprintf(logfile, "Global Checksum               : %lld\n", global_checksum);
        fprintf(logfile, "Distributed Source IPs        : %d\n",   distributed_ip_count);
        fprintf(logfile, "Distributed Dest Ports        : %d\n",   distributed_port_count);
        fprintf(logfile, "Processes used                : %d\n",   size);
        fprintf(logfile, "Execution Time                : %.6f seconds\n", end - start);

        fprintf(logfile, "\nFinal Suspicious IP List (broadcast to all processes):\n");
        if (final_ip_count == 0) fprintf(logfile, "  (none)\n");
        for (int i = 0; i < final_ip_count; i++)
            fprintf(logfile, "  [%d] %s\n", i + 1, final_ips[i]);

        fprintf(logfile, "\nFinal Suspicious Port List (broadcast to all processes):\n");
        if (final_port_count == 0) fprintf(logfile, "  (none)\n");
        for (int i = 0; i < final_port_count; i++)
            fprintf(logfile, "  [%d] port %s\n", i + 1, final_ports[i]);

        if (global_flag > 0)
            fprintf(logfile, "\n[!] Distributed Attack Confirmed.\n");
        else
            fprintf(logfile, "\n[OK] No distributed attack pattern detected.\n");

        fclose(logfile);
    }

    if (rank == 0) {

        printf("\n===== Q2: Cross-Process Correlation Results =====\n\n");
        printf("Total Malicious Activities    : %d\n",     global_total);
        printf("Global Checksum               : %lld\n\n", global_checksum);
        printf("Distributed Source IPs  (seen in 2+ processes) : %d\n", distributed_ip_count);
        printf("Distributed Dest Ports  (seen in 2+ processes) : %d\n\n", distributed_port_count);

        if (final_ip_count > 0) {
            printf("Suspicious Source IPs:\n");
            for (int i = 0; i < final_ip_count; i++)
                printf("  [%d] %s\n", i + 1, final_ips[i]);
        } else {
            printf("No distributed source IPs found.\n");
        }

        if (final_port_count > 0) {
            printf("\nSuspicious Destination Ports:\n");
            for (int i = 0; i < final_port_count; i++)
                printf("  [%d] port %s\n", i + 1, final_ports[i]);
        } else {
            printf("\nNo distributed destination ports found.\n");
        }

        printf("\nProcesses used : %d\n",          size);
        printf("Execution Time : %.6f seconds\n", end - start);

        if (global_flag > 0)
            printf("\n[!] Distributed Attack Confirmed across multiple processes.\n");
        else
            printf("\n[OK] No distributed attack pattern detected.\n");

        printf("\nDetailed logs saved in q2_execution_log.txt\n");
    }

    MPI_Finalize();
    return 0;
}