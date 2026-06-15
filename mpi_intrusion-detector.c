#include <mpi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LINE   2048
#define BATCH_SIZE 20000

/* Static buffers — kept off the stack due to large size */
static char batch[BATCH_SIZE][MAX_LINE];
static char local_logs[BATCH_SIZE][MAX_LINE];

/* Returns 1=DoS, 2=Backdoor, 3=Recon, 0=clean */
int detect_attack(char *attack) {
    if (strstr(attack, "DoS"))            return 1;
    if (strstr(attack, "Backdoor"))       return 2;
    if (strstr(attack, "Reconnaissance")) return 3;
    return 0;
}

/* Extracts column 47 (attack label) from a CSV row */
void get_attack(char *line, char *attack) {
    int col = 0;
    char *token = strtok(line, ",");
    while (token != NULL) {
        if (col == 47) {
            strncpy(attack, token, 49);
            attack[49] = '\0';
            return;
        }
        token = strtok(NULL, ",");
        col++;
    }
    attack[0] = '\0';
}

/* Byte-sum checksum — unsigned char cast prevents sign-extension on bytes > 127 */
long long checksum(char *line) {
    long long sum = 0;
    int len = (int)strlen(line);
    for (int i = 0; i < len; i++)
        sum += (unsigned char)line[i];
    return sum;
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
        logfile = fopen("execution_log.txt", "w");
        if (!logfile)
            fprintf(stderr, "Warning: could not open execution_log.txt\n");
    }

    char *files[] = {
        "UNSW-NB15_1.csv",
        "UNSW-NB15_2.csv",
        "UNSW-NB15_3.csv",
        "UNSW-NB15_4.csv"
    };
    int num_files = 4;

    int global_dos      = 0;
    int global_backdoor = 0;
    int global_recon    = 0;
    long long global_checksum = 0;

    if (rank == 0 && logfile) {
        fprintf(logfile, "Processing dataset using MPI (batch + scatter)\n");
        fprintf(logfile, "Processes: %d\n\n", size);
    }

    for (int f = 0; f < num_files; f++) {

        int batch_num = 0;

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

            int local_dos      = 0;
            int local_backdoor = 0;
            int local_recon    = 0;
            long long local_sum = 0;

            for (int i = 0; i < chunk; i++) {

                if (local_logs[i][0] == '\0') continue;   /* skip padding rows */

                local_sum += checksum(local_logs[i]);   /* checksum before strtok */

                char temp[MAX_LINE];
                strncpy(temp, local_logs[i], MAX_LINE - 1);
                temp[MAX_LINE - 1] = '\0';

                char attack[50] = "";
                get_attack(temp, attack);

                int type = detect_attack(attack);
                if      (type == 1) local_dos++;
                else if (type == 2) local_backdoor++;
                else if (type == 3) local_recon++;
            }

            /* MPI_Gather — collect per-process counts into arrays on rank 0
             * satisfies the brief requirement and enables per-process logging */
            int *gathered_dos      = NULL;
            int *gathered_backdoor = NULL;
            int *gathered_recon    = NULL;

            if (rank == 0) {
                gathered_dos      = malloc(size * sizeof(int));
                gathered_backdoor = malloc(size * sizeof(int));
                gathered_recon    = malloc(size * sizeof(int));
            }

            MPI_Gather(&local_dos,      1, MPI_INT,
                       gathered_dos,    1, MPI_INT, 0, MPI_COMM_WORLD);
            MPI_Gather(&local_backdoor, 1, MPI_INT,
                       gathered_backdoor, 1, MPI_INT, 0, MPI_COMM_WORLD);
            MPI_Gather(&local_recon,    1, MPI_INT,
                       gathered_recon, 1, MPI_INT, 0, MPI_COMM_WORLD);

            int total_dos = 0, total_backdoor = 0, total_recon = 0;

            if (rank == 0) {
                if (logfile)
                    fprintf(logfile, "batch %d per-process breakdown:\n", batch_num);

                for (int p = 0; p < size; p++) {
                    total_dos      += gathered_dos[p];
                    total_backdoor += gathered_backdoor[p];
                    total_recon    += gathered_recon[p];

                    if (logfile)
                        fprintf(logfile,
                                "  process %d — dos:%d  backdoor:%d  recon:%d\n",
                                p, gathered_dos[p], gathered_backdoor[p],
                                gathered_recon[p]);
                }

                global_dos      += total_dos;
                global_backdoor += total_backdoor;
                global_recon    += total_recon;

                free(gathered_dos);
                free(gathered_backdoor);
                free(gathered_recon);
            }

            /* MPI_Reduce — aggregate checksum to rank 0 */
            long long total_sum = 0;
            MPI_Reduce(&local_sum, &total_sum, 1, MPI_LONG_LONG, MPI_SUM,
                       0, MPI_COMM_WORLD);

            if (rank == 0) {
                global_checksum += total_sum;

                if (logfile)
                    fprintf(logfile,
                            "batch %d completed — dos:%d bkd:%d recon:%d  "
                            "checksum: %lld\n\n",
                            batch_num, total_dos, total_backdoor, total_recon,
                            total_sum);
            }

        } /* end batch loop */

        if (rank == 0 && fp) fclose(fp);

    } /* end file loop */

    /* Bcast global_total first so all ranks raise a valid flag for Allreduce */
    int global_total = 0;
    if (rank == 0)
        global_total = global_dos + global_backdoor + global_recon;

    MPI_Bcast(&global_total, 1, MPI_INT, 0, MPI_COMM_WORLD);

    int local_flag  = (global_total > 0) ? 1 : 0;
    int global_flag = 0;
    MPI_Allreduce(&local_flag, &global_flag, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);

    double end = MPI_Wtime();

    if (rank == 0) {

        if (logfile) {
            fprintf(logfile, "\n========== FINAL RESULTS ==========\n");
            fprintf(logfile, "DoS attacks:            %d\n", global_dos);
            fprintf(logfile, "Backdoor attacks:       %d\n", global_backdoor);
            fprintf(logfile, "Reconnaissance attacks: %d\n", global_recon);
            fprintf(logfile, "Total malicious:        %d\n", global_total);
            fprintf(logfile, "Global checksum:        %lld\n", global_checksum);
            fprintf(logfile, "Execution time:         %.6f seconds\n", end - start);
            fclose(logfile);
        }

        printf("\n===== Parallel Log Analysis Result =====\n\n");
        printf("Processes used:                   %d\n\n", size);
        printf("DoS patterns detected:            %d\n",   global_dos);
        printf("Reconnaissance patterns detected: %d\n",   global_recon);
        printf("Backdoor patterns detected:       %d\n\n", global_backdoor);
        printf("Suspicious connections detected:  %d\n",   global_total);
        printf("Global checksum:                  %lld\n", global_checksum);
        printf("Execution Time:                   %.6f seconds\n", end - start);

        if (global_flag > 0)
            printf("\n[!] Distributed Attack Detected (flag sum = %d)\n", global_flag);
        else
            printf("\n[OK] No distributed attack detected.\n");

        printf("\nDetailed logs saved in execution_log.txt\n");
    }

    MPI_Finalize();
    return 0;
}