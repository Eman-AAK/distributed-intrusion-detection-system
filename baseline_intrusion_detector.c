#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_LINE 2048

/* Check attack type from string */
int detect_attack(char *attack) {
    if (strstr(attack, "DoS")) return 1;
    if (strstr(attack, "Backdoor")) return 2;
    if (strstr(attack, "Reconnaissance")) return 3;
    return 0;
}

/* Extract attack label from column 47 */
void get_attack(char *line, char *attack) {
    int col = 0;
    char *token = strtok(line, ",");

    while (token != NULL) {
        if (col == 47) {
            strcpy(attack, token);
            return;
        }
        token = strtok(NULL, ",");
        col++;
    }
}

/* Compute checksum of a line */
long long checksum(char *line) {
    long long sum = 0;
    for (int i = 0; i < strlen(line); i++) {
        sum += line[i];
    }
    return sum;
}

int main() {

    clock_t start = clock();  // start timing

    char *files[] = {
        "UNSW-NB15_1.csv",
        "UNSW-NB15_2.csv",
        "UNSW-NB15_3.csv",
        "UNSW-NB15_4.csv"
    };

    int total_dos = 0;
    int total_backdoor = 0;
    int total_recon = 0;
    long long global_checksum = 0;

    /* Loop through all files */
    for (int f = 0; f < 4; f++) {

        FILE *fp = fopen(files[f], "r");
        if (!fp) {
            printf("Error opening file\n");
            return 1;
        }

        char line[MAX_LINE];
        fgets(line, sizeof(line), fp); // skip header

        /* Read each line */
        while (fgets(line, sizeof(line), fp)) {

            char temp[MAX_LINE];
            strcpy(temp, line); // copy for strtok

            char attack[50] = "";
            get_attack(temp, attack);

            int type = detect_attack(attack);

            if (type == 1) total_dos++;
            else if (type == 2) total_backdoor++;
            else if (type == 3) total_recon++;

            global_checksum += checksum(line);
        }

        fclose(fp);
    }

    int total = total_dos + total_backdoor + total_recon;

    clock_t end = clock();  // end timing
    double time_taken = (double)(end - start) / CLOCKS_PER_SEC;

    printf("\n===== SERIAL LOG ANALYSIS =====\n\n");

    printf("DoS patterns detected: %d\n", total_dos);
    printf("Reconnaissance patterns detected: %d\n", total_recon);
    printf("Backdoor patterns detected: %d\n\n", total_backdoor);

    printf("Total suspicious activities: %d\n", total);
    printf("Global checksum: %lld\n", global_checksum);

    printf("Execution Time: %f seconds\n", time_taken);

    return 0;
}