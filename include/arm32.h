#pragma once
/* Dispatch raw ARM-reset images while retaining Watch Thumb precedence. */
int kairos_arm32_probe(const char *path);
int kairos_arm32_main(int argc, char **argv);
