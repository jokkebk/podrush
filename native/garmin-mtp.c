#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

/*
 * Podrush's deliberately small libmtp adapter.
 *
 * The declarations below are the stable public libmtp ABI fields/functions
 * used by this program. Keeping the adapter's surface small also makes it
 * straightforward to audit independently of the full libmtp header.
 */

typedef enum {
  LIBMTP_ERROR_NONE,
  LIBMTP_ERROR_GENERAL,
  LIBMTP_ERROR_PTP_LAYER,
  LIBMTP_ERROR_USB_LAYER,
  LIBMTP_ERROR_MEMORY_ALLOCATION,
  LIBMTP_ERROR_NO_DEVICE_ATTACHED,
  LIBMTP_ERROR_STORAGE_FULL,
  LIBMTP_ERROR_CONNECTING,
  LIBMTP_ERROR_CANCELLED
} LIBMTP_error_number_t;

typedef enum {
  LIBMTP_FILETYPE_FOLDER,
  LIBMTP_FILETYPE_WAV,
  LIBMTP_FILETYPE_MP3
} LIBMTP_filetype_t;

typedef struct LIBMTP_device_entry_struct {
  char *vendor;
  uint16_t vendor_id;
  char *product;
  uint16_t product_id;
  uint32_t device_flags;
} LIBMTP_device_entry_t;

typedef struct LIBMTP_raw_device_struct {
  LIBMTP_device_entry_t device_entry;
  uint32_t bus_location;
  uint8_t devnum;
} LIBMTP_raw_device_t;

typedef struct LIBMTP_error_struct LIBMTP_error_t;
typedef struct LIBMTP_device_extension_struct LIBMTP_device_extension_t;
typedef struct LIBMTP_mtpdevice_struct LIBMTP_mtpdevice_t;
typedef struct LIBMTP_file_struct LIBMTP_file_t;
typedef struct LIBMTP_devicestorage_struct LIBMTP_devicestorage_t;

struct LIBMTP_file_struct {
  uint32_t item_id;
  uint32_t parent_id;
  uint32_t storage_id;
  char *filename;
  uint64_t filesize;
  time_t modificationdate;
  LIBMTP_filetype_t filetype;
  LIBMTP_file_t *next;
};

struct LIBMTP_devicestorage_struct {
  uint32_t id;
  uint16_t StorageType;
  uint16_t FilesystemType;
  uint16_t AccessCapability;
  uint64_t MaxCapacity;
  uint64_t FreeSpaceInBytes;
  uint64_t FreeSpaceInObjects;
  char *StorageDescription;
  char *VolumeIdentifier;
  LIBMTP_devicestorage_t *next;
  LIBMTP_devicestorage_t *prev;
};

struct LIBMTP_mtpdevice_struct {
  uint8_t object_bitsize;
  void *params;
  void *usbinfo;
  LIBMTP_devicestorage_t *storage;
  LIBMTP_error_t *errorstack;
  uint8_t maximum_battery_level;
  uint32_t default_music_folder;
  uint32_t default_playlist_folder;
  uint32_t default_picture_folder;
  uint32_t default_video_folder;
  uint32_t default_organizer_folder;
  uint32_t default_zencast_folder;
  uint32_t default_album_folder;
  uint32_t default_text_folder;
  void *cd;
  LIBMTP_device_extension_t *extensions;
  int cached;
  LIBMTP_mtpdevice_t *next;
};

extern void LIBMTP_Init(void);
extern LIBMTP_error_number_t LIBMTP_Detect_Raw_Devices(
    LIBMTP_raw_device_t **, int *);
extern LIBMTP_mtpdevice_t *LIBMTP_Open_Raw_Device_Uncached(
    LIBMTP_raw_device_t *);
extern void LIBMTP_Release_Device(LIBMTP_mtpdevice_t *);
extern char *LIBMTP_Get_Manufacturername(LIBMTP_mtpdevice_t *);
extern char *LIBMTP_Get_Modelname(LIBMTP_mtpdevice_t *);
extern char *LIBMTP_Get_Serialnumber(LIBMTP_mtpdevice_t *);
extern int LIBMTP_Get_Storage(LIBMTP_mtpdevice_t *, int);
extern LIBMTP_file_t *LIBMTP_Get_Files_And_Folders(
    LIBMTP_mtpdevice_t *, uint32_t, uint32_t);
extern LIBMTP_file_t *LIBMTP_new_file_t(void);
extern void LIBMTP_destroy_file_t(LIBMTP_file_t *);
extern int LIBMTP_Send_File_From_File(
    LIBMTP_mtpdevice_t *, const char *, LIBMTP_file_t *, void *, const void *);
extern int LIBMTP_Delete_Object(LIBMTP_mtpdevice_t *, uint32_t);
extern uint32_t LIBMTP_Create_Folder(
    LIBMTP_mtpdevice_t *, char *, uint32_t, uint32_t);
extern void LIBMTP_Dump_Errorstack(LIBMTP_mtpdevice_t *);
extern void LIBMTP_Clear_Errorstack(LIBMTP_mtpdevice_t *);

#define GARMIN_VENDOR_ID 0x091e
#define MTP_ROOT 0xffffffffU
/* Garmin music watches expose the same deliberately incomplete MTP surface
 * as Android devices. Apply libmtp's Garmin mapping explicitly so behavior
 * remains stable if the pinned device database changes. */
#define GARMIN_MTP_FLAGS 0x18008106U

typedef struct {
  LIBMTP_mtpdevice_t *device;
  LIBMTP_devicestorage_t *storage;
  uint32_t podcasts_id;
} watch_t;

static void json_string(const char *value) {
  const unsigned char *cursor = (const unsigned char *)(value ? value : "");
  putchar('"');
  while (*cursor) {
    switch (*cursor) {
      case '"': fputs("\\\"", stdout); break;
      case '\\': fputs("\\\\", stdout); break;
      case '\b': fputs("\\b", stdout); break;
      case '\f': fputs("\\f", stdout); break;
      case '\n': fputs("\\n", stdout); break;
      case '\r': fputs("\\r", stdout); break;
      case '\t': fputs("\\t", stdout); break;
      default:
        if (*cursor < 0x20) {
          fprintf(stdout, "\\u%04x", *cursor);
        } else {
          putchar(*cursor);
        }
    }
    cursor++;
  }
  putchar('"');
}

static void destroy_file_list(LIBMTP_file_t *files) {
  while (files) {
    LIBMTP_file_t *next = files->next;
    files->next = NULL;
    LIBMTP_destroy_file_t(files);
    files = next;
  }
}

static LIBMTP_file_t *children(watch_t *watch, uint32_t parent_id) {
  return LIBMTP_Get_Files_And_Folders(
      watch->device, watch->storage->id, parent_id);
}

static uint32_t find_named_folder(
    watch_t *watch, uint32_t parent_id, const char *name, int depth) {
  if (depth > 8) return 0;
  LIBMTP_file_t *entries = children(watch, parent_id);
  LIBMTP_file_t *entry = entries;
  uint32_t found = 0;

  while (entry && !found) {
    if (entry->filetype == LIBMTP_FILETYPE_FOLDER && entry->filename) {
      if (strcasecmp(entry->filename, name) == 0) {
        found = entry->item_id;
      } else {
        found = find_named_folder(watch, entry->item_id, name, depth + 1);
      }
    }
    entry = entry->next;
  }
  destroy_file_list(entries);
  return found;
}

static int has_child_named(watch_t *watch, const char *name) {
  LIBMTP_file_t *entries = children(watch, watch->podcasts_id);
  LIBMTP_file_t *entry = entries;
  int found = 0;
  while (entry) {
    if (entry->filename && strcmp(entry->filename, name) == 0) {
      found = 1;
      break;
    }
    entry = entry->next;
  }
  destroy_file_list(entries);
  return found;
}

static int child_id_exists(watch_t *watch, uint32_t id) {
  LIBMTP_file_t *entries = children(watch, watch->podcasts_id);
  LIBMTP_file_t *entry = entries;
  int found = 0;
  while (entry) {
    if (entry->item_id == id && entry->filetype != LIBMTP_FILETYPE_FOLDER) {
      found = 1;
      break;
    }
    entry = entry->next;
  }
  destroy_file_list(entries);
  return found;
}

static const char *path_basename(const char *path) {
  const char *slash = strrchr(path, '/');
  return slash ? slash + 1 : path;
}

static int send_file(watch_t *watch, const char *path) {
  struct stat details;
  if (stat(path, &details) != 0 || !S_ISREG(details.st_mode)) {
    fprintf(stderr, "Cannot read %s: %s\n", path, strerror(errno));
    return -1;
  }

  const char *name = path_basename(path);
  if (!name[0] || has_child_named(watch, name)) return 0;

  LIBMTP_file_t *file = LIBMTP_new_file_t();
  if (!file) return -1;
  file->filename = strdup(name);
  file->filesize = (uint64_t)details.st_size;
  file->filetype = LIBMTP_FILETYPE_MP3;
  file->parent_id = watch->podcasts_id;
  file->storage_id = watch->storage->id;

  int result = LIBMTP_Send_File_From_File(
      watch->device, path, file, NULL, NULL);
  LIBMTP_destroy_file_t(file);
  if (result != 0) {
    LIBMTP_Dump_Errorstack(watch->device);
    LIBMTP_Clear_Errorstack(watch->device);
    return -1;
  }
  return 1;
}

static void print_state(
    watch_t *watch, const char *manufacturer, const char *model,
    const char *serial, const char *message) {
  printf("{\"connected\":true,\"manufacturer\":");
  json_string(manufacturer);
  printf(",\"model\":");
  json_string(model);
  printf(",\"serial\":");
  json_string(serial);
  printf(",\"storage\":{\"id\":%u,\"description\":", watch->storage->id);
  json_string(watch->storage->StorageDescription);
  printf(",\"capacity\":%llu,\"free\":%llu},\"podcastsFolderId\":%u,\"files\":[",
      (unsigned long long)watch->storage->MaxCapacity,
      (unsigned long long)watch->storage->FreeSpaceInBytes,
      watch->podcasts_id);

  LIBMTP_file_t *entries = children(watch, watch->podcasts_id);
  LIBMTP_file_t *entry = entries;
  int first = 1;
  while (entry) {
    if (entry->filetype != LIBMTP_FILETYPE_FOLDER) {
      if (!first) putchar(',');
      printf("{\"id\":%u,\"name\":", entry->item_id);
      json_string(entry->filename);
      printf(",\"size\":%llu,\"type\":%d}",
          (unsigned long long)entry->filesize, entry->filetype);
      first = 0;
    }
    entry = entry->next;
  }
  destroy_file_list(entries);
  printf("],\"message\":");
  json_string(message);
  puts("}");
}

static void print_disconnected(const char *error) {
  printf("{\"connected\":false,\"error\":");
  json_string(error);
  puts("}");
}

static int open_watch(
    watch_t *watch, LIBMTP_raw_device_t **raw_devices_out,
    char **manufacturer, char **model, char **serial) {
  LIBMTP_raw_device_t *raw_devices = NULL;
  int count = 0;
  LIBMTP_error_number_t detected =
      LIBMTP_Detect_Raw_Devices(&raw_devices, &count);

  if (detected == LIBMTP_ERROR_NO_DEVICE_ATTACHED || count == 0) {
    print_disconnected("No MTP device found. Connect the Garmin watch with its data cable.");
    return 0;
  }
  if (detected != LIBMTP_ERROR_NONE) {
    print_disconnected("MTP device discovery failed.");
    return -1;
  }

  LIBMTP_raw_device_t *raw = NULL;
  for (int index = 0; index < count; index++) {
    if (raw_devices[index].device_entry.vendor_id == GARMIN_VENDOR_ID) {
      raw = &raw_devices[index];
      break;
    }
  }
  if (!raw) {
    free(raw_devices);
    print_disconnected("An MTP device is connected, but it is not a Garmin.");
    return 0;
  }

  raw->device_entry.device_flags |= GARMIN_MTP_FLAGS;
  watch->device = LIBMTP_Open_Raw_Device_Uncached(raw);
  if (!watch->device) {
    free(raw_devices);
    print_disconnected(
        "Garmin is busy. Close any app using the watch, reconnect it, and try again.");
    return -1;
  }

  if (!watch->device->storage &&
      LIBMTP_Get_Storage(watch->device, 1) != 0) {
    LIBMTP_Dump_Errorstack(watch->device);
    LIBMTP_Clear_Errorstack(watch->device);
  }
  watch->storage = watch->device->storage;
  if (!watch->storage) {
    LIBMTP_Release_Device(watch->device);
    free(raw_devices);
    print_disconnected(
        "Garmin connected, but its internal storage could not be opened. Reconnect it and try again.");
    return -1;
  }

  watch->podcasts_id = find_named_folder(watch, MTP_ROOT, "Podcasts", 0);
  if (!watch->podcasts_id) {
    char folder_name[] = "Podcasts";
    watch->podcasts_id = LIBMTP_Create_Folder(
        watch->device, folder_name, MTP_ROOT, watch->storage->id);
  }
  if (!watch->podcasts_id) {
    LIBMTP_Dump_Errorstack(watch->device);
    LIBMTP_Clear_Errorstack(watch->device);
    LIBMTP_Release_Device(watch->device);
    free(raw_devices);
    print_disconnected("The Podcasts folder could not be found or created.");
    return -1;
  }

  *manufacturer = LIBMTP_Get_Manufacturername(watch->device);
  *model = LIBMTP_Get_Modelname(watch->device);
  *serial = LIBMTP_Get_Serialnumber(watch->device);
  *raw_devices_out = raw_devices;
  return 1;
}

int main(int argc, char **argv) {
  const char *command = argc > 1 ? argv[1] : "scan";
  if (strcmp(command, "scan") != 0 &&
      strcmp(command, "send") != 0 &&
      strcmp(command, "delete") != 0) {
    print_disconnected("Unknown helper command.");
    return 2;
  }

  LIBMTP_Init();
  watch_t watch = {0};
  LIBMTP_raw_device_t *raw_devices = NULL;
  char *manufacturer = NULL;
  char *model = NULL;
  char *serial = NULL;
  int opened = open_watch(
      &watch, &raw_devices, &manufacturer, &model, &serial);
  if (opened <= 0) return opened == 0 ? 0 : 1;

  int changed = 0;
  int failures = 0;
  if (strcmp(command, "send") == 0) {
    for (int index = 2; index < argc; index++) {
      int result = send_file(&watch, argv[index]);
      if (result > 0) changed++;
      if (result < 0) failures++;
    }
  } else if (strcmp(command, "delete") == 0) {
    for (int index = 2; index < argc; index++) {
      char *end = NULL;
      unsigned long parsed = strtoul(argv[index], &end, 10);
      if (!end || *end || parsed == 0 || parsed > UINT32_MAX ||
          !child_id_exists(&watch, (uint32_t)parsed)) {
        failures++;
        continue;
      }
      if (LIBMTP_Delete_Object(watch.device, (uint32_t)parsed) == 0) {
        changed++;
      } else {
        LIBMTP_Dump_Errorstack(watch.device);
        LIBMTP_Clear_Errorstack(watch.device);
        failures++;
      }
    }
  }

  char message[160];
  if (strcmp(command, "scan") == 0) {
    snprintf(message, sizeof(message), "Watch contents refreshed.");
  } else if (strcmp(command, "send") == 0) {
    snprintf(message, sizeof(message), "Sent %d file%s%s.", changed,
        changed == 1 ? "" : "s", failures ? "; some transfers failed" : "");
  } else {
    snprintf(message, sizeof(message), "Removed %d file%s%s.", changed,
        changed == 1 ? "" : "s", failures ? "; some removals failed" : "");
  }

  print_state(&watch, manufacturer, model, serial, message);
  free(manufacturer);
  free(model);
  free(serial);
  LIBMTP_Release_Device(watch.device);
  free(raw_devices);
  return failures ? 1 : 0;
}
