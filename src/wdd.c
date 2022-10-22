/*
 * Copyright 2018-2020 Sergey Zolotarev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <windows.h>

#define UNIT_KiB (1 << 10)
#define UNIT_MiB (1 << 20)
#define UNIT_GiB (1 << 30)
#define DEFAULT_BUFFER_SIZE 4096
#define UPDATE_INTERVAL 1000000
#define MAX_BUFFER_COUNT 2

#ifdef _MSC_VER
    #define strdup _strdup
    #define strtoll _strtoi64
    #define strtok_r strtok_s
#endif

struct program_options
{
    BOOL print_drive_list;
    BOOL show_progress;
    const char *input_filename;
    const char *output_filename;
    size_t block_size;
    size_t count;
    LARGE_INTEGER skip_offset;
    LARGE_INTEGER seek_offset;
};

struct program_state
{
    HANDLE input_file_handle;
    HANDLE output_file_handle;
    DWORD buffer_size;
    char *buffer[MAX_BUFFER_COUNT];
    BOOL output_file_is_device;
    BOOL started_copying;
    ULONGLONG start_time;
    size_t bytes_read;
    size_t bytes_write;
    size_t blocks_read;
    size_t blocks_write;
    size_t block_count;
    HANDLE semaphore_buffer_ready;
    HANDLE semaphore_buffer_occupied;
    HANDLE mutex_progress_display;
    HANDLE handle_thread_read;
    HANDLE handle_thread_write;
    DWORD bytes_read_per_block[MAX_BUFFER_COUNT];
    DWORD bytes_write_per_block;
    BOOL input_use_dev_zero;
};

static void print_usage(void)
{
    fprintf(stderr, "Usage: wdd [if=<in_file>] [of=<out_file>] [bs=N] [count=N] [skip=N] [seek=N] [progress]\n");
}

static ULONGLONG get_time_usec(void)
{
    FILETIME file_time;
    ULARGE_INTEGER time;

    GetSystemTimeAsFileTime(&file_time);
    time.LowPart = file_time.dwLowDateTime;
    time.HighPart = file_time.dwHighDateTime;
    return time.QuadPart / 10;
}

static void format_size(char *buffer, size_t buffer_size, size_t size)
{
    if (size >= UNIT_GiB)
    {
        snprintf(buffer, buffer_size, "%0.1f GiB", (double)size / (double)UNIT_GiB);
    }
    else if (size >= UNIT_MiB)
    {
        snprintf(buffer, buffer_size, "%0.1f MiB", (double)size / (double)UNIT_MiB);
    }
    else if (size >= UNIT_KiB)
    {
        snprintf(buffer, buffer_size, "%0.1f KiB", (double)size / (double)UNIT_KiB);
    }
    else
    {
        snprintf(buffer, buffer_size, "%zu B", size);
    }
}

static void format_speed(char *buffer, size_t buffer_size, double speed)
{
    if (speed >= (double)UNIT_GiB)
    {
        snprintf(buffer, buffer_size, "%0.1f GiB/s", speed / (double)UNIT_GiB);
    }
    else if (speed >= (double)UNIT_MiB)
    {
        snprintf(buffer, buffer_size, "%0.1f MiB/s", speed / (double)UNIT_MiB);
    }
    else if (speed >= (double)UNIT_KiB)
    {
        snprintf(buffer, buffer_size, "%0.1f KiB/s", speed / (double)UNIT_KiB);
    }
    else
    {
        snprintf(buffer, buffer_size, "%0.1f B/s", speed);
    }
}

static void print_progress(size_t bytes_copied,
                           size_t last_bytes_copied,
                           ULONGLONG start_time,
                           ULONGLONG last_time)
{
    ULONGLONG current_time;
    ULONGLONG elapsed_time;
    double speed;
    char bytes_str[16];
    char speed_str[16];

    current_time = get_time_usec();
    elapsed_time = current_time - start_time;
    speed = last_bytes_copied / ((double)(current_time - last_time) / 1000000);

    format_size(bytes_str, sizeof(bytes_str), bytes_copied);
    format_speed(speed_str, sizeof(speed_str), speed);

    fprintf(stderr,
            "%zu B (%s) copied, %0.1f s, %s",
            bytes_copied,
            bytes_str,
            (double)elapsed_time / 1000000.0,
            speed_str);
}

static void print_status(size_t bytes_copied, ULONGLONG start_time)
{
    print_progress(
        bytes_copied,
        bytes_copied,
        start_time,
        start_time);
}

static void clear_output(void)
{
    HANDLE console;
    COORD start_coord = {0, 0};
    DWORD num_chars_written;
    CONSOLE_SCREEN_BUFFER_INFO buffer_info;

    console = GetStdHandle(STD_ERROR_HANDLE);
    GetConsoleScreenBufferInfo(console, &buffer_info);
    start_coord.Y = buffer_info.dwCursorPosition.Y;
    FillConsoleOutputCharacter(
        console,
        ' ',
        buffer_info.dwSize.X,
        start_coord,
        &num_chars_written);
    SetConsoleCursorPosition(console, start_coord);
}

static char *get_error_message(DWORD error)
{
    char *buffer = NULL;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        error,
        0,
        (char *)&buffer,
        0,
        NULL);
    return buffer;
}

static void cleanup(const struct program_state *state)
{
    for (int i = 0; i < MAX_BUFFER_COUNT; i++)
    {
        VirtualFree(state->buffer[i], 0, MEM_RELEASE);
    }

    if (state->input_file_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(state->input_file_handle);
    }

    if (state->output_file_is_device)
    {
        DeviceIoControl(state->output_file_handle, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, NULL, NULL);
    }

    if (state->output_file_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(state->output_file_handle);
    }

    if (state->handle_thread_read != INVALID_HANDLE_VALUE)
    {
        CloseHandle(state->handle_thread_read);
    }

    if (state->handle_thread_write != INVALID_HANDLE_VALUE)
    {
        CloseHandle(state->handle_thread_write);
    }

    if (state->semaphore_buffer_ready != INVALID_HANDLE_VALUE)
    {
        CloseHandle(state->semaphore_buffer_ready);
    }

    if (state->semaphore_buffer_occupied != INVALID_HANDLE_VALUE)
    {
        CloseHandle(state->semaphore_buffer_occupied);
    }

    if (state->mutex_progress_display != INVALID_HANDLE_VALUE)
    {
        CloseHandle(state->mutex_progress_display);
    }
}

static void exit_on_error(const struct program_state *state,
                          int error_code,
                          char *format,
                          ...)
{
    va_list arg_list;
    char *reason;

    va_start(arg_list, format);
    vfprintf(stderr, format, arg_list);
    va_end(arg_list);
    fprintf(stderr, ": ");

    reason = get_error_message(error_code);
    reason[strlen(reason) - 2] = '\0';
    fprintf(stderr, "%s\n", reason);
    LocalFree(reason);

    if (state->started_copying == TRUE)
    {
        print_status(state->bytes_write, state->start_time);
    }

    cleanup(state);
    exit(EXIT_FAILURE);
}

static size_t parse_size(const char *str)
{
    char *end = NULL;
    size_t size = (size_t)strtoll(str, &end, 10);

    if (end != NULL && *end != '\0')
    {
        switch (*end)
        {
            case 'k':
            case 'K':
                size *= UNIT_KiB;
                break;
            case 'm':
            case 'M':
                size *= UNIT_MiB;
                break;
            case 'g':
            case 'G':
                size *= UNIT_GiB;
                break;
        }
    }
    return size;
}

static BOOL is_empty_string(const char *str)
{
    return str == NULL || *str == '\0';
}

static BOOL enable_windows_privilege(LPSTR requested_privilege)
{
    /* Tries to enable privilege if it is present to the Permissions set. */
    HANDLE handle_current_token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &handle_current_token) == FALSE)
    {
        return FALSE;
    }
    TOKEN_PRIVILEGES token_privileges;
    if (LookupPrivilegeValue(NULL, requested_privilege, &(token_privileges.Privileges[0].Luid)) == FALSE)
    {
        return FALSE;
    }
    token_privileges.PrivilegeCount = 1;
    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (AdjustTokenPrivileges(handle_current_token, FALSE, &token_privileges, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL) == FALSE)
    {
        return FALSE;
    }
    return TRUE;
}

static BOOL parse_options(int argc,
                          char **argv,
                          struct program_options *options)
{
    options->print_drive_list = FALSE;
    options->show_progress = FALSE;
    options->input_filename = "-";
    options->output_filename = "-";
    options->block_size = 0;
    options->count = 0;
    options->skip_offset.QuadPart = 0;
    options->seek_offset.QuadPart = 0;

    for (int i = 1; i < argc; i++)
    {
        char *value = NULL;
        char *name = strtok_r(argv[i], "=", &value);

        if (strcmp(name, "list") == 0)
        {
            options->print_drive_list = TRUE;
            return TRUE;
        }
        else if (strcmp(name, "if") == 0)
        {
            options->input_filename = strdup(value);
        }
        else if (strcmp(name, "of") == 0)
        {
            options->output_filename = strdup(value);
        }
        else if (strcmp(name, "bs") == 0)
        {
            options->block_size = parse_size(value);
        }
        else if (strcmp(name, "count") == 0)
        {
            options->count = (size_t)strtoll(value, NULL, 10);
        }
        else if (strcmp(name, "progress") == 0)
        {
            options->show_progress = TRUE;
        }
        else if (strcmp(name, "skip") == 0)
        {
            options->skip_offset.QuadPart = parse_size(value);
        }
        else if (strcmp(name, "seek") == 0)
        {
            options->seek_offset.QuadPart = parse_size(value);
        }
        else
        {
            return FALSE;
        }
    }
    if (options->count > 0 && options->block_size <= 0)
    {
        return FALSE;
    }
    if (is_empty_string(options->input_filename) == TRUE)
    {
        options->input_filename = "-";
    }
    if (is_empty_string(options->output_filename) == TRUE)
    {
        options->output_filename = "-";
    }
    if (options->skip_offset.QuadPart < 0)
    {
        return FALSE;
    }
    if (options->seek_offset.QuadPart < 0)
    {
        return FALSE;
    }
    return TRUE;
}

static void open_input_file(const char *input_filename, LARGE_INTEGER skip_offset, struct program_state *state)
{
    if (strcmp(input_filename, "/dev/zero") == 0)
    {
        state->input_use_dev_zero = TRUE;
    }
    else if (strcmp(input_filename, "-") == 0)
    {
        state->input_file_handle = GetStdHandle(STD_INPUT_HANDLE);
        if (state->input_file_handle == INVALID_HANDLE_VALUE)
        {
            exit_on_error(
                state,
                GetLastError(),
                "Could not open stdin for reading");
        }
    }
    else
    {
        state->input_file_handle = CreateFile(
            input_filename,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            NULL);
        if (state->input_file_handle == INVALID_HANDLE_VALUE)
        {
            exit_on_error(
                state,
                GetLastError(),
                "Could not open input file or device %s for reading",
                input_filename);
        }

        if (SetFilePointer(state->input_file_handle, skip_offset.LowPart, &skip_offset.HighPart, 0) == INVALID_SET_FILE_POINTER)
        {
            exit_on_error(
                state,
                GetLastError(),
                "Input file seek failed. Requested offset: %li",
                skip_offset.QuadPart);
        }
    }
    return;
}

static void open_output_file(const char *output_filename, LARGE_INTEGER seek_offset, struct program_state *state)
{
    if (strcmp(output_filename, "-") == 0)
    {
        state->output_file_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (state->output_file_handle == INVALID_HANDLE_VALUE)
        {
            exit_on_error(
                state,
                GetLastError(),
                "Could not open stdout for writing");
        }
    }
    else
    {
        /* First try to open as an existing file, thne as a new file. We can't
         * use OPEN_ALWAYS because it fails when out_file is a physical drive
         * (no idea why).
         */
        state->output_file_handle = CreateFile(
            output_filename,
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (state->output_file_handle == INVALID_HANDLE_VALUE)
        {
            state->output_file_handle = CreateFile(
                output_filename,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);
        }
        if (state->output_file_handle == INVALID_HANDLE_VALUE)
        {
            exit_on_error(
                state,
                GetLastError(),
                "Could not open output file or device %s for writing",
                output_filename);
        }

        if (SetFilePointer(state->output_file_handle, seek_offset.LowPart, &seek_offset.HighPart, 0) == INVALID_SET_FILE_POINTER)
        {
            exit_on_error(
                state,
                GetLastError(),
                "Output file seek failed. Requested offset: %li",
                seek_offset.QuadPart);
        }
    }
    return;
}

static void calculate_buffer_size(size_t block_size, struct program_state *state)
{
    DISK_GEOMETRY_EX disk_geometry;
    state->buffer_size = DEFAULT_BUFFER_SIZE;
    state->output_file_is_device = DeviceIoControl(
        state->output_file_handle,
        IOCTL_DISK_GET_DRIVE_GEOMETRY,
        NULL,
        0,
        &disk_geometry,
        sizeof(disk_geometry),
        NULL,
        NULL);

    if (state->output_file_is_device)
    {
        DWORD sector_size;
        size_t requested_size = 0;

        if (DeviceIoControl(state->output_file_handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, NULL, NULL) == FALSE)
        {
            exit_on_error(
                state,
                GetLastError(),
                "Failed to dismount output volume");
        }
        if (DeviceIoControl(state->output_file_handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, NULL, NULL) == FALSE)
        {
            exit_on_error(
                state,
                GetLastError(),
                "Failed to lock output volume");
        }

        sector_size = disk_geometry.Geometry.BytesPerSector;
        if (state->block_count > 0)
        {
            requested_size = state->buffer_size * state->block_count;
        }
        sector_size--;
        state->buffer_size = (block_size + sector_size) & ~sector_size;
        if (block_size > 0 && state->buffer_size != block_size)
        {
            fprintf(stderr, "Buffer size changed. Requested: %zi Real: %li\n", block_size, state->buffer_size);
            if (state->block_count > 0)
            {
                size_t original_block_count = state->block_count;
                requested_size = (requested_size + sector_size) & ~sector_size;
                state->block_count = requested_size / state->buffer_size;
                if (state->block_count != original_block_count)
                {
                    fprintf(stderr, "Block count changed. Requested: %zi Real: %zi\n", state->block_count, original_block_count);
                }
            }
        }
    }
    else if (block_size > 0)
    {
        state->buffer_size = (DWORD)block_size; // TODO: Possible bug with bs > 4GB
    }
}

static void allocate_buffer(struct program_state *state)
{
    BOOL use_large_pages = FALSE;
    DWORD large_page_buffer_size = 0;
    int buffer_count = MAX_BUFFER_COUNT;
    if (state->input_use_dev_zero == TRUE)
    {
        buffer_count = 1;
    }
    if (enable_windows_privilege("SeLockMemoryPrivilege") == TRUE)
    {
        size_t large_page_size = GetLargePageMinimum();
        fprintf(stderr, "LargePage support enabled, size: %zi\n", large_page_size);
        large_page_size--;
        large_page_buffer_size = (DWORD)((state->buffer_size + large_page_size) & ~large_page_size);
        use_large_pages = TRUE;
    }
    for (int i = 0; i < buffer_count; i++)
    {
        if (use_large_pages == TRUE)
        {
            state->buffer[i] = VirtualAlloc(
                NULL,
                large_page_buffer_size,
                MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
                PAGE_READWRITE);
            if (state->buffer[i] != NULL)
            {
                continue;
            }
            fprintf(stderr, "Buffer %i large pages allocation failed, fall back to normal allocation.\n", i);
        }
        state->buffer[i] = VirtualAlloc(
            NULL,
            state->buffer_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);
        if (state->buffer[i] == NULL)
        {
            exit_on_error(state, GetLastError(), "Failed to allocate buffer");
        }
    }
}

static void show_progress(struct program_state *state)
{
    ULONGLONG last_time = 0;
    ULONGLONG current_time = 0;
    size_t last_bytes_copied = 0;

    while (state->started_copying == TRUE)
    {

        WaitForSingleObject(state->mutex_progress_display, INFINITE);
        current_time = get_time_usec();
        if (last_time == 0)
        {
            last_time = current_time;
        }
        else
        {
            if (current_time - last_time >= UPDATE_INTERVAL)
            {
                clear_output();
                print_progress(
                    state->bytes_write,
                    state->bytes_write - last_bytes_copied,
                    state->start_time,
                    last_time);
                last_time = current_time;
                last_bytes_copied = state->bytes_write;
            }
        }
    }
}

DWORD WINAPI thread_read_default(struct program_state *state)
{
    BOOL result;
    DWORD buffer_index;

    while (1)
    {
        if (state->block_count > 0 && state->blocks_read >= state->block_count)
        {
            break;
        }
        buffer_index = state->blocks_read % MAX_BUFFER_COUNT;
        WaitForSingleObject(state->semaphore_buffer_ready, INFINITE);
        result = ReadFile(
            state->input_file_handle,
            state->buffer[buffer_index],
            state->buffer_size,
            &(state->bytes_read_per_block[buffer_index]),
            NULL);
        if (state->bytes_read_per_block[buffer_index] == 0 || (result == FALSE && GetLastError() == ERROR_SECTOR_NOT_FOUND))
        {
            ReleaseSemaphore(state->semaphore_buffer_occupied, 1, NULL);
            break;
        }
        if (result == FALSE)
        {
            ReleaseSemaphore(state->semaphore_buffer_occupied, 1, NULL);
            exit_on_error(state, GetLastError(), "Error reading from file");
        }

        state->bytes_read += state->bytes_read_per_block[buffer_index];
        state->blocks_read++;
        ReleaseSemaphore(state->semaphore_buffer_occupied, 1, NULL);
    }
    return EXIT_SUCCESS;
}

DWORD WINAPI thread_write_default(struct program_state *state)
{
    BOOL result;
    DWORD buffer_index;

    while (1)
    {
        if (state->mutex_progress_display != INVALID_HANDLE_VALUE)
        {
            ReleaseSemaphore(state->mutex_progress_display, 1, NULL);
        }
        if (state->block_count > 0 && state->blocks_write >= state->block_count)
        {
            break;
        }
        buffer_index = state->blocks_write % MAX_BUFFER_COUNT;
        WaitForSingleObject(state->semaphore_buffer_occupied, INFINITE);
        if (state->bytes_read_per_block[buffer_index] == 0)
        {
            ReleaseSemaphore(state->semaphore_buffer_ready, 1, NULL);
            break;
        }
        result = WriteFile(
            state->output_file_handle,
            state->buffer[buffer_index],
            state->bytes_read_per_block[buffer_index],
            &(state->bytes_write_per_block),
            NULL);
        if (result == FALSE)
        {
            ReleaseSemaphore(state->semaphore_buffer_ready, 1, NULL);
            exit_on_error(state, GetLastError(), "Error writing to file");
        }

        state->bytes_write += state->bytes_write_per_block;
        state->blocks_write++;
        ReleaseSemaphore(state->semaphore_buffer_ready, 1, NULL);
    }
    state->started_copying = FALSE;
    return EXIT_SUCCESS;
}

DWORD WINAPI thread_write_dev_zero(struct program_state *state)
{
    BOOL result;
    WaitForSingleObject(state->semaphore_buffer_ready, INFINITE);
    while (1)
    {
        if (state->mutex_progress_display != INVALID_HANDLE_VALUE)
        {
            ReleaseSemaphore(state->mutex_progress_display, 1, NULL);
        }
        if (state->block_count > 0 && state->blocks_write >= state->block_count)
        {
            break;
        }
        result = WriteFile(
            state->output_file_handle,
            state->buffer[0],
            state->buffer_size,
            &(state->bytes_write_per_block),
            NULL);
        if (result == FALSE)
        {
            exit_on_error(state, GetLastError(), "Error writing to file");
        }

        state->bytes_write += state->bytes_write_per_block;
        state->blocks_write++;
    }
    state->started_copying = FALSE;
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    struct program_options options;
    struct program_state state;

    ZeroMemory(&options, sizeof(options));

    if (parse_options(argc, argv, &options) == FALSE)
    {
        print_usage();
        return EXIT_FAILURE;
    }

    if (options.print_drive_list == TRUE)
    {
        return system("wmic diskdrive list brief");
    }

    ZeroMemory(&state, sizeof(state));
    state.input_file_handle = INVALID_HANDLE_VALUE;
    state.output_file_handle = INVALID_HANDLE_VALUE;
    state.mutex_progress_display = INVALID_HANDLE_VALUE;
    state.start_time = get_time_usec();
    state.output_file_is_device = FALSE;
    state.started_copying = FALSE;
    state.bytes_read = 0;
    state.bytes_write = 0;
    state.blocks_read = 0;
    state.blocks_write = 0;
    state.block_count = options.count;

    open_input_file(options.input_filename, options.skip_offset, &state);
    open_output_file(options.output_filename, options.seek_offset, &state);
    calculate_buffer_size(options.block_size, &state);

    allocate_buffer(&state);
    if (options.show_progress == TRUE)
    {
        state.mutex_progress_display = CreateSemaphore(NULL, 0, 1, NULL);
    }
    if (state.input_use_dev_zero == TRUE)
    {
        state.semaphore_buffer_ready = CreateSemaphore(NULL, MAX_BUFFER_COUNT, MAX_BUFFER_COUNT, NULL);
        state.handle_thread_write = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_write_dev_zero, &state, 0, NULL);
    }
    else
    {
        state.semaphore_buffer_ready = CreateSemaphore(NULL, MAX_BUFFER_COUNT, MAX_BUFFER_COUNT, NULL);
        state.semaphore_buffer_occupied = CreateSemaphore(NULL, 0, MAX_BUFFER_COUNT, NULL);
        state.handle_thread_read = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_read_default, &state, 0, NULL);
        state.handle_thread_write = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)thread_write_default, &state, 0, NULL);
    }

    state.started_copying = TRUE;

    if (options.show_progress == TRUE)
    {
        show_progress(&state);
    }

    WaitForSingleObject(state.handle_thread_read, INFINITE);
    WaitForSingleObject(state.handle_thread_write, INFINITE);

    cleanup(&state);
    clear_output();
    print_status(state.bytes_write, state.start_time);

    return EXIT_SUCCESS;
}
