#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>

#define _POSIX_C_SOURCE 200809L

#define DISK_SIZE_MB 10
#define BLOCK_SIZE 1024
#define NUM_BLOCKS (DISK_SIZE_MB * 1024 * 1024 / BLOCK_SIZE)
#define MAX_FILENAME_LEN 16
#define MAX_OPEN_FILES 10
#define MAX_DIRECT_BLOCKS 10
#define INODE_SIZE sizeof(Inode)
#define NUM_INODES (NUM_BLOCKS / 10)
#define INODE_TABLE_BLOCKS ((NUM_INODES * INODE_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE)
#define INODE_BITMAP_SIZE ((NUM_INODES + 7) / 8)
#define BLOCK_BITMAP_SIZE ((NUM_BLOCKS + 7) / 8)

#define SUPER_BLOCK_START_BLOCK 0
#define INODE_BITMAP_START_BLOCK (SUPER_BLOCK_START_BLOCK + 1)
#define BLOCK_BITMAP_START_BLOCK (INODE_BITMAP_START_BLOCK + (INODE_BITMAP_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE)
#define INODE_TABLE_START_BLOCK (BLOCK_BITMAP_START_BLOCK + (BLOCK_BITMAP_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE)
#define DATA_BLOCK_START_BLOCK (INODE_TABLE_START_BLOCK + INODE_TABLE_BLOCKS)

typedef enum { FILE_TYPE_UNKNOWN, FILE_TYPE_REGULAR, FILE_TYPE_DIRECTORY } FileType;

typedef struct {
    unsigned int total_blocks, block_size, num_inodes, free_blocks, free_inodes;
    unsigned int inode_bitmap_start_block, block_bitmap_start_block, inode_table_start_block, data_block_start_block;
    unsigned int magic_number;
    time_t mount_time, last_write_time;
} SuperBlock;

typedef struct {
    FileType type;
    unsigned int size, link_count;
    time_t create_time, modify_time;
    unsigned int block_pointers[MAX_DIRECT_BLOCKS];
} Inode;

typedef struct {
    char filename[MAX_FILENAME_LEN];
    unsigned int inode_num;
} DirEntry;

typedef struct {
    int inode_num, position, flags, is_open;
} FileDescriptor;

#define OPEN_READ 0x01
#define OPEN_WRITE 0x02
#define OPEN_APPEND 0x04

unsigned char *disk_memory = NULL;
SuperBlock *g_super_block;
unsigned char *g_inode_bitmap;
unsigned char *g_block_bitmap;
Inode *g_inode_table;
unsigned int g_current_dir_inode_num;
FileDescriptor open_fds[MAX_OPEN_FILES];

void write_block(unsigned int block_num, const void *buffer);
void read_block(unsigned int block_num, void *buffer);
Inode* get_inode(int inode_num);
int allocate_inode();
int allocate_block();
void free_inode(int inode_num);
void free_block(int block_num);
int find_inode_by_path(const char *path);
int get_parent_dir_inode_num_from_inode(int current_inode_num);
void recursive_delete_inode(int inode_num_to_delete);
void create_directory(const char *dirname);
void delete_directory(const char *dirname);
void list_directory(const char *path);
void change_directory(const char *dirname);
void print_current_path();
void create_file(const char *filename);
int open_file_op(const char *filename, int flags);
int close_file_op(int fd_idx);
int read_file_op(int fd_idx, char *buffer, int size);
int write_file_op(int fd_idx, const char *buffer, int size);
void delete_file(const char *filename);
void format_disk();
void mount_filesystem();
void unmount_filesystem();
void write_metadata_to_disk();
void read_metadata_from_disk();
void init_disk_memory();

int foreach_entry_in_dir(int dir_inode_num, int (*callback)(DirEntry*, void*), void *user_data) {
    Inode *dir_inode = get_inode(dir_inode_num);
    if (!dir_inode || dir_inode->type != FILE_TYPE_DIRECTORY) return 0;
    unsigned char block_buffer[BLOCK_SIZE];
    for (int i = 0; i < MAX_DIRECT_BLOCKS && dir_inode->block_pointers[i] != 0; i++) {
        read_block(dir_inode->block_pointers[i], block_buffer);
        int num_entries_in_block = BLOCK_SIZE / sizeof(DirEntry);
        for (int j = 0; j < num_entries_in_block; j++) {
            DirEntry *entry = (DirEntry*)(block_buffer + j * sizeof(DirEntry));
            if (entry->filename[0] != '\0') {
                if (callback(entry, user_data)) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

typedef struct { const char *name_to_find; int found_inode_num; } FindData;
int find_entry_callback(DirEntry *entry, void *user_data) {
    FindData *data = (FindData *)user_data;
    if (strcmp(entry->filename, data->name_to_find) == 0) {
        data->found_inode_num = entry->inode_num;
        return 1;
    }
    return 0;
}
int find_entry_in_dir(int dir_inode_num, const char *name) {
    FindData data = { .name_to_find = name, .found_inode_num = -1 };
    foreach_entry_in_dir(dir_inode_num, find_entry_callback, &data);
    return data.found_inode_num;
}

int parse_path_and_find_parent(const char *path, int *parent_inode_num_out, char *filename_out) {
    char *path_copy = strdup(path);
    if (!path_copy) { perror("strdup"); return -1; }
    char *last_slash = strrchr(path_copy, '/');
    int parent_inode_num;
    char *filename;
    if (last_slash == NULL) {
        parent_inode_num = g_current_dir_inode_num;
        filename = path_copy;
    } else {
        *last_slash = '\0';
        filename = last_slash + 1;
        const char *parent_path = (path_copy[0] == '\0') ? "/" : path_copy;
        parent_inode_num = find_inode_by_path(parent_path);
    }
    if (parent_inode_num == -1) {
        printf("错误: 父目录未找到。\n");
        free(path_copy);
        return -1;
    }
    if (strlen(filename) >= MAX_FILENAME_LEN) {
        printf("错误: 文件名 '%s' 过长。\n", filename);
        free(path_copy);
        return -1;
    }
    if (strlen(filename) == 0 && strcmp(path, "/") != 0) {
        printf("错误: 文件名不能为空。\n");
        free(path_copy);
        return -1;
    }
    *parent_inode_num_out = parent_inode_num;
    strncpy(filename_out, filename, MAX_FILENAME_LEN);
    free(path_copy);
    return 0;
}

int find_inode_by_path(const char *path) {
    if (strcmp(path, "/") == 0) return 0;
    int current_inode = (path[0] == '/') ? 0 : g_current_dir_inode_num;
    const char *p = (path[0] == '/') ? path + 1 : path;
    char *path_copy = strdup(p);
    if (!path_copy) { perror("strdup"); return -1; }
    char *token = strtok(path_copy, "/");
    while (token != NULL) {
        current_inode = find_entry_in_dir(current_inode, token);
        if (current_inode == -1) break;
        token = strtok(NULL, "/");
    }
    free(path_copy);
    return current_inode;
}

void write_block(unsigned int block_num, const void *buffer) {
    if (block_num >= NUM_BLOCKS) return;
    memcpy(disk_memory + block_num * BLOCK_SIZE, buffer, BLOCK_SIZE);
}
void read_block(unsigned int block_num, void *buffer) {
    if (block_num >= NUM_BLOCKS) return;
    memcpy(buffer, disk_memory + block_num * BLOCK_SIZE, BLOCK_SIZE);
}
Inode* get_inode(int inode_num) {
    if (inode_num < 0 || inode_num >= (int)NUM_INODES) return NULL;
    return &g_inode_table[inode_num];
}

int allocate_inode() {
    for (int i = 0; i < (int)NUM_INODES; i++) {
        if (!(g_inode_bitmap[i / 8] & (1 << (i % 8)))) {
            g_inode_bitmap[i / 8] |= (1 << (i % 8));
            g_super_block->free_inodes--;
            memset(&g_inode_table[i], 0, sizeof(Inode));
            return i;
        }
    }
    return -1;
}
void free_inode(int inode_num) {
    if (inode_num < 0 || inode_num >= (int)NUM_INODES) return;
    g_inode_bitmap[inode_num / 8] &= ~(1 << (inode_num % 8));
    g_super_block->free_inodes++;
}
int allocate_block() {
    for (int i = DATA_BLOCK_START_BLOCK; i < (int)NUM_BLOCKS; i++) {
        if (!(g_block_bitmap[i / 8] & (1 << (i % 8)))) {
            g_block_bitmap[i / 8] |= (1 << (i % 8));
            g_super_block->free_blocks--;
            return i;
        }
    }
    return -1;
}
void free_block(int block_num) {
    if (block_num < (int)DATA_BLOCK_START_BLOCK || block_num >= (int)NUM_BLOCKS) return;
    g_block_bitmap[block_num / 8] &= ~(1 << (block_num % 8));
    g_super_block->free_blocks++;
}

int add_entry_to_dir(int dir_inode_num, const char *name, int new_inode_num) {
    Inode *dir_inode = get_inode(dir_inode_num);
    if (!dir_inode || dir_inode->type != FILE_TYPE_DIRECTORY) return -1;
    DirEntry new_entry;
    strncpy(new_entry.filename, name, MAX_FILENAME_LEN - 1);
    new_entry.filename[MAX_FILENAME_LEN - 1] = '\0';
    new_entry.inode_num = new_inode_num;
    unsigned char block_buffer[BLOCK_SIZE];
    for (int i = 0; i < MAX_DIRECT_BLOCKS; i++) {
        int block_num = dir_inode->block_pointers[i];
        if (block_num == 0) {
            block_num = allocate_block();
            if (block_num == -1) return -1;
            dir_inode->block_pointers[i] = block_num;
            memset(block_buffer, 0, BLOCK_SIZE);
        } else {
            read_block(block_num, block_buffer);
        }
        int num_entries_in_block = BLOCK_SIZE / sizeof(DirEntry);
        for (int j = 0; j < num_entries_in_block; j++) {
            DirEntry *entry = (DirEntry*)(block_buffer + j * sizeof(DirEntry));
            if (entry->filename[0] == '\0') {
                memcpy(entry, &new_entry, sizeof(DirEntry));
                write_block(block_num, block_buffer);
                dir_inode->size += sizeof(DirEntry);
                dir_inode->modify_time = time(NULL);
                return 0;
            }
        }
    }
    return -1;
}
void remove_entry_from_dir(int dir_inode_num, const char *name) {
    Inode *dir_inode = get_inode(dir_inode_num);
    if (!dir_inode || dir_inode->type != FILE_TYPE_DIRECTORY) return;
    unsigned char block_buffer[BLOCK_SIZE];
    for (int i = 0; i < MAX_DIRECT_BLOCKS && dir_inode->block_pointers[i] != 0; i++) {
        read_block(dir_inode->block_pointers[i], block_buffer);
        for (int j = 0; j < BLOCK_SIZE / (int)sizeof(DirEntry); j++) {
            DirEntry *entry = (DirEntry*)(block_buffer + j * sizeof(DirEntry));
            if (entry->filename[0] != '\0' && strcmp(entry->filename, name) == 0) {
                memset(entry, 0, sizeof(DirEntry));
                write_block(dir_inode->block_pointers[i], block_buffer);
                dir_inode->size -= sizeof(DirEntry);
                dir_inode->modify_time = time(NULL);
                return;
            }
        }
    }
}

int get_parent_dir_inode_num_from_inode(int current_inode_num) {
    if (current_inode_num == 0) return 0;
    return find_entry_in_dir(current_inode_num, "..");
}

void recursive_delete_inode(int inode_num) {
    Inode *inode = get_inode(inode_num);
    if (!inode) return;
    if (inode->type == FILE_TYPE_DIRECTORY) {
        unsigned char block_buffer[BLOCK_SIZE];
        for (int i = 0; i < MAX_DIRECT_BLOCKS && inode->block_pointers[i] != 0; i++) {
            read_block(inode->block_pointers[i], block_buffer);
            for (int j = 0; j < BLOCK_SIZE / (int)sizeof(DirEntry); j++) {
                DirEntry *entry = (DirEntry*)(block_buffer + j * sizeof(DirEntry));
                if (entry->filename[0] != '\0' && strcmp(entry->filename, ".") != 0 && strcmp(entry->filename, "..") != 0) {
                    recursive_delete_inode(entry->inode_num);
                }
            }
            free_block(inode->block_pointers[i]);
        }
    } else {
        for (int i = 0; i < MAX_DIRECT_BLOCKS && inode->block_pointers[i] != 0; i++) {
            free_block(inode->block_pointers[i]);
        }
    }
    free_inode(inode_num);
}

void create_directory(const char *dirname) {
    char new_dirname[MAX_FILENAME_LEN];
    int parent_inode_num;
    if (parse_path_and_find_parent(dirname, &parent_inode_num, new_dirname) != 0) return;
    if (find_entry_in_dir(parent_inode_num, new_dirname) != -1) {
        printf("错误: '%s' 已存在。\n", dirname);
        return;
    }
    int new_inode_num = allocate_inode();
    int data_block = allocate_block();
    if (new_inode_num == -1 || data_block == -1) {
        printf("错误: 无法分配 i-node 或数据块。\n");
        if (new_inode_num != -1) free_inode(new_inode_num);
        if (data_block != -1) free_block(data_block);
        return;
    }
    Inode *new_dir_inode = get_inode(new_inode_num);
    new_dir_inode->type = FILE_TYPE_DIRECTORY;
    new_dir_inode->link_count = 2;
    new_dir_inode->create_time = new_dir_inode->modify_time = time(NULL);
    new_dir_inode->block_pointers[0] = data_block;
    unsigned char empty_block[BLOCK_SIZE] = {0};
    write_block(data_block, empty_block);
    add_entry_to_dir(new_inode_num, ".", new_inode_num);
    add_entry_to_dir(new_inode_num, "..", parent_inode_num);
    if (add_entry_to_dir(parent_inode_num, new_dirname, new_inode_num) == 0) {
        printf("目录 '%s' 创建成功。\n", dirname);
    } else {
        printf("错误: 无法在父目录中创建条目。\n");
        recursive_delete_inode(new_inode_num);
    }
    write_metadata_to_disk();
}

typedef struct { int count; } DirEmptyCheckData;
int dir_empty_check_callback(DirEntry *entry, void *user_data) {
    if (strcmp(entry->filename, ".") != 0 && strcmp(entry->filename, "..") != 0) {
        ((DirEmptyCheckData*)user_data)->count++;
        return 1;
    }
    return 0;
}
void delete_directory(const char *dirname) {
    int target_inode_num = find_inode_by_path(dirname);
    if (target_inode_num <= 0) {
        printf("错误: 无法删除根目录或目录 '%s' 未找到。\n", dirname);
        return;
    }
    if (target_inode_num == (int)g_current_dir_inode_num) {
         printf("错误: 无法删除当前工作目录。\n");
         return;
    }
    Inode *target_inode = get_inode(target_inode_num);
    if (target_inode->type != FILE_TYPE_DIRECTORY) {
        printf("错误: '%s' 不是一个目录。\n", dirname);
        return;
    }
    DirEmptyCheckData check = {0};
    foreach_entry_in_dir(target_inode_num, dir_empty_check_callback, &check);
    if (check.count > 0) {
        printf("错误: 目录 '%s' 非空。\n", dirname);
        return;
    }
    char target_name[MAX_FILENAME_LEN];
    int parent_inode_num;
    parse_path_and_find_parent(dirname, &parent_inode_num, target_name);
    remove_entry_from_dir(parent_inode_num, target_name);
    recursive_delete_inode(target_inode_num);
    printf("目录 '%s' 已删除。\n", dirname);
    write_metadata_to_disk();
}

int list_entry_callback(DirEntry *entry, void *user_data) {
    (void)user_data;
    Inode *entry_inode = get_inode(entry->inode_num);
    if (entry_inode) {
        char time_buf[20];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M", localtime(&entry_inode->modify_time));
        printf("%-8s %4d %8u %s  %s\n",
               (entry_inode->type == FILE_TYPE_DIRECTORY ? "目录" : "文件"),
               entry->inode_num, entry_inode->size, time_buf, entry->filename);
    }
    return 0;
}
void list_directory(const char *path) {
    int dir_inode_num = (path == NULL || strlen(path) == 0) ? g_current_dir_inode_num : find_inode_by_path(path);
    if (dir_inode_num == -1) {
        printf("错误: 目录 '%s' 未找到。\n", path);
        return;
    }
    Inode *dir_inode = get_inode(dir_inode_num);
    if (dir_inode->type != FILE_TYPE_DIRECTORY) {
        printf("错误: '%s' 不是目录。\n", path);
        return;
    }
    printf("目录 '%s' (i-node %d) 的内容:\n", (path && strlen(path)>0)?path:".", dir_inode_num);
    printf("类型       i-节点     大小 最后修改时间        名称\n");
    printf("---------------------------------------------------------\n");
    foreach_entry_in_dir(dir_inode_num, list_entry_callback, NULL);
    printf("---------------------------------------------------------\n");
}

void change_directory(const char *dirname) {
    int target_inode_num = find_inode_by_path(dirname);
    if (target_inode_num == -1) {
        printf("错误: 未找到目录 '%s'。\n", dirname);
        return;
    }
    Inode *target_inode = get_inode(target_inode_num);
    if (target_inode->type != FILE_TYPE_DIRECTORY) {
        printf("错误: '%s' 不是目录。\n", dirname);
        return;
    }
    g_current_dir_inode_num = target_inode_num;
}

void print_current_path() {
    if (g_current_dir_inode_num == 0) {
        printf("myfs:/$ ");
        return;
    }
    char path_components[32][MAX_FILENAME_LEN];
    int depth = 0;
    int current = g_current_dir_inode_num;
    while (current != 0 && depth < 32) {
        int parent = get_parent_dir_inode_num_from_inode(current);
        if (parent == current) break;
        Inode* parent_inode = get_inode(parent);
        unsigned char block_buffer[BLOCK_SIZE];
        int found = 0;
        for (int i = 0; i < MAX_DIRECT_BLOCKS && parent_inode->block_pointers[i] != 0 && !found; i++) {
            read_block(parent_inode->block_pointers[i], block_buffer);
            for (int j = 0; j < BLOCK_SIZE / (int)sizeof(DirEntry); j++) {
                DirEntry *entry = (DirEntry*)(block_buffer + j * sizeof(DirEntry));
                if (entry->inode_num == (unsigned int)current) {
                    strcpy(path_components[depth++], entry->filename);
                    found = 1;
                    break;
                }
            }
        }
        current = parent;
    }
    printf("myfs:/");
    for (int i = depth - 1; i >= 0; i--) {
        printf("%s/", path_components[i]);
    }
    printf("$ ");
}

void create_file(const char *filename) {
    char new_filename[MAX_FILENAME_LEN];
    int parent_inode_num;
    if (parse_path_and_find_parent(filename, &parent_inode_num, new_filename) != 0) return;
    if (find_entry_in_dir(parent_inode_num, new_filename) != -1) {
        printf("错误: '%s' 已存在。\n", filename);
        return;
    }
    int new_inode_num = allocate_inode();
    if (new_inode_num == -1) {
        printf("错误: 无法为文件分配 i-node。\n");
        return;
    }
    Inode *new_file_inode = get_inode(new_inode_num);
    new_file_inode->type = FILE_TYPE_REGULAR;
    new_file_inode->size = 0;
    new_file_inode->link_count = 1;
    new_file_inode->create_time = new_file_inode->modify_time = time(NULL);
    if (add_entry_to_dir(parent_inode_num, new_filename, new_inode_num) == 0) {
        printf("文件 '%s' 创建成功。\n", filename);
    } else {
        printf("错误: 无法在父目录中创建条目。\n");
        free_inode(new_inode_num);
    }
    write_metadata_to_disk();
}

void delete_file(const char *filename) {
    int target_inode_num = find_inode_by_path(filename);
    if (target_inode_num < 0) {
        printf("错误: 文件 '%s' 未找到。\n", filename);
        return;
    }
    for (int i=0; i<MAX_OPEN_FILES; ++i) {
        if(open_fds[i].is_open && open_fds[i].inode_num == target_inode_num) {
            printf("错误: 文件 '%s' 当前已打开 (fd=%d)。\n", filename, i);
            return;
        }
    }
    char target_name[MAX_FILENAME_LEN];
    int parent_inode_num;
    parse_path_and_find_parent(filename, &parent_inode_num, target_name);
    remove_entry_from_dir(parent_inode_num, target_name);
    recursive_delete_inode(target_inode_num);
    printf("文件 '%s' 已删除。\n", filename);
    write_metadata_to_disk();
}

int open_file_op(const char *filename, int flags) {
    int file_inode_num = find_inode_by_path(filename);
    if (file_inode_num < 0) {
        printf("错误: 文件 '%s' 未找到。\n", filename);
        return -1;
    }
    if (get_inode(file_inode_num)->type != FILE_TYPE_REGULAR) {
        printf("错误: '%s' 不是一个普通文件。\n", filename);
        return -1;
    }
    int fd_idx = -1;
    for (int i=0; i < MAX_OPEN_FILES; ++i) {
        if (!open_fds[i].is_open) {
            fd_idx = i;
            break;
        }
    }
    if (fd_idx == -1) {
        printf("错误: 打开的文件过多。\n");
        return -1;
    }
    Inode* file_inode = get_inode(file_inode_num);
    open_fds[fd_idx].is_open = 1;
    open_fds[fd_idx].inode_num = file_inode_num;
    open_fds[fd_idx].flags = flags;
    open_fds[fd_idx].position = (flags & OPEN_APPEND) ? file_inode->size : 0;
    if ((flags & OPEN_WRITE) && !(flags & OPEN_READ) && !(flags & OPEN_APPEND)) {
        for(int i=0; i<MAX_DIRECT_BLOCKS; ++i) {
            if (file_inode->block_pointers[i] != 0) {
                free_block(file_inode->block_pointers[i]);
                file_inode->block_pointers[i] = 0;
            }
        }
        file_inode->size = 0;
    }
    return fd_idx;
}

int close_file_op(int fd_idx) {
    if (fd_idx < 0 || fd_idx >= MAX_OPEN_FILES || !open_fds[fd_idx].is_open) {
        printf("错误: 无效的文件描述符 %d。\n", fd_idx);
        return -1;
    }
    open_fds[fd_idx].is_open = 0;
    return 0;
}

int read_file_op(int fd_idx, char *buffer, int size) {
    if (fd_idx < 0 || fd_idx >= MAX_OPEN_FILES || !open_fds[fd_idx].is_open || !(open_fds[fd_idx].flags & OPEN_READ)) {
        printf("错误: 无效或非读模式的文件描述符 %d。\n", fd_idx);
        return -1;
    }
    FileDescriptor *fd = &open_fds[fd_idx];
    Inode *file_inode = get_inode(fd->inode_num);
    int bytes_read = 0;
    unsigned char block_buffer[BLOCK_SIZE];
    while (bytes_read < size && fd->position < (int)file_inode->size) {
        int block_idx = fd->position / BLOCK_SIZE;
        int offset_in_block = fd->position % BLOCK_SIZE;
        read_block(file_inode->block_pointers[block_idx], block_buffer);
        int bytes_to_copy = BLOCK_SIZE - offset_in_block;
        if (bytes_to_copy > size - bytes_read) bytes_to_copy = size - bytes_read;
        if (fd->position + bytes_to_copy > (int)file_inode->size) bytes_to_copy = file_inode->size - fd->position;
        memcpy(buffer + bytes_read, block_buffer + offset_in_block, bytes_to_copy);
        fd->position += bytes_to_copy;
        bytes_read += bytes_to_copy;
    }
    return bytes_read;
}
int write_file_op(int fd_idx, const char *buffer, int size) {
    if (fd_idx < 0 || fd_idx >= MAX_OPEN_FILES || !open_fds[fd_idx].is_open || !(open_fds[fd_idx].flags & OPEN_WRITE)) {
        printf("错误: 无效或非写模式的文件描述符 %d。\n", fd_idx);
        return -1;
    }
    FileDescriptor *fd = &open_fds[fd_idx];
    Inode *file_inode = get_inode(fd->inode_num);
    int bytes_written = 0;
    unsigned char block_buffer[BLOCK_SIZE];
    while(bytes_written < size) {
        int block_idx = fd->position / BLOCK_SIZE;
        if (block_idx >= MAX_DIRECT_BLOCKS) {
            printf("错误: 文件达到最大尺寸。\n");
            break;
        }
        int offset_in_block = fd->position % BLOCK_SIZE;
        int block_num = file_inode->block_pointers[block_idx];
        if (block_num == 0) {
            block_num = allocate_block();
            if (block_num == -1) { printf("错误: 磁盘空间不足。\n"); break; }
            file_inode->block_pointers[block_idx] = block_num;
            memset(block_buffer, 0, BLOCK_SIZE);
        } else {
            read_block(block_num, block_buffer);
        }
        int bytes_to_copy = BLOCK_SIZE - offset_in_block;
        if(bytes_to_copy > size - bytes_written) bytes_to_copy = size - bytes_written;
        memcpy(block_buffer + offset_in_block, buffer + bytes_written, bytes_to_copy);
        write_block(block_num, block_buffer);
        fd->position += bytes_to_copy;
        bytes_written += bytes_to_copy;
        if ((unsigned int)fd->position > file_inode->size) {
            file_inode->size = fd->position;
        }
    }
    file_inode->modify_time = time(NULL);
    write_metadata_to_disk();
    return bytes_written;
}

void init_disk_memory() {
    disk_memory = (unsigned char *)malloc(DISK_SIZE_MB * 1024 * 1024);
    if (!disk_memory) { perror("malloc disk"); exit(EXIT_FAILURE); }
    memset(disk_memory, 0, DISK_SIZE_MB * 1024 * 1024);
    for(int i = 0; i < MAX_OPEN_FILES; i++) open_fds[i].is_open = 0;
}
void write_metadata_to_disk() {
    write_block(SUPER_BLOCK_START_BLOCK, g_super_block);
    write_block(INODE_BITMAP_START_BLOCK, g_inode_bitmap);
    write_block(BLOCK_BITMAP_START_BLOCK, g_block_bitmap);
    for (int i = 0; i < (int)INODE_TABLE_BLOCKS; i++) {
        write_block(INODE_TABLE_START_BLOCK + i, (unsigned char*)g_inode_table + i * BLOCK_SIZE);
    }
}
void read_metadata_from_disk() {
    read_block(SUPER_BLOCK_START_BLOCK, g_super_block);
    read_block(INODE_BITMAP_START_BLOCK, g_inode_bitmap);
    read_block(BLOCK_BITMAP_START_BLOCK, g_block_bitmap);
    for (int i = 0; i < (int)INODE_TABLE_BLOCKS; i++) {
        read_block(INODE_TABLE_START_BLOCK + i, (unsigned char*)g_inode_table + i * BLOCK_SIZE);
    }
}
void format_disk() {
    printf("正在格式化磁盘...\n");
    g_super_block = (SuperBlock*)(disk_memory);
    g_inode_bitmap = disk_memory + INODE_BITMAP_START_BLOCK * BLOCK_SIZE;
    g_block_bitmap = disk_memory + BLOCK_BITMAP_START_BLOCK * BLOCK_SIZE;
    g_inode_table = (Inode*)(disk_memory + INODE_TABLE_START_BLOCK * BLOCK_SIZE);
    *g_super_block = (SuperBlock){
        .total_blocks = NUM_BLOCKS, .block_size = BLOCK_SIZE, .num_inodes = NUM_INODES,
        .free_blocks = NUM_BLOCKS, .free_inodes = NUM_INODES,
        .inode_bitmap_start_block = INODE_BITMAP_START_BLOCK,
        .block_bitmap_start_block = BLOCK_BITMAP_START_BLOCK,
        .inode_table_start_block = INODE_TABLE_START_BLOCK,
        .data_block_start_block = DATA_BLOCK_START_BLOCK,
        .magic_number = 0xDEADBEEF, .mount_time = time(NULL)
    };
    for (int i = 0; i < (int)DATA_BLOCK_START_BLOCK; i++) {
        g_block_bitmap[i/8] |= (1 << (i%8));
        g_super_block->free_blocks--;
    }
    int root_inode_num = allocate_inode();
    Inode *root_inode = get_inode(root_inode_num);
    root_inode->type = FILE_TYPE_DIRECTORY;
    root_inode->link_count = 2;
    root_inode->create_time = root_inode->modify_time = time(NULL);
    int root_data_block = allocate_block();
    root_inode->block_pointers[0] = root_data_block;
    unsigned char empty_block[BLOCK_SIZE] = {0};
    write_block(root_data_block, empty_block);
    add_entry_to_dir(root_inode_num, ".", root_inode_num);
    add_entry_to_dir(root_inode_num, "..", root_inode_num);
    g_current_dir_inode_num = 0;
    write_metadata_to_disk();
    printf("磁盘格式化成功！\n");
}
void mount_filesystem() {
    g_super_block = (SuperBlock*)(disk_memory);
    g_inode_bitmap = disk_memory + INODE_BITMAP_START_BLOCK * BLOCK_SIZE;
    g_block_bitmap = disk_memory + BLOCK_BITMAP_START_BLOCK * BLOCK_SIZE;
    g_inode_table = (Inode*)(disk_memory + INODE_TABLE_START_BLOCK * BLOCK_SIZE);
    if (g_super_block->magic_number != 0xDEADBEEF) {
        printf("文件系统未格式化。正在自动格式化...\n");
        format_disk();
    } else {
        printf("文件系统挂载成功。\n");
        g_current_dir_inode_num = 0;
    }
}
void unmount_filesystem() {
    if (disk_memory) {
        write_metadata_to_disk();
        free(disk_memory);
        disk_memory = NULL;
        printf("文件系统已卸载。\n");
    }
}

typedef void (*CommandHandler)(int argc, char *argv[]);
typedef struct {
    const char *name; CommandHandler handler; int min_args; const char *usage;
} Command;

void handle_format(int argc, char *argv[]) { (void)argc; (void)argv; format_disk(); }
void handle_ls(int argc, char *argv[]) { list_directory(argc > 1 ? argv[1] : ""); }
void handle_cd(int argc, char *argv[]) { change_directory(argv[1]); }
void handle_mkdir(int argc, char *argv[]) { create_directory(argv[1]); }
void handle_rmdir(int argc, char *argv[]) { delete_directory(argv[1]); }
void handle_touch(int argc, char *argv[]) { create_file(argv[1]); }
void handle_rm(int argc, char *argv[]) { delete_file(argv[1]); }

void handle_open(int argc, char *argv[]) {
    int flags = 0;
    if (strcmp(argv[2], "r") == 0) flags = OPEN_READ;
    else if (strcmp(argv[2], "w") == 0) flags = OPEN_WRITE;
    else if (strcmp(argv[2], "a") == 0) flags = OPEN_APPEND | OPEN_WRITE;
    else { printf("无效模式。请使用 r, w, 或 a。\n"); return; }
    int fd_idx = open_file_op(argv[1], flags);
    if (fd_idx != -1) printf("文件 '%s' 已打开，文件描述符: %d\n", argv[1], fd_idx);
}
void handle_close(int argc, char *argv[]) {
    int fd_idx = atoi(argv[1]);
    if (close_file_op(fd_idx) == 0) printf("文件描述符 %d 已关闭。\n", fd_idx);
}
void handle_write(int argc, char *argv[]) {
    int fd_idx = atoi(argv[1]);
    char *line_ptr = strstr(strstr(argv[0], argv[1]), argv[2]);
    if (!line_ptr) { printf("用法: write <fd> <文本>\n"); return;}
    int written = write_file_op(fd_idx, line_ptr, strlen(line_ptr));
    if (written != -1) printf("已向文件描述符 %d 写入 %d 字节。\n", fd_idx, written);
}
void handle_read(int argc, char *argv[]) {
    int fd_idx = atoi(argv[1]);
    int read_size = atoi(argv[2]);
    if (read_size <= 0) return;
    char *read_buffer = malloc(read_size + 1);
    if (!read_buffer) { perror("malloc"); return; }
    int bytes_read = read_file_op(fd_idx, read_buffer, read_size);
    if (bytes_read != -1) {
        read_buffer[bytes_read] = '\0';
        printf("从 fd %d 读取 %d 字节: \"%s\"\n", fd_idx, bytes_read, read_buffer);
    }
    free(read_buffer);
}
void handle_help(int argc, char *argv[]);

const Command commands[] = {
    {"format", handle_format, 1, "用法: format"},
    {"ls", handle_ls, 1, "用法: ls [目录路径]"},
    {"cd", handle_cd, 2, "用法: cd <目录路径>"},
    {"mkdir", handle_mkdir, 2, "用法: mkdir <目录路径>"},
    {"rmdir", handle_rmdir, 2, "用法: rmdir <目录路径>"},
    {"touch", handle_touch, 2, "用法: touch <文件路径>"},
    {"rm", handle_rm, 2, "用法: rm <文件路径>"},
    {"open", handle_open, 3, "用法: open <文件路径> <模式:r|w|a>"},
    {"close", handle_close, 2, "用法: close <文件描述符>"},
    {"write", handle_write, 3, "用法: write <文件描述符> <文本...>"},
    {"read", handle_read, 3, "用法: read <文件描述符> <大小>"},
    {"help", handle_help, 1, "用法: help"}
};
const int NUM_COMMANDS = sizeof(commands) / sizeof(Command);
void handle_help(int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("可用命令列表:\n");
    for(int i=0; i<NUM_COMMANDS; ++i) {
        printf("  %s\n", commands[i].usage);
    }
}

int main() {
    init_disk_memory();
    mount_filesystem();
    char command_line_orig[256];
    char command_line_copy[256];
    char *argv[32];
    int argc;
    printf("\n--- 简单文件系统 Shell ---\n");
    printf("输入 'help' 获取命令列表, 'exit' 退出。\n");
    while (1) {
        printf("\n");
        print_current_path();
        if (fgets(command_line_orig, sizeof(command_line_orig), stdin) == NULL) break;
        strcpy(command_line_copy, command_line_orig);
        argc = 0;
        char *token = strtok(command_line_copy, " \t\n");
        while(token != NULL && argc < 31) {
            argv[argc++] = token;
            token = strtok(NULL, " \t\n");
        }
        argv[argc] = NULL;
        if (argc == 0) continue;
        if (strcmp(argv[0], "exit") == 0) break;
        int found = 0;
        for (int i = 0; i < NUM_COMMANDS; i++) {
            if (strcmp(argv[0], commands[i].name) == 0) {
                if (argc < commands[i].min_args) {
                    printf("%s\n", commands[i].usage);
                } else {
                    if (commands[i].handler == handle_write) {
                         argv[0] = command_line_orig;
                    }
                    commands[i].handler(argc, argv);
                }
                found = 1;
                break;
            }
        }
        if (!found) printf("未知命令: %s\n", argv[0]);
    }
    unmount_filesystem();
    return 0;
}

