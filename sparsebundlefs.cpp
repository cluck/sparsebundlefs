#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <streambuf>
#include <string>
#include <vector>

#include <fuse.h>

#include <libxml/parser.h>
// #include <libxml/tree.h>
#include <libxml/xpath.h>

#define FUSE_SUPPORTS_ZERO_COPY FUSE_VERSION >= 29

using namespace std;

static const char image_path[] = "/sparsebundle.dmg";

struct sparsebundle_t {
    char *path;
    char *mountpoint;
    bool readonly;
    off_t band_size;
    off_t size;
    off_t times_opened;
    bool current_band_write;
    int current_band_file;
    int current_band;
#if FUSE_SUPPORTS_ZERO_COPY
    map<string, int> open_files;
#endif
};

#define sparsebundle_cast(ptr) ((struct sparsebundle_t *) ptr)
#define sparsebundle_current() (sparsebundle_cast(fuse_get_context()->private_data))

static int sparsebundle_getattr(const char *path, struct stat *stbuf)
{
    sparsebundle_t *sparsebundle = sparsebundle_current();

    memset(stbuf, 0, sizeof(struct stat));

    struct stat bundle_stat;
    stat(sparsebundle->path, &bundle_stat);

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | (sparsebundle->readonly == false ? 0777 : 0555);
        stbuf->st_nlink = 3;
        stbuf->st_size = sizeof(sparsebundle_t);
    } else if (strcmp(path, image_path) == 0) {
        stbuf->st_mode = S_IFREG | (sparsebundle->readonly == false ? 0666 : 0444);
        stbuf->st_nlink = 1;
        stbuf->st_size = sparsebundle->size;
    } else
        return -ENOENT;

    stbuf->st_uid = bundle_stat.st_uid;
    stbuf->st_gid = bundle_stat.st_gid;
    stbuf->st_atime = bundle_stat.st_atime;
    stbuf->st_mtime = bundle_stat.st_mtime;
    stbuf->st_ctime = bundle_stat.st_ctime;

    return 0;
}

static int sparsebundle_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
              off_t offset, struct fuse_file_info *)
{
    if (strcmp(path, "/") != 0)
        return -ENOENT;

    struct stat image_stat;
    sparsebundle_getattr(image_path, &image_stat);

    filler(buf, ".", 0, 0);
    filler(buf, "..", 0, 0);
    filler(buf, image_path + 1, &image_stat, 0);

    return 0;
}

static int sparsebundle_open(const char *path, struct fuse_file_info *fi)
{
    sparsebundle_t *sparsebundle = sparsebundle_current();

    if (strcmp(path, image_path) != 0)
        return -ENOENT;

    /* FIXME TODO: what is this test for? */
    // if ((fi->flags & O_ACCMODE) != (sparsebundle->readonly == true ? O_RDWR : O_RDONLY))
    //    return -EACCES;

    sparsebundle->times_opened++;

    if (sparsebundle->times_opened == 1) {
        sparsebundle->current_band_write = false;
        sparsebundle->current_band_file = -1;
        sparsebundle->current_band = 0;
    }

    syslog(LOG_DEBUG, "opened %s%s, now referenced %ju times",
        sparsebundle->mountpoint, path, uintmax_t(sparsebundle->times_opened));

    return 0;
}

struct sparsebundle_rw_operations {
    int (*process_band) (sparsebundle_t*, off_t, const char *, size_t, off_t, void*);
    int (*pad_with_zeroes) (size_t, void*);
    void *data;
    bool write;
};

static int sparsebundle_iterate_bands(const char *path, size_t length, off_t offset,
           struct sparsebundle_rw_operations *rw_ops)
{
    if (strcmp(path, image_path) != 0)
        return -ENOENT;

    sparsebundle_t *sparsebundle = sparsebundle_current();

    if (offset >= sparsebundle->size)
        return 0;

    if (offset < 0)
        return 0;

    if (length + (size_t)offset > sparsebundle->size)
        length = sparsebundle->size - (size_t)offset;

    syslog(LOG_DEBUG, "iterating %zu bytes at offset %ju", length, uintmax_t(offset));

    size_t bytes_rw = 0;
    while (bytes_rw < length) {
        off_t band_number = (offset + bytes_rw) / sparsebundle->band_size;
        off_t band_offset = (offset + bytes_rw) % sparsebundle->band_size;

        ssize_t to_rw = min(static_cast<off_t>(length - bytes_rw),
            sparsebundle->band_size - band_offset);

        char *band_path;
        if (asprintf(&band_path, "%s/bands/%jx", sparsebundle->path, uintmax_t(band_number)) == -1) {
            syslog(LOG_ERR, "failed to resolve band name");
            return -errno;
        }

        syslog(LOG_DEBUG, "processing %zu bytes from band %jx at offset %ju",
            to_rw, uintmax_t(band_number), uintmax_t(band_offset));

        ssize_t rw = rw_ops->process_band(sparsebundle, band_number, band_path, to_rw, band_offset, rw_ops->data);
        if (rw < 0) {
            free(band_path);
            return -errno;
        }

        free(band_path);

        if (rw_ops->pad_with_zeroes != NULL && rw < to_rw) {
            to_rw = to_rw - rw;
            syslog(LOG_DEBUG, "missing %zu bytes from band %jx, padding with zeroes",
                to_rw, uintmax_t(band_number));
            rw += rw_ops->pad_with_zeroes(to_rw, rw_ops->data);
        }

        bytes_rw += rw;

        if (rw_ops->write == false)
            syslog(LOG_DEBUG, "done processing band %jx, %zu bytes left to read",
                uintmax_t(band_number), length - bytes_rw);
        else
            syslog(LOG_DEBUG, "done processing band %jx, %zu bytes left to write",
                uintmax_t(band_number), length - bytes_rw);
    }

    assert(bytes_rw == length);
    return bytes_rw;
}

static int sparsebundle_read_process_band(sparsebundle_t* sparsebundle, off_t band_number,
        const char *band_path, size_t length, off_t offset, void *read_data)
{
    ssize_t read = 0;

    char** buffer = static_cast<char**>(read_data);

    syslog(LOG_DEBUG, "reading %zu bytes at offset %ju into %p",
        length, uintmax_t(offset), *buffer);

    int band_file;
    if (sparsebundle->current_band_file >= 0 && sparsebundle->current_band != band_number )
    {
        syslog(LOG_DEBUG, "closing previous band file %d", sparsebundle->current_band);
        close(sparsebundle->current_band_file);
        sparsebundle->current_band_file = -1;
    }
    if (sparsebundle->current_band_file < 0) {
#if FUSE_SUPPORTS_ZERO_COPY
        int band_file = sparsebundle_read_buf_prepare_file(band_path);
        if (band_file != -1) {
            sparsebundle->current_band_file = band_file;
            sparsebundle->current_band = band_number;
            sparsebundle->current_band_write = false;
        }
#else
        band_file = open(band_path, O_RDONLY);
        sparsebundle->current_band_file = band_file;
        sparsebundle->current_band = band_number;
        sparsebundle->current_band_write = false;
        if (band_file != -1)
            syslog(LOG_DEBUG, "opened new read band file %d", sparsebundle->current_band);
#endif
    } else {
        band_file = sparsebundle->current_band_file;
        //syslog(LOG_DEBUG, "reusing open band file %d", sparsebundle->current_band);
    }

    if (band_file != -1) {
        read = pread(band_file, *buffer, length, offset);

        if (read == -1) {
            syslog(LOG_ERR, "failed to read band: %s", strerror(errno));
            return -errno;
        }
    } else if (errno != ENOENT && errno != EACCES) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(errno));
        return -errno;
    }

    *buffer += read;

    return read;
}

static int sparsebundle_read_pad_with_zeroes(size_t length, void *read_data)
{
    char** buffer = static_cast<char**>(read_data);

    syslog(LOG_DEBUG, "padding %zu bytes of zeroes into %p", length, *buffer);

    memset(*buffer, 0, length);
    *buffer += length;

    return length;
}

static int sparsebundle_read(const char *path, char *buffer, size_t length, off_t offset,
           struct fuse_file_info *)
{
    sparsebundle_rw_operations read_ops = {
        &sparsebundle_read_process_band,
        sparsebundle_read_pad_with_zeroes,
        &buffer,
        false
    };

    syslog(LOG_DEBUG, "asked to read %zu bytes at offset %ju", length, uintmax_t(offset));

    return sparsebundle_iterate_bands(path, length, offset, &read_ops);
}

#if FUSE_SUPPORTS_ZERO_COPY
int sparsebundle_read_buf_prepare_file(const char *path)
{
    int fd = -1;
    map<string, int>::const_iterator iter = sparsebundle->open_files.find(path);
    if (iter != sparsebundle->open_files.end()) {
        fd = iter->second;
    } else {
        syslog(LOG_DEBUG, "file %s not opened yet, opening", path);
        sparsebundle_t *sparsebundle = sparsebundle_current();
        if (sparsebundle->readonly == false)
            fd = open(path, O_RDWR | O_CREAT, 0644);
        else
            fd = open(path, O_RDONLY);
        sparsebundle->open_files[path] = fd;
    }

    return fd;
}

static int sparsebundle_read_buf_process_band(const char *band_path, size_t length, off_t offset, void *read_data)
{
    ssize_t read = 0;

    vector<fuse_buf> *buffers = static_cast<vector<fuse_buf>*>(read_data);

    syslog(LOG_DEBUG, "preparing %zu bytes at offset %ju", length,
        uintmax_t(offset));

    int band_file_fd = sparsebundle_read_buf_prepare_file(band_path);
    if (band_file_fd != -1) {
        struct stat band_stat;
        stat(band_path, &band_stat);
        read += max(off_t(0), min(static_cast<off_t>(length), band_stat.st_size - offset));
    } else if (errno != ENOENT && errno != EACCES) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(errno));
        return -errno;
    }

    if (read > 0) {
        fuse_buf buffer = { read, fuse_buf_flags(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK), 0, band_file_fd, offset };
        buffers->push_back(buffer);
    }

    return read;
}

static const char zero_device[] = "/dev/zero";

static int sparsebundle_read_buf_pad_with_zeroes(size_t length, void *read_data)
{
    vector<fuse_buf> *buffers = static_cast<vector<fuse_buf>*>(read_data);
    int zero_device_fd = sparsebundle_read_buf_prepare_file(zero_device);
    fuse_buf buffer = { length, fuse_buf_flags(FUSE_BUF_IS_FD), 0, zero_device_fd, 0 };
    buffers->push_back(buffer);

    return length;
}

static void sparsebundle_read_buf_close_files()
{
    syslog(LOG_DEBUG, "closing %u open file descriptor(s)", sparsebundle->open_files.size());

    map<string, int>::iterator iter;
    for(iter = sparsebundle->open_files.begin(); iter != sparsebundle->open_files.end(); ++iter)
        close(iter->second);

    sparsebundle->open_files.clear();
}

static int sparsebundle_read_buf(const char *path, struct fuse_bufvec **bufp,
                        size_t length, off_t offset, struct fuse_file_info *fi)
{
    int ret = 0;

    vector<fuse_buf> buffers;

    sparsebundle_rw_operations read_ops = {
        &sparsebundle_read_buf_process_band,
        sparsebundle_read_buf_pad_with_zeroes,
        &buffers,
        false
    };

    syslog(LOG_DEBUG, "asked to read %zu bytes at offset %ju using zero-copy read",
        length, uintmax_t(offset));

    static struct rlimit fd_limit = { -1, -1 };
    if (fd_limit.rlim_cur < 0)
        getrlimit(RLIMIT_NOFILE, &fd_limit);

    if (sparsebundle->open_files.size() + 1 >= fd_limit.rlim_cur) {
        syslog(LOG_DEBUG, "hit max number of file descriptors");
        sparsebundle_read_buf_close_files();
    }

    ret = sparsebundle_iterate_bands(path, length, offset, &read_ops);
    if (ret < 0)
        return ret;

    size_t bufvec_size = sizeof(struct fuse_bufvec) + (sizeof(struct fuse_buf) * (buffers.size() - 1));
    struct fuse_bufvec *buffer_vector = static_cast<fuse_bufvec*>(malloc(bufvec_size));
    if (buffer_vector == 0)
        return -ENOMEM;

    buffer_vector->count = buffers.size();
    buffer_vector->idx = 0;
    buffer_vector->off = 0;

    copy(buffers.begin(), buffers.end(), buffer_vector->buf);

    syslog(LOG_DEBUG, "returning %d buffers to fuse", buffer_vector->count);
    *bufp = buffer_vector;

    return ret;
}
#endif

static int sparsebundle_write_process_band(sparsebundle_t* sparsebundle, off_t band_number,
        const char *band_path, size_t length, off_t offset, void *write_data)
{
    if (sparsebundle->readonly == true)
        return -EACCES;

    ssize_t write = 0;

    char** buffer = (char**)write_data;

    syslog(LOG_DEBUG, "writing %zu bytes at offset %ju from %p",
        length, uintmax_t(offset), *buffer);

    int band_file;
    if (sparsebundle->current_band_file >= 0 && (
        sparsebundle->current_band != band_number ||
        sparsebundle->current_band_write == false))
    {
        syslog(LOG_DEBUG, "closing previous band file %d", sparsebundle->current_band);
        close(sparsebundle->current_band_file);
        sparsebundle->current_band_file = -1;
    }
    if (sparsebundle->current_band_file < 0) {
#if FUSE_SUPPORTS_ZERO_COPY
        int band_file = sparsebundle_read_buf_prepare_file(band_path);
        if (band_file != -1) {
            sparsebundle->current_band_file = band_file;
            sparsebundle->current_band = band_number;
            sparsebundle->current_band_write = true;
        }
#else
        band_file = open(band_path, O_RDWR | O_CREAT, 0644);
        sparsebundle->current_band_file = band_file;
        sparsebundle->current_band = band_number;
        sparsebundle->current_band_write = true;
        if (band_file != -1)
            syslog(LOG_DEBUG, "opened new write band %d", sparsebundle->current_band);
#endif
    } else {
        band_file = sparsebundle->current_band_file;
        //syslog(LOG_DEBUG, "reusing open write band %d", sparsebundle->current_band);
    }

    if (band_file != -1) {
        write = pwrite(band_file, *buffer, length, offset);

        if (write == -1) {
            syslog(LOG_ERR, "failed to write band: %s", strerror(errno));
            return -errno;
        }
    } else if (errno != ENOENT && errno != EACCES) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(errno));
        return -errno;
    }

    *buffer += write;

    return write;
}


static int sparsebundle_write(const char *path, const char *buffer, size_t length,
        off_t offset, struct fuse_file_info *fi)
{
    sparsebundle_rw_operations write_ops = {
        &sparsebundle_write_process_band,
        NULL,
        &buffer,
        true
    };

    syslog(LOG_DEBUG, "asked to write %zu bytes at offset %ju", length, uintmax_t(offset));

    return sparsebundle_iterate_bands(path, length, offset, &write_ops);
}

static int sparsebundle_truncate(const char *path, off_t size)
{
    ssize_t truncate = 0;
    return truncate;
}

static int sparsebundle_release(const char *path, struct fuse_file_info *)
{
    sparsebundle_t *sparsebundle = sparsebundle_current();

    if (sparsebundle->current_band_file != -1) {
        syslog(LOG_DEBUG, "closing previous band file %d", sparsebundle->current_band);
        close(sparsebundle->current_band_file);
        sparsebundle->current_band_file = -1;
    }

    sparsebundle->times_opened--;
    syslog(LOG_DEBUG, "closed %s%s, now referenced %ju times",
        sparsebundle->mountpoint, path, uintmax_t(sparsebundle->times_opened));

    if (sparsebundle->times_opened == 0) {
        syslog(LOG_DEBUG, "no more references, cleaning up");

#if FUSE_SUPPORTS_ZERO_COPY
        if (!sparsebundle->open_files.empty())
            sparsebundle_read_buf_close_files();
#endif
    }

    return 0;
}

__attribute__((noreturn, format(printf, 1, 2))) static void sparsebundle_fatal_error(const char *message, ...)
{
    fprintf(stderr, "sparsebundlefs: ");

    va_list args;
    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);

    if (errno)
        fprintf(stderr, ": %s", strerror(errno));

    fprintf(stderr, "\n");

    exit(EXIT_FAILURE);
}

static int sparsebundle_show_usage(char *program_name)
{
    fprintf(stderr, "usage: %s [-o options] [-s] [-f] [-D] [-w] <sparsebundle> <mountpoint>\n", program_name);
    return 1;
}

enum { SPARSEBUNDLE_OPT_DEBUG = 0, SPARSEBUNDLE_OPT_HANDLED = 0, SPARSEBUNDLE_OPT_IGNORED = 1, SPARSEBUNDLE_OPT_WRITE = 2 };

static int sparsebundle_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    sparsebundle_t *sparsebundle = sparsebundle_cast(data);

    switch (key) {
    case SPARSEBUNDLE_OPT_DEBUG:
        setlogmask(LOG_UPTO(LOG_DEBUG));
        return SPARSEBUNDLE_OPT_HANDLED;

    case SPARSEBUNDLE_OPT_WRITE:
        sparsebundle->readonly = false;
        return SPARSEBUNDLE_OPT_HANDLED;

    case FUSE_OPT_KEY_NONOPT:
        if (!sparsebundle->path) {
            sparsebundle->path = realpath(arg, 0);
            if (!sparsebundle->path)
                sparsebundle_fatal_error("bad sparse-bundle `%s'", arg);
            return SPARSEBUNDLE_OPT_HANDLED;
        } else if (!sparsebundle->mountpoint) {
            sparsebundle->mountpoint = realpath(arg, 0);
            if (!sparsebundle->mountpoint)
                sparsebundle_fatal_error("bad mount point `%s'", arg);
            fuse_opt_add_arg(outargs, sparsebundle->mountpoint);
            return SPARSEBUNDLE_OPT_HANDLED;
        }

        return SPARSEBUNDLE_OPT_IGNORED;
    }

    return SPARSEBUNDLE_OPT_IGNORED;
}

static off_t read_size(const string &str)
{
    uintmax_t value = strtoumax(str.c_str(), 0, 10);
    if (errno == ERANGE || value > uintmax_t(numeric_limits<off_t>::max()))
        sparsebundle_fatal_error("disk image too large (%s bytes)", str.c_str());

    return value;
}

xmlXPathObjectPtr getnodeset(xmlDocPtr doc, xmlChar *xpath) 
{    
    xmlXPathContextPtr context;
    xmlXPathObjectPtr result;

    context = xmlXPathNewContext(doc);
    if (context == NULL) {
        printf("Error in xmlXPathNewContext\n");
        return NULL;
    }
    result = xmlXPathEvalExpression(xpath, context);
    xmlXPathFreeContext(context);
    if (result == NULL) {
        printf("Error in xmlXPathEvalExpression\n");
        return NULL;
    }
    if(xmlXPathNodeSetIsEmpty(result->nodesetval)){
        xmlXPathFreeObject(result);
                printf("No result\n");
        return NULL;
    }
    return result;
}

const char* plist_get_value(xmlDocPtr doc, const char* key_type, const char* key_name)
{
    int i;
    xmlXPathObjectPtr qResult;
    xmlNodeSetPtr nodeset;
    xmlChar* value = NULL;
    const char *xpath_tpl = "/plist[@version=\"1.0\"]/dict/%s[preceding-sibling::key[1]/text()=\"%s\"]";
    char* xpathCharQuery;
    if (asprintf(&xpathCharQuery, xpath_tpl, key_type, key_name) == -1)
        return NULL;
    qResult = getnodeset(doc, (xmlChar*)xpathCharQuery);
    free(xpathCharQuery);
    if (qResult != NULL) {
        nodeset = qResult->nodesetval;
        for (i=0; i < nodeset->nodeNr; i++) {
            value = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
            syslog(LOG_DEBUG, "Plist key=%s: value=%s (type %s)", key_name, (char*)value, key_type);
            break;
        }
        xmlXPathFreeObject (qResult);
    } else {
        syslog(LOG_DEBUG, "Plist error on key %s (type %s)", key_name, key_type);
    }
    return (char*)value;
}

int main(int argc, char **argv)
{
    openlog("sparsebundlefs", LOG_CONS | LOG_PERROR, LOG_USER);
    setlogmask(~(LOG_MASK(LOG_DEBUG)));

    struct sparsebundle_t sparsebundle = {};
    sparsebundle.readonly = true;

    static struct fuse_opt sparsebundle_options[] = {
        FUSE_OPT_KEY("-D",  SPARSEBUNDLE_OPT_DEBUG),
        FUSE_OPT_KEY("-w",  SPARSEBUNDLE_OPT_WRITE),
        { 0, 0, 0 } // End of options
    };

    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    fuse_opt_parse(&args, &sparsebundle, sparsebundle_options, sparsebundle_opt_proc);

    if (sparsebundle.readonly == true)
        fuse_opt_add_arg(&args, "-oro"); // Force read-only mount

    if (!sparsebundle.path || !sparsebundle.mountpoint)
        return sparsebundle_show_usage(argv[0]);

    syslog(LOG_DEBUG, "mounting `%s' at mount-point `%s'",
        sparsebundle.path, sparsebundle.mountpoint);

    char *plist_path;
    const char* size;
    const char* band_size;
    if (asprintf(&plist_path, "%s/Info.plist", sparsebundle.path) == -1)
        sparsebundle_fatal_error("could not resolve Info.plist path");
    xmlDocPtr plist_doc;
    plist_doc = xmlParseFile(plist_path);
    free(plist_path);
    if (plist_doc == NULL) {
        sparsebundle_fatal_error("could not load XML document Info.plist");
    }

    band_size = plist_get_value(plist_doc, "integer", "band-size");
    if (band_size == NULL)
        sparsebundle_fatal_error("could not retrieve band-size from Info.plist");
    sparsebundle.band_size = read_size(band_size);
    xmlFree((void*)band_size);

    size = plist_get_value(plist_doc, "integer", "size");
    if (size == NULL)
        sparsebundle_fatal_error("could not retrieve size from Info.plist");
    sparsebundle.size = read_size(size);
    xmlFree((void*)size);

    xmlFreeDoc(plist_doc);
    xmlCleanupParser();
    
    /*
    ifstream plist_file(plist_path);
    stringstream plist_data;
    plist_data << plist_file.rdbuf();

    string key, line;
    while (getline(plist_data, line)) {
        static const char whitespace_chars[] = " \n\r\t";
        line.erase(0, line.find_first_not_of(whitespace_chars));
        line.erase(line.find_last_not_of(whitespace_chars) + 1);

        if (line.compare(0, 5, "<key>") == 0) {
            key = line.substr(5, line.length() - 11);
        } else if (!key.empty()) {
            line.erase(0, line.find_first_of('>') + 1);
            line.erase(line.find_first_of('<'));

            if (key == "band-size")
                sparsebundle.band_size = read_size(line);
            else if (key == "size")
                sparsebundle.size = read_size(line);

            key.clear();
        }
    }
    */

    syslog(LOG_DEBUG, "bundle has band size %ju and total size %ju",
        uintmax_t(sparsebundle.band_size), uintmax_t(sparsebundle.size));

    struct fuse_operations sparsebundle_filesystem_operations = {};
    sparsebundle_filesystem_operations.getattr = sparsebundle_getattr;
    sparsebundle_filesystem_operations.open = sparsebundle_open;
    sparsebundle_filesystem_operations.read = sparsebundle_read;
    sparsebundle_filesystem_operations.readdir = sparsebundle_readdir;
    sparsebundle_filesystem_operations.release = sparsebundle_release;
#if FUSE_SUPPORTS_ZERO_COPY
    sparsebundle_filesystem_operations.read_buf = sparsebundle_read_buf;
    // TODO @cluck: write_buf?
#endif
    sparsebundle_filesystem_operations.write = sparsebundle_write;
    sparsebundle_filesystem_operations.truncate = sparsebundle_truncate;

    return fuse_main(args.argc, args.argv, &sparsebundle_filesystem_operations, &sparsebundle);
}
