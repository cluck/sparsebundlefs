/*
 * Copyright (c) 2012-2016 Tor Arne Vestbø. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
#include <list>
#include <sstream>
#include <streambuf>
#include <string>
#include <vector>

#include <fuse.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

#define FUSE_SUPPORTS_ZERO_COPY FUSE_VERSION >= 29

/* TODO:
 *  - Replace off_t (signed) with size_t (unsigned)
 */

using namespace std;

static const char image_path[] = "/sparsebundle.dmg";
unsigned int max_open_files = 128;

struct sparsebundle_band_t {
    int fh;
    int errnr;
    int mode;
    struct stat stat;
};

struct sparsebundle_t {
    char *path;
    char *mountpoint;
    off_t band_size;
    off_t size;
    off_t times_opened;
    bool readonly;
    map<string, sparsebundle_band_t> open_files;
    list<string> lru_files;
};

static sparsebundle_band_t sparsebundle_rw_buf_prepare_file(sparsebundle_t* sparsebundle, const char *path, bool write_intent);

#define sparsebundle_current() \
    static_cast<sparsebundle_t *>(fuse_get_context()->private_data)

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
    if (strcmp(path, image_path) != 0)
        return -ENOENT;

    sparsebundle_t *sparsebundle = sparsebundle_current();

    sparsebundle->times_opened++;

    syslog(LOG_INFO, "opened %s %s%s, now referenced %ju times",
        (sparsebundle->readonly ? "read-only" : "read-write"),
        sparsebundle->mountpoint, path, uintmax_t(sparsebundle->times_opened));

    return 0;
}

struct sparsebundle_rw_operations {
    int (*process_band) (sparsebundle_t*, off_t, const char *, size_t, off_t, void*);
    int (*pad_with_zeroes) (sparsebundle_t*, size_t, void*);
    void *data;
    bool write;
};

static int sparsebundle_iterate_bands(sparsebundle_t* sparsebundle, const char *path, size_t length, off_t offset,
           struct sparsebundle_rw_operations *rw_ops)
{
    if (strcmp(path, image_path) != 0)
        return -ENOENT;

    if (offset >= sparsebundle->size)
        return 0;

    if (offset < 0)
        return 0;

    if (length + (size_t)offset > (size_t)sparsebundle->size)
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
        free(band_path);

        if (rw < 0) {
            return -errno;
        }

        if (rw_ops->pad_with_zeroes != NULL && rw < to_rw) {
            to_rw = to_rw - rw;
            syslog(LOG_DEBUG, "missing %zu bytes from band %jx, padding with zeroes",
                to_rw, uintmax_t(band_number));
            rw += rw_ops->pad_with_zeroes(sparsebundle, to_rw, rw_ops->data);
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

    sparsebundle_band_t band;
    band = sparsebundle_rw_buf_prepare_file(sparsebundle, band_path, false);

    if (band.errnr != 0) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(band.errnr));
        return -band.errnr;
    }

    read = pread(band.fh, *buffer, length, offset);

    if (read == -1) {
        syslog(LOG_ERR, "failed to read band: %s", strerror(errno));
        return -errno;
    }

    *buffer += read;

    return read;
}

static int sparsebundle_read_pad_with_zeroes(sparsebundle_t* sparsebundle, size_t length, void *read_data)
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
    sparsebundle_t *sparsebundle = sparsebundle_current();
    
    sparsebundle_rw_operations rw_ops = {
        &sparsebundle_read_process_band,
        sparsebundle_read_pad_with_zeroes,
        &buffer,
        false
    };

    return sparsebundle_iterate_bands(sparsebundle, path, length, offset, &rw_ops);
}

static sparsebundle_band_t sparsebundle_rw_buf_prepare_file(sparsebundle_t* sparsebundle, const char *path, bool write_intent)
{
    sparsebundle_band_t band;
    map<string, sparsebundle_band_t>::const_iterator iter = sparsebundle->open_files.find(path);
    errno = 0;

    if (iter != sparsebundle->open_files.end()) {
        if (write_intent == true && (iter->second.mode & O_RDWR) != O_RDWR) {
            if (iter->second.fh != -1) {
                syslog(LOG_DEBUG, "file %s is opened read-only, re-opening read-write", path);
                close(iter->second.fh);
            } else {
                syslog(LOG_DEBUG, "file %s does not exist yet, creating", path);
            }
            band.fh = open(path, O_RDWR | O_CREAT, 0644);
            band.errnr = errno;
            band.mode = O_RDWR | O_CREAT;
            stat(path, &band.stat);

            sparsebundle->open_files[path] = band;
        } else {
            band = iter->second;
        }
    } else {

        if (sparsebundle->lru_files.size() >= max_open_files) {
            syslog(LOG_INFO, "too many open files, closing least recently opened bands");
            while (sparsebundle->lru_files.size()*2 >= max_open_files) {
                const char* lru_path = sparsebundle->lru_files.back().c_str();
                sparsebundle->lru_files.pop_back();
                close(sparsebundle->open_files[lru_path].fh);
                sparsebundle->open_files.erase(lru_path);
           }
        }

        if (sparsebundle->readonly == true || write_intent == false) {
            if (stat(path, &band.stat) == 0) {
                syslog(LOG_DEBUG, "file %s not opened yet, opening read-only", path);
                band.fh = open(path, O_RDONLY);
                band.errnr = errno;
                band.mode = O_RDONLY;
            } else {
                syslog(LOG_DEBUG, "delaying creation of new band file %s until first write", path);
                band.fh = -1;
                band.errnr = 0;
                band.mode = O_RDONLY;
            }
        } else {
            syslog(LOG_DEBUG, "file %s not opened yet, opening read-write", path);
            band.fh = open(path, O_RDWR | O_CREAT, 0644);
            band.errnr = errno;
            band.mode = O_RDWR | O_CREAT;
            stat(path, &band.stat);
        }
        sparsebundle->lru_files.push_front(path);
        sparsebundle->open_files[path] = band;
    }

    return band;
}

#if FUSE_SUPPORTS_ZERO_COPY
static int sparsebundle_read_buf_process_band(sparsebundle_t* sparsebundle, off_t band_number,
    const char *band_path, size_t length, off_t offset, void *read_data)
{
    ssize_t read = 0;

    vector<fuse_buf> *buffers = static_cast<vector<fuse_buf>*>(read_data);

    sparsebundle_band_t band = sparsebundle_rw_buf_prepare_file(sparsebundle, band_path, false);
    if (band.errnr != 0) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(errno));
        return -errno;
    }

    syslog(LOG_DEBUG, "preparing %zu bytes at offset %ju", length,
        uintmax_t(offset));

    read += max(off_t(0), min(static_cast<off_t>(length), band.stat.st_size - offset));

    if (read > 0) {
        fuse_buf buffer = { read, fuse_buf_flags(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK), 0, band.fh, offset };
        buffers->push_back(buffer);
    }

    return read;
}

static const char zero_device[] = "/dev/zero";

static int sparsebundle_read_buf_pad_with_zeroes(sparsebundle_t* sparsebundle, size_t length, void *read_data)
{
    vector<fuse_buf> *buffers = static_cast<vector<fuse_buf>*>(read_data);
    sparsebundle_band_t zero_band = sparsebundle_rw_buf_prepare_file(sparsebundle, zero_device, false);
    fuse_buf buffer = { length, fuse_buf_flags(FUSE_BUF_IS_FD), 0, zero_band.fh, 0 };
    buffers->push_back(buffer);

    return length;
}

static void sparsebundle_rw_close_files()
{
    sparsebundle_t *sparsebundle = sparsebundle_current();

    syslog(LOG_DEBUG, "closing %lu open file(s)", sparsebundle->lru_files.size());

    while (sparsebundle->lru_files.size() > 0) {
        const char* path = sparsebundle->lru_files.back().c_str();
        sparsebundle->lru_files.pop_back();
        close(sparsebundle->open_files[path].fh);
        sparsebundle->open_files.erase(path);
    }
}

static int sparsebundle_read_buf(const char *path, struct fuse_bufvec **bufp,
                        size_t length, off_t offset, struct fuse_file_info *fi)
{
    int ret = 0;

    vector<fuse_buf> buffers;
    
    sparsebundle_t *sparsebundle = sparsebundle_current();

    sparsebundle_rw_operations read_ops = {
        &sparsebundle_read_buf_process_band,
        sparsebundle_read_buf_pad_with_zeroes,
        &buffers,
        false
    };

    syslog(LOG_DEBUG, "asked to read %zu bytes at offset %ju using zero-copy read",
        length, uintmax_t(offset));

    ret = sparsebundle_iterate_bands(sparsebundle, path, length, offset, &read_ops);
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

/* ========== add here write ops ========= */

static int sparsebundle_write_process_band(sparsebundle_t* sparsebundle, off_t band_number,
        const char *band_path, size_t length, off_t offset, void *write_data)
{
    if (sparsebundle->readonly == true)
        return -EACCES;

    ssize_t write = 0;

    char** buffer = (char**)write_data;

    sparsebundle_band_t band;
    band = sparsebundle_rw_buf_prepare_file(sparsebundle, band_path, true);

    syslog(LOG_DEBUG, "writing %zu bytes at offset %ju from %p",
        length, uintmax_t(offset), *buffer);

    if (band.errnr != 0) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(band.errnr));
        return -band.errnr;
    }

    write = pwrite(band.fh, *buffer, length, offset);

    if (write == -1) {
        syslog(LOG_ERR, "failed to write band: %s", strerror(errno));
        return -errno;
    }

    *buffer += write;

    return write;
}

static int sparsebundle_write(const char *path, const char *buffer, size_t length,
        off_t offset, struct fuse_file_info *fi)
{
    sparsebundle_t *sparsebundle = sparsebundle_current();

    sparsebundle_rw_operations write_ops = {
        &sparsebundle_write_process_band,
        NULL,
        &buffer,
        true
    };

    return sparsebundle_iterate_bands(sparsebundle, path, length, offset, &write_ops);
}

static int sparsebundle_truncate(const char *path, off_t size)
{
    ssize_t truncate = 0;
    return truncate;
}

#if FUSE_SUPPORTS_ZERO_COPY

// new
static int sparsebundle_write_buf_process_band(sparsebundle_t* sparsebundle, off_t band_number,
    const char *band_path, size_t length, off_t offset, void *write_data)
{
    ssize_t written = 0;

    sparsebundle_band_t band = sparsebundle_rw_buf_prepare_file(sparsebundle, band_path, true);
    if (band.errnr != 0) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(errno));
        return -errno;
    }

    //vector<fuse_buf> buffers = vector<fuse_buf>((fuse_buf*)write_data);
    struct fuse_bufvec *buffers = (fuse_bufvec*)write_data;
    struct fuse_bufvec band_buffer = FUSE_BUFVEC_INIT(length);

    band_buffer.buf[0].flags = (fuse_buf_flags)(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
    band_buffer.buf[0].fd = band.fh;
    band_buffer.buf[0].pos = offset;

    syslog(LOG_DEBUG, "splicing %zu bytes at offset %ju", length,
        uintmax_t(offset));

    fuse_buf_copy(&band_buffer, buffers, FUSE_BUF_SPLICE_NONBLOCK);

    return length;
}

// new
static int sparsebundle_write_buf(const char *path, struct fuse_bufvec *bufp,
                        off_t offset, struct fuse_file_info *fi)
{
    int ret = 0;

    //vector<fuse_buf> buffers;
    
    sparsebundle_t *sparsebundle = sparsebundle_current();

    sparsebundle_rw_operations write_ops = {
        &sparsebundle_write_buf_process_band,
        NULL,
        bufp,
        true
    };

    size_t length = fuse_buf_size(bufp);

    syslog(LOG_DEBUG, "asked to write %zu bytes at offset %ju using zero-copy write",
        length, uintmax_t(offset));

    return sparsebundle_iterate_bands(sparsebundle, path, length, offset, &write_ops);
}

#endif

/* ==========  end of write ops ======== */

static int sparsebundle_fsync(const char *path, int datasync, struct fuse_file_info *) {
    sparsebundle_t *sparsebundle = sparsebundle_current();
    
    syslog(LOG_DEBUG, "fsync");

    if (!sparsebundle->open_files.empty())
        sparsebundle_rw_close_files();
}

static int sparsebundle_release(const char *path, struct fuse_file_info *)
{
    sparsebundle_t *sparsebundle = sparsebundle_current();

    sparsebundle->times_opened--;
    syslog(LOG_DEBUG, "closed %s%s, now referenced %ju times",
        sparsebundle->mountpoint, path, uintmax_t(sparsebundle->times_opened));

    if (sparsebundle->times_opened == 0) {
        if (!sparsebundle->open_files.empty())
            sparsebundle_rw_close_files();
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

enum { SPARSEBUNDLE_OPT_HANDLED = 0, SPARSEBUNDLE_OPT_IGNORED = 1,
       SPARSEBUNDLE_OPT_WRITE = 2, SPARSEBUNDLE_OPT_VERBOSE = 3, SPARSEBUNDLE_OPT_DEBUG = 4 };

static int sparsebundle_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    sparsebundle_t *sparsebundle = (struct sparsebundle_t*)data;

    switch (key) {
    case SPARSEBUNDLE_OPT_DEBUG:
        setlogmask(LOG_UPTO(LOG_DEBUG));
        return SPARSEBUNDLE_OPT_HANDLED;

    case SPARSEBUNDLE_OPT_VERBOSE:
        setlogmask(LOG_UPTO(LOG_INFO));
        return SPARSEBUNDLE_OPT_HANDLED;

    case SPARSEBUNDLE_OPT_WRITE:
        sparsebundle->readonly = false;
        return SPARSEBUNDLE_OPT_HANDLED;

    case FUSE_OPT_KEY_NONOPT:
        sparsebundle_t *sparsebundle = static_cast<sparsebundle_t *>(data);

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
        FUSE_OPT_KEY("-w",  SPARSEBUNDLE_OPT_WRITE),
        FUSE_OPT_KEY("-v",  SPARSEBUNDLE_OPT_VERBOSE),
        FUSE_OPT_KEY("-D",  SPARSEBUNDLE_OPT_DEBUG),
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
    sparsebundle_filesystem_operations.write_buf = sparsebundle_write_buf;
#endif
    sparsebundle_filesystem_operations.fsync = sparsebundle_fsync;
    sparsebundle_filesystem_operations.write = sparsebundle_write;
    sparsebundle_filesystem_operations.truncate = sparsebundle_truncate;

    return fuse_main(args.argc, args.argv, &sparsebundle_filesystem_operations, &sparsebundle);
}
