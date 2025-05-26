#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/mutex.h>

#define DEVICE_NAME "telegram_notifier"
#define BUF_LEN 512
MODULE_LICENSE("GPL");
static int major;
static char bot_token[BUF_LEN] = "";
static char chat_id[BUF_LEN] = "";
static char message[BUF_LEN] = "";

static DEFINE_MUTEX(telegram_mutex);

static void url_encode_basic(const char *src, char *dst, size_t dst_size) {
    static const char *hex = "0123456789ABCDEF";
    size_t i = 0, j = 0;
    while (src[i] && j + 3 < dst_size) {
        unsigned char c = src[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9')) {
            dst[j++] = c;
        } else if (c == ' ') {
            dst[j++] = '%'; dst[j++] = '2'; dst[j++] = '0';
        } else {
            dst[j++] = '%';
            dst[j++] = hex[c >> 4];
            dst[j++] = hex[c & 15];
        }
        i++;
    }
    dst[j] = '\0';
}

static int send_to_telegram(void) {
    char *argv[5];
    char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };

    char *url = kmalloc(BUF_LEN * 4, GFP_KERNEL);
    char *encoded_msg = kmalloc(BUF_LEN * 3, GFP_KERNEL);
    if (!url || !encoded_msg) {
        kfree(url); kfree(encoded_msg);
        return -ENOMEM;
    }

    mutex_lock(&telegram_mutex);
    url_encode_basic(message, encoded_msg, BUF_LEN * 3);
    snprintf(url, BUF_LEN * 4,
             "https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s",
             bot_token, chat_id, encoded_msg);
    mutex_unlock(&telegram_mutex);

    argv[0] = "/usr/bin/curl";
    argv[1] = "-s";
    argv[2] = "-k";
    argv[3] = url;
    argv[4] = NULL;

    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    kfree(url); kfree(encoded_msg);
    return ret;
}

static void parse_input(const char *input) {
    size_t len = strlen(input);
    if (len > 6 && strncmp(input, "TOKEN=", 6) == 0) {
        mutex_lock(&telegram_mutex);
        strncpy(bot_token, input + 6, BUF_LEN - 1);
        mutex_unlock(&telegram_mutex);
    } else if (len > 8 && strncmp(input, "CHAT_ID=", 8) == 0) {
        mutex_lock(&telegram_mutex);
        strncpy(chat_id, input + 8, BUF_LEN - 1);
        mutex_unlock(&telegram_mutex);
    } else if (len > 4 && strncmp(input, "MSG=", 4) == 0) {
        mutex_lock(&telegram_mutex);
        strncpy(message, input + 4, BUF_LEN - 1);
        mutex_unlock(&telegram_mutex);

        mutex_lock(&telegram_mutex);
        bool ready = strlen(bot_token) > 0 && strlen(chat_id) > 0;
        mutex_unlock(&telegram_mutex);

        if (ready)
            send_to_telegram();
    }
}

static ssize_t device_write(struct file *filp, const char *buffer, size_t length, loff_t *offset) {
    char input[BUF_LEN] = {0};
    if (length >= BUF_LEN)
        length = BUF_LEN - 1;
    if (copy_from_user(input, buffer, length))
        return -EFAULT;
    input[length] = '\0';
    char *newline = strchr(input, '\n');
    if (newline)
        *newline = '\0';
    parse_input(input);
    return length;
}

static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset) {
    char temp[BUF_LEN * 3];
    mutex_lock(&telegram_mutex);
    int len = snprintf(temp, sizeof(temp),
                       "TOKEN=%s\nCHAT_ID=%s\nMSG=%s\n", bot_token, chat_id, message);
    mutex_unlock(&telegram_mutex);
    if (*offset >= len)
        return 0;
    if (copy_to_user(buffer, temp + *offset, len - *offset))
        return -EFAULT;
    *offset += len - *offset;
    return len;
}

static int device_open(struct inode *inode, struct file *file) { return 0; }
static int device_release(struct inode *inode, struct file *file) { return 0; }

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_release,
    .read = device_read,
    .write = device_write,
};

static int __init telegram_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0)
        return major;
    mutex_init(&telegram_mutex);
    return 0;
}

static void __exit telegram_exit(void) {
    unregister_chrdev(major, DEVICE_NAME);
    mutex_destroy(&telegram_mutex);
}

module_init(telegram_init);
module_exit(telegram_exit);
