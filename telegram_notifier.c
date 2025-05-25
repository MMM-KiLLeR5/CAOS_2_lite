#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kmod.h>

#define DEVICE_NAME "telegram_notifier"
#define BUF_LEN 512

static int major;
static char bot_token[BUF_LEN] = "";
static char chat_id[BUF_LEN] = "";
static char message[BUF_LEN] = "";

static void send_to_telegram(void) {
    char *argv[5];
    char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };

    char *url = kmalloc(BUF_LEN * 2, GFP_KERNEL);
    if (!url)
        return;

    snprintf(url, BUF_LEN * 2,
             "https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s",
             bot_token, chat_id, message);

    printk(KERN_INFO "telegram_notifier: FULL URL: %s\n", url);

    argv[0] = "/usr/bin/curl";
    argv[1] = "-s";
    argv[2] = "-k";
    argv[3] = url;
    argv[4] = NULL;

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

    kfree(url);
}

static void parse_input(const char *input) {
    if (strncmp(input, "TOKEN=", 6) == 0) {
        strncpy(bot_token, input + 6, BUF_LEN - 1);
    } else if (strncmp(input, "CHAT_ID=", 8) == 0) {
        strncpy(chat_id, input + 8, BUF_LEN - 1);
    } else if (strncmp(input, "MSG=", 4) == 0) {
        strncpy(message, input + 4, BUF_LEN - 1);
        if (strlen(bot_token) > 0 && strlen(chat_id) > 0)
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
    int len = snprintf(temp, sizeof(temp),
                       "TOKEN=%s\nCHAT_ID=%s\nMSG=%s\n", bot_token, chat_id, message);
    if (*offset >= len)
        return 0;
    if (copy_to_user(buffer, temp + *offset, len - *offset))
        return -EFAULT;
    *offset += len - *offset;
    return len;
}

static struct file_operations fops = {
    .read = device_read,
    .write = device_write,
};

static int __init telegram_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0)
        return major;
    return 0;
}

static void __exit telegram_exit(void) {
    unregister_chrdev(major, DEVICE_NAME);
}

module_init(telegram_init);
module_exit(telegram_exit);

