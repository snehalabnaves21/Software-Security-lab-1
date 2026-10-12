#include <stdlib.h>
#include <string.h>

/* macOS: clang -shared -fPIC -o libpassgen.dylib passgenerate.c */
int gen_password(char *buf, int len)
{
    char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";

    for (int i = 0; i < len; i++)
        buf[i] = chars[arc4random_uniform(strlen(chars))];  
    buf[len] = '\0';
    return 0;
}