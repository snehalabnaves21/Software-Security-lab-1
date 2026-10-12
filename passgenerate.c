#include <string.h>
#include <Security/SecRandom.h>

int gen_password(char *buf, int len)
{
    char chars[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789!@#$%^&*";

    unsigned char bytes[12];

    if (buf == NULL || len != 12)
        return -1;

    if (SecRandomCopyBytes(kSecRandomDefault, 12, bytes)
        != errSecSuccess)
        return -1;

    int n = strlen(chars);

    for (int i = 0; i < 12; i++)
        buf[i] = chars[bytes[i] % n];

    buf[12] = '\0';
    return 0;
}