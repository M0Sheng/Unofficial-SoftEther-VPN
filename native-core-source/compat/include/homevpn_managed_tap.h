/* Android managed-TAP input policy. Apache-2.0.
 * This header is shared verbatim with the freestanding host boundary test. */
#ifndef HOMEVPN_MANAGED_TAP_H
#define HOMEVPN_MANAGED_TAP_H

/* Linux IFNAMSIZ is 16 including NUL. No templates, whitespace, signs, paths,
 * shell syntax, Unicode digits, or fallback names are accepted. */
static int homevpn_managed_tap_name_valid(const char *name)
{
    unsigned int i;
    if (name == 0) return 0;
    if (!((name[0] == 'e' && name[1] == 't' && name[2] == 'h') ||
          (name[0] == 'u' && name[1] == 's' && name[2] == 'b'))) return 0;
    for (i = 3; i <= 15; i++)
    {
        unsigned char c = (unsigned char)name[i];
        if (c == 0) return i > 3;
        if (i == 15 || c < '0' || c > '9') return 0;
    }
    return 0;
}

/* UUID.toString() emits exactly 36 lower-case ASCII characters. The nonce is
 * private per-run ownership evidence; it is never server-provided metadata. */
static int homevpn_managed_tap_token_valid(const char *token)
{
    unsigned int i;
    if (token == 0) return 0;
    for (i = 0; i < 36; i++)
    {
        unsigned char c = (unsigned char)token[i];
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (c != '-') return 0;
        }
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return token[36] == 0;
}

#endif
