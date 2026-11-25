/* Exact official UnixNewSingleInstance(NULL) basename policy. Apache-2.0. */
#ifndef HOMEVPN_LEGACY_INSTANCE_H
#define HOMEVPN_LEGACY_INSTANCE_H
static int homevpn_legacy_instance_name_valid(const char *name)
{
    unsigned int i;
    if (name == 0 || name[0] != '.' || name[1] != 'V' || name[2] != 'P' ||
            name[3] != 'N' || name[4] != '-') return 0;
    for (i = 5; i < 15; i++)
    {
        unsigned char c = (unsigned char)name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
    }
    return name[15] == 0;
}
#endif
