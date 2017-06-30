#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <xenctrl.h>

void show_help(void)
{
    fprintf(stderr,
            "xen-gnttab-query: query grant table info\n"
            "Usage: xen-gnttab-query [domid (default 0)]\n");
}

int main(int argc, char *argv[])
{
    xc_interface *xch;
    int domid, rc, c;
    struct gnttab_query_size query;

    while ( (c = getopt(argc, argv, "h")) != -1 )
    {
        switch ( c )
        {
        case 'h':
            show_help();
            return 0;
        }
    }

    domid = (argc > 1) ? strtol(argv[1], NULL, 10) : 0;

    xch = xc_interface_open(0, 0, 0);
    if ( !xch )
        errx(1, "failed to open control interface");

    query.dom = domid;
    rc = xc_gnttab_query_size(xch, &query);

    if ( rc == 0 && (query.status == GNTST_okay) )
        printf("domid=%d: nr_frames=%d, max_nr_frames=%d\n",
               query.dom, query.nr_frames, query.max_nr_frames);

    xc_interface_close(xch);

    return 0;
}
