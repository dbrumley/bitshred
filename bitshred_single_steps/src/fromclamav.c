#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "bs_types.h"
#include "fromclamav.h"

const char *cli_memstr(const char *haystack, unsigned int hs, const char *needle, unsigned int ns)
{
	unsigned int i, s1, s2;

    if(!hs || !ns || hs < ns)
	return NULL;

    if(needle == haystack)
	return haystack;

    if(ns == 1)
	return memchr(haystack, needle[0], hs);

    if(needle[0] == needle[1]) {
	s1 = 2;
	s2 = 1;
    } else {
	s1 = 1;
	s2 = 2;
    }
    for(i = 0; i <= hs - ns; ) {
	if(needle[1] != haystack[i + 1]) {
	    i += s1;
	} else {
	    if((needle[0] == haystack[i]) && !memcmp(needle + 2, haystack + i + 2, ns - 2))
		return &haystack[i];
	    i += s2;
	}
    }

    return NULL;
}

void cli_debugmsg(char *str)
{
  printf("%s\n", str);
}

void cli_errormsg(char *str)
{
  fprintf(stderr,"%s\n", str);
}

int cli_writen(int fd, const void *buff, unsigned int count)
{
        int retval;
        unsigned int todo;
        const unsigned char *current;


        todo = count;
        current = (const unsigned char *) buff;

        do {
                retval = write(fd, current, todo);
                if (retval < 0) {
			if (errno == EINTR) {
				continue;
			}
			cli_errmsg("cli_writen: write error");
                        return -1;
                }
                todo -= retval;
                current += retval;
        } while (todo > 0);


        return count;
}


