/*

 */

#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>

#define FAILED      -1
#define NO_DEADLOCK  0
#define DEADLOCK     1

int
main ( int argc, char ** argv )
{
    struct flock fl = {0};
    int fd, result, flock_lock_succeeded = 0;

    fd = open( "config/test-file-to-lock", O_RDWR );
    if( fd < 0 ) {
        perror( "Couldn't open test-file-to-lock" );
	return FAILED;
    }

    /* lock with fcntl */

    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;

    if( fcntl(fd, F_SETLK, &fl) == -1 ) {
        perror( "Couldn't lock with fcntl in the first place" );
        return FAILED;
    }
    
    /* try to lock with flock (non-blocking)...  */

    result = flock( fd, LOCK_EX | LOCK_NB );

    switch( result ) {

    case 0:
        flock_lock_succeeded = 1;
        if ( flock( fd, LOCK_UN ) == -1 ) {
            perror( "flock succeeded, but couldn't unlock again with flock" );
            return FAILED;
        }
        break;
    case EWOULDBLOCK:
        flock_lock_succeeded = 0;
        break;
    default:
        if( errno == EAGAIN ) {
            flock_lock_succeeded = 0;
            break;
        } else {
            perror( "flock failed" );
            return FAILED;
        }

    }
    
    /* unlock with fcntl */

    fl.l_type   = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
 
    if( fcntl(fd, F_SETLK, &fl) == -1 ) {
        perror( "Couldn't unlock with fcntl afterwards" );
        return FAILED;
    }

    if( flock_lock_succeeded ) {
        return NO_DEADLOCK;
    } else {
        return DEADLOCK;
    }

}
